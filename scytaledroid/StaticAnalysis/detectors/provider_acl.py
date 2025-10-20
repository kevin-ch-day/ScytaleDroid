"""Content provider ACL analysis."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from time import perf_counter
from typing import List, Mapping, Optional, Sequence
from xml.etree import ElementTree

from ..core.context import DetectorContext
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from ..core.pipeline import make_detector_result
from .base import BaseDetector, register_detector
from ..modules.permissions import classify_permission, load_permission_catalog

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass(frozen=True)
class ProviderRecord:
    """Parsed representation of a manifest <provider> entry."""

    name: str
    exported: bool
    read_permission: Optional[str]
    write_permission: Optional[str]
    general_permission: Optional[str]
    grant_uri_permissions: bool
    authorities: tuple[str, ...]
    path_permissions: tuple[Mapping[str, str], ...]


_GUARD_PRIORITY = {
    "none": 0,
    "unknown": 1,
    "weak": 1,
    "dangerous": 2,
    "custom": 2,
    "signature": 3,
}


def _resolve_strength(
    permission: Optional[str],
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> tuple[str, tuple[str, ...]]:
    if not permission:
        return "none", tuple()
    strength, levels = classify_permission(
        permission,
        manifest_levels=protection_levels,
        catalog=catalog,
    )
    if strength == "none":
        return "none", tuple(levels)
    return strength, tuple(levels)


def _select_worst_guard(*guards: Optional[str]) -> str:
    selected = "none"
    selected_rank = 99
    for guard in guards:
        candidate = guard or "none"
        rank = _GUARD_PRIORITY.get(candidate, 1)
        if rank < selected_rank:
            selected = candidate
            selected_rank = rank
    return selected


def _collect_providers(manifest_root: ElementTree.Element) -> Sequence[ProviderRecord]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    records: List[ProviderRecord] = []

    for element in application.findall("provider"):
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue

        exported_attr = element.get(f"{_ANDROID_NS}exported")
        if exported_attr is not None:
            exported = exported_attr.strip().lower() == "true"
        else:
            exported = False

        read_perm = (element.get(f"{_ANDROID_NS}readPermission") or "").strip() or None
        write_perm = (element.get(f"{_ANDROID_NS}writePermission") or "").strip() or None
        permission = (element.get(f"{_ANDROID_NS}permission") or "").strip() or None
        grant_uri = (
            element.get(f"{_ANDROID_NS}grantUriPermissions") or ""
        ).strip().lower() in {"true", "1"}

        authorities = []
        authority_value = (element.get(f"{_ANDROID_NS}authorities") or "").strip()
        for part in authority_value.split(","):
            token = part.strip()
            if token:
                authorities.append(token)

        path_permissions: List[Mapping[str, str]] = []
        for path_node in element.findall("path-permission"):
            entry: dict[str, str] = {}
            for attr in ("path", "pathPrefix", "pathPattern"):
                value = path_node.get(f"{_ANDROID_NS}{attr}")
                if value:
                    entry[attr] = value
            if entry:
                entry["readPermission"] = (
                    path_node.get(f"{_ANDROID_NS}readPermission") or read_perm or permission or ""
                )
                entry["writePermission"] = (
                    path_node.get(f"{_ANDROID_NS}writePermission")
                    or write_perm
                    or permission
                    or ""
                )
                path_permissions.append(entry)

        records.append(
            ProviderRecord(
                name=name,
                exported=exported,
                read_permission=read_perm or permission,
                write_permission=write_perm or permission,
                general_permission=permission,
                grant_uri_permissions=grant_uri,
                authorities=tuple(authorities),
                path_permissions=tuple(path_permissions),
            )
        )

    return tuple(records)


def _build_provider_evidence(provider: ProviderRecord, *, apk_path) -> EvidencePointer:
    location = f"{apk_path.resolve().as_posix()}!AndroidManifest.xml::provider:{provider.name}"
    description = f"provider {provider.name}"
    extra = {
        "authorities": provider.authorities,
        "read_permission": provider.read_permission,
        "write_permission": provider.write_permission,
        "grant_uri_permissions": provider.grant_uri_permissions,
    }
    return EvidencePointer(location=location, description=description, extra=extra)


def _classify_provider(
    provider: ProviderRecord,
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> Optional[Finding]:
    if not provider.exported:
        return None

    if not provider.read_permission and not provider.write_permission:
        risk = "No read/write permissions"
        because = (
            "Exported provider lacks read/write permissions; content is globally"
            " accessible to other apps."
        )
        return Finding(
            finding_id=f"provider_world_{provider.name}",
            title=f"Exported provider without ACL — {provider.name}",
            severity_gate=SeverityLevel.P0,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.FAIL,
            because=because,
            remediate=(
                "Set readPermission/writePermission or mark the provider private."
            ),
            metrics={"risk": risk},
        )

    if provider.grant_uri_permissions and not provider.general_permission:
        return Finding(
            finding_id=f"provider_uri_perms_{provider.name}",
            title=f"grantUriPermissions without base permission — {provider.name}",
            severity_gate=SeverityLevel.P1,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.WARN,
            because=(
                "Provider grants URI permissions dynamically without a base"
                " permission; malicious apps can retain handles beyond intent scope."
            ),
            remediate=(
                "Define signature-level base permissions before enabling grantUriPermissions"
                " or disable URI grants."
            ),
        )

    if provider.path_permissions:
        weak_paths = [
            entry
            for entry in provider.path_permissions
            if not entry.get("readPermission") and not entry.get("writePermission")
        ]
        if weak_paths:
            return Finding(
                finding_id=f"provider_path_acl_{provider.name}",
                title=f"Path permissions missing guards — {provider.name}",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.WARN,
                because=(
                    "One or more path-permission entries omit read/write permissions,"
                    " weakening provider ACLs."
                ),
                remediate=(
                    "Supply readPermission/writePermission on every path-permission or"
                    " remove the wildcard entry."
                ),
            )

    return None


def _build_provider_snapshot(
    provider: ProviderRecord,
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> Mapping[str, object]:
    base_guard, base_levels = _resolve_strength(
        provider.general_permission,
        protection_levels=protection_levels,
        catalog=catalog,
    )
    read_guard, read_levels = _resolve_strength(
        provider.read_permission,
        protection_levels=protection_levels,
        catalog=catalog,
    )
    write_guard, write_levels = _resolve_strength(
        provider.write_permission,
        protection_levels=protection_levels,
        catalog=catalog,
    )
    effective = _select_worst_guard(base_guard, read_guard, write_guard)

    path_details: list[Mapping[str, object]] = []
    for entry in provider.path_permissions:
        read_perm = entry.get("readPermission") or None
        write_perm = entry.get("writePermission") or None
        read_strength, read_tokens = _resolve_strength(
            read_perm,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        write_strength, write_tokens = _resolve_strength(
            write_perm,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        path_details.append(
            {
                "path": entry.get("path"),
                "pathPrefix": entry.get("pathPrefix"),
                "pathPattern": entry.get("pathPattern"),
                "read_permission": read_perm,
                "write_permission": write_perm,
                "read_guard": read_strength,
                "write_guard": write_strength,
                "read_levels": read_tokens,
                "write_levels": write_tokens,
            }
        )

    return {
        "name": provider.name,
        "exported": provider.exported,
        "authorities": provider.authorities,
        "grant_uri_permissions": provider.grant_uri_permissions,
        "base_permission": provider.general_permission,
        "base_guard": base_guard,
        "base_levels": base_levels,
        "read_permission": provider.read_permission,
        "read_guard": read_guard,
        "read_levels": read_levels,
        "write_permission": provider.write_permission,
        "write_guard": write_guard,
        "write_levels": write_levels,
        "effective_guard": effective,
        "path_permissions": tuple(path_details),
    }


def _build_metrics(
    providers: Sequence[ProviderRecord],
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> Mapping[str, object]:
    exported = [provider for provider in providers if provider.exported]
    insecure = [
        provider
        for provider in exported
        if not provider.read_permission and not provider.write_permission
    ]

    guard_histogram: Counter[str] = Counter()
    acl_snapshot = []
    for provider in providers:
        snapshot = _build_provider_snapshot(
            provider,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        guard_histogram[snapshot["effective_guard"]] += 1
        acl_snapshot.append(snapshot)

    return {
        "total_providers": len(providers),
        "exported": len(exported),
        "without_permissions": len(insecure),
        "grant_uri_permissions": sum(
            1 for provider in exported if provider.grant_uri_permissions
        ),
        "guard_strength_histogram": dict(guard_histogram),
        "acl_snapshot": tuple(acl_snapshot),
    }


@register_detector
class ProviderAclDetector(BaseDetector):
    """Analyses exported content providers for ACL regressions."""

    detector_id = "provider_acl"
    name = "Provider ACL detector"
    default_profiles = ("quick", "full")
    section_key = "provider_acl"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        providers = _collect_providers(context.manifest_root)
        findings: List[Finding] = []
        evidence: List[EvidencePointer] = []
        catalog = getattr(context, "permission_catalog", None) or load_permission_catalog()
        protection_levels = getattr(context.permissions, "protection_levels", {})

        for provider in providers:
            finding = _classify_provider(
                provider,
                protection_levels=protection_levels,
                catalog=catalog,
            )
            if finding is None:
                continue
            findings.append(finding)
            evidence.append(_build_provider_evidence(provider, apk_path=context.apk_path))

        metrics = _build_metrics(
            providers,
            protection_levels=protection_levels,
            catalog=catalog,
        )

        badge = Badge.OK
        if any(f.status is Badge.FAIL for f in findings):
            badge = Badge.FAIL
        elif any(f.status is Badge.WARN for f in findings):
            badge = Badge.WARN

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
            evidence=tuple(evidence[:5]),
        )


__all__ = ["ProviderAclDetector"]
