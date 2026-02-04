"""IPC component exposure detector implementation."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from time import perf_counter
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
from ..core.results_builder import make_detector_result
from ..modules.permissions import classify_permission, load_permission_catalog
from .base import BaseDetector, register_detector

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = {
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
}


@dataclass(frozen=True)
class ComponentRecord:
    """Parsed manifest component metadata."""

    component_type: str
    name: str
    exported: bool
    permission: str | None
    authorities: tuple[str, ...] = ()
    grant_uri_permissions: bool = False
    process: str | None = None


def iter_manifest_components(
    manifest_root: ElementTree.Element,
) -> Iterable[ComponentRecord]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    records: list[ComponentRecord] = []

    for element in application:
        tag = element.tag.rsplit("}", 1)[-1] if "}" in element.tag else element.tag
        if tag not in _COMPONENT_TAGS:
            continue
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue

        exported_attr = element.get(f"{_ANDROID_NS}exported")
        if exported_attr is not None:
            exported = exported_attr.strip().lower() == "true"
        elif tag == "provider":
            exported = False
        else:
            exported = any(
                child.tag.rsplit("}", 1)[-1] == "intent-filter"
                if "}" in child.tag
                else child.tag == "intent-filter"
                for child in element
            )

        permission = element.get(f"{_ANDROID_NS}permission")
        authorities: list[str] = []
        if tag == "provider":
            auth_value = element.get(f"{_ANDROID_NS}authorities") or ""
            for token in auth_value.split(","):
                token = token.strip()
                if token:
                    authorities.append(token)

        grant_uri = (
            element.get(f"{_ANDROID_NS}grantUriPermissions") or ""
        ).strip().lower() in {"true", "1"}

        process_name = element.get(f"{_ANDROID_NS}process")

        records.append(
            ComponentRecord(
                component_type=tag,
                name=name,
                exported=exported,
                permission=permission,
                authorities=tuple(authorities),
                grant_uri_permissions=grant_uri,
                process=process_name,
            )
        )

    return tuple(records)


def _build_evidence(component: ComponentRecord, *, apk_path) -> EvidencePointer:
    location = f"{apk_path.resolve().as_posix()}!AndroidManifest.xml::{component.component_type}:{component.name}"
    description = f"{component.component_type} {component.name}"
    extra = {
        "exported": component.exported,
        "permission": component.permission,
        "authorities": component.authorities,
        "grant_uri_permissions": component.grant_uri_permissions,
        "process": component.process,
    }
    return EvidencePointer(
        location=location,
        description=description,
        extra=extra,
    )


def _permission_strength(
    permission: str,
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> tuple[str, tuple[str, ...]]:
    strength, levels = classify_permission(
        permission,
        manifest_levels=protection_levels,
        catalog=catalog,
    )
    if strength == "none":
        return "none", levels
    return strength, tuple(levels)


def _classify_component(
    component: ComponentRecord,
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> Finding | None:
    if not component.exported:
        return None

    base_id = component.name.replace("/", ".")
    permission = (component.permission or "").strip()
    component_label = component.component_type.replace("-", " ")

    if component.component_type == "provider":
        if not permission:
            return Finding(
                finding_id=f"ipc_provider_world_{base_id}",
                title=f"Exported provider without permission — {component.name}",
                severity_gate=SeverityLevel.P0,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.FAIL,
                because=(
                    "Content provider is exported without read/write permissions, allowing"
                    " external processes to query data."
                ),
                remediate=(
                    "Declare readPermission and writePermission or mark the provider"
                    " as private (exported=false)."
                ),
            )

        strength, levels = _permission_strength(
            permission,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        level_display = "/".join(levels) if levels else "unspecified"
        if strength == "strong":
            return Finding(
                finding_id=f"ipc_provider_permission_{base_id}",
                title=f"Exported provider gated by {permission}",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.INFO,
                because=(
                    f"Provider {component.name} is exported and guarded by {permission}"
                    f" (protectionLevel={level_display})."
                ),
                remediate=(
                    "Keep custom provider permissions scoped to signature-level callers"
                    " and document expected consumers."
                ),
                metrics={"protection_level": level_display},
            )
        if strength == "weak":
            return Finding(
                finding_id=f"ipc_provider_permission_weak_{base_id}",
                title=f"Weak guard on exported provider — {component.name}",
                severity_gate=SeverityLevel.P0,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.FAIL,
                because=(
                    f"Provider {component.name} is exported but guarded by {permission}"
                    f" with protectionLevel={level_display}, allowing broad callers."
                ),
                remediate=(
                    "Switch the provider permission to signature or signatureOrSystem"
                    " or make the component private."
                ),
                metrics={"protection_level": level_display},
            )
        return Finding(
            finding_id=f"ipc_provider_permission_custom_{base_id}",
            title=f"Exported provider guarded by {permission}",
            severity_gate=SeverityLevel.P2,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.WARN,
            because=(
                f"Provider {component.name} relies on {permission}"
                f" (protectionLevel={level_display}). Review that only trusted callers"
                " can obtain the permission."
            ),
            remediate=(
                "Confirm the custom permission is distributed only to trusted"
                " packages and consider signature-level enforcement."
            ),
            metrics={"protection_level": level_display},
        )

    if not permission:
        return Finding(
            finding_id=f"ipc_{component.component_type}_open_{base_id}",
            title=f"Exported {component_label} without permission",
            severity_gate=SeverityLevel.P1,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.WARN,
            because=(
                f"{component_label.title()} {component.name} is exported but does not"
                " declare android:permission."
            ),
            remediate=(
                "Restrict the component with signature-level permissions or mark it"
                " non-exported unless explicitly required."
            ),
        )

    strength, levels = _permission_strength(
        permission,
        protection_levels=protection_levels,
        catalog=catalog,
    )
    level_display = "/".join(levels) if levels else "unspecified"

    if strength == "strong":
        return Finding(
            finding_id=f"ipc_{component.component_type}_permission_{base_id}",
            title=f"Exported {component_label} gated by {permission}",
            severity_gate=SeverityLevel.P2,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.INFO,
            because=(
                f"Exported {component_label} relies on {permission}"
                f" (protectionLevel={level_display})."
            ),
            remediate=(
                "Document the permission contract and monitor for unexpected"
                " callers."
            ),
            metrics={"protection_level": level_display},
        )

    if strength == "weak":
        return Finding(
            finding_id=f"ipc_{component.component_type}_weak_permission_{base_id}",
            title=f"Weak permission guard on exported {component_label}",
            severity_gate=SeverityLevel.P1,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.WARN,
            because=(
                f"{component_label.title()} {component.name} uses {permission}"
                f" (protectionLevel={level_display}), which is insufficient for"
                " exported components."
            ),
            remediate=(
                "Protect the component with a signature-level permission or mark"
                " it non-exported."
            ),
            metrics={"protection_level": level_display},
        )

    return Finding(
        finding_id=f"ipc_{component.component_type}_permission_{base_id}",
        title=f"Exported {component_label} guarded by {permission}",
        severity_gate=SeverityLevel.P2,
        category_masvs=MasvsCategory.PLATFORM,
        status=Badge.INFO,
        because=(
            f"Exported {component_label} relies on {permission}"
            f" (protectionLevel={level_display}). Verify distribution controls."
        ),
        remediate=(
            "Confirm only trusted callers can obtain the guarding permission"
            " and prefer signature-level protection."
        ),
        metrics={"protection_level": level_display},
    )


def _shared_uid_finding(shared_user_id: str, *, permissions: Sequence[str]) -> Finding:
    because = (
        "Application declares android:sharedUserId, allowing other packages signed with"
        " the same cert to share UID and permissions."
    )
    if permissions:
        because += " Combined permission surface: " + ", ".join(permissions[:10])
        if len(permissions) > 10:
            because += " …"

    return Finding(
        finding_id="ipc_shared_user_id",
        title=f"sharedUserId in use ({shared_user_id})",
        severity_gate=SeverityLevel.P1,
        category_masvs=MasvsCategory.PLATFORM,
        status=Badge.WARN,
        because=because,
        remediate=(
            "Avoid sharedUserId unless absolutely necessary. Prefer explicit IPC"
            " contracts and signature permissions."
        ),
    )


@register_detector
class IpcExposureDetector(BaseDetector):
    """Summarises exported IPC components and shared UID posture."""

    detector_id = "ipc_components"
    name = "IPC exposure detector"
    default_profiles = ("quick", "full")
    section_key = "ipc_components"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        components = iter_manifest_components(context.manifest_root)
        findings: list[Finding] = []
        evidence: list[EvidencePointer] = []
        protection_levels = getattr(context.permissions, "protection_levels", {})
        catalog = getattr(context, "permission_catalog", None) or load_permission_catalog()

        for component in components:
            finding = _classify_component(
                component,
                protection_levels=protection_levels,
                catalog=catalog,
            )
            if finding is None:
                continue
            findings.append(finding)
            evidence.append(_build_evidence(component, apk_path=context.apk_path))

        manifest_shared_uid = context.manifest_root.get(f"{_ANDROID_NS}sharedUserId")
        if manifest_shared_uid:
            permissions = [
                perm
                for perm in context.permissions.declared
                if perm not in context.permissions.custom
            ]
            findings.append(
                _shared_uid_finding(manifest_shared_uid, permissions=permissions)
            )

        metrics = _build_metrics(
            components,
            manifest_shared_uid,
            protection_levels=protection_levels,
            catalog=catalog,
        )

        badge = Badge.OK
        if any(f.status in {Badge.FAIL, Badge.WARN} for f in findings):
            badge = Badge.FAIL if any(f.status is Badge.FAIL for f in findings) else Badge.WARN

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
            evidence=tuple(evidence[:5]),
        )


def _build_metrics(
    components: Sequence[ComponentRecord],
    shared_user_id: str | None,
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> Mapping[str, object]:
    total = len(components)
    exported = sum(1 for comp in components if comp.exported)
    permissioned = sum(1 for comp in components if comp.permission)
    exported_with_permission = sum(
        1 for comp in components if comp.exported and comp.permission
    )
    exported_without_permission = sum(
        1 for comp in components if comp.exported and not comp.permission
    )
    providers = [comp for comp in components if comp.component_type == "provider"]
    guard_strengths: Counter[str] = Counter()
    for component in components:
        if not component.permission:
            continue
        strength, _ = _permission_strength(
            component.permission,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        guard_strengths[strength] += 1

    type_map: dict[str, Counter[str]] = {}
    for component in components:
        if not component.permission:
            continue
        bucket, _ = _permission_strength(
            component.permission,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        counter = type_map.setdefault(component.component_type, Counter())
        counter[bucket] += 1
    by_type = {
        component_type: dict(counter)
        for component_type, counter in type_map.items()
    }

    return {
        "components_total": total,
        "components_exported": exported,
        "permission_enforced": permissioned,
        "exported_with_permission": exported_with_permission,
        "exported_without_permission": exported_without_permission,
        "providers": len(providers),
        "shared_user_id": shared_user_id,
        "permission_guard_strength": dict(guard_strengths),
        "permission_guard_strength_by_type": by_type,
    }


__all__ = ["IpcExposureDetector", "ComponentRecord", "iter_manifest_components"]