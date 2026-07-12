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
    enabled: bool = True
    enabled_explicit: bool | None = None
    application_enabled: bool = True
    read_permission: str | None = None
    write_permission: str | None = None
    exported_explicit: bool | None = None
    export_reason: str | None = None
    authorities: tuple[str, ...] = ()
    grant_uri_permissions: bool = False
    process: str | None = None


def iter_manifest_components(
    manifest_root: ElementTree.Element,
) -> Iterable[ComponentRecord]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    target_sdk = _extract_target_sdk_int(manifest_root)
    application_enabled = _manifest_bool(
        application.get(f"{_ANDROID_NS}enabled"),
        default=True,
    )

    records: list[ComponentRecord] = []

    for element in application:
        tag = element.tag.rsplit("}", 1)[-1] if "}" in element.tag else element.tag
        if tag not in _COMPONENT_TAGS:
            continue
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue

        enabled_explicit = _manifest_bool_or_none(element.get(f"{_ANDROID_NS}enabled"))
        component_enabled = (
            application_enabled
            and _manifest_bool(element.get(f"{_ANDROID_NS}enabled"), default=True)
        )
        exported_attr = element.get(f"{_ANDROID_NS}exported")
        exported_explicit: bool | None = None
        export_reason = None
        if exported_attr is not None:
            exported_explicit = exported_attr.strip().lower() == "true"
            exported = exported_explicit
            export_reason = "explicit_flag"
        else:
            has_intent_filter = any(
                child.tag.rsplit("}", 1)[-1] == "intent-filter"
                if "}" in child.tag
                else child.tag == "intent-filter"
                for child in element
            )
            if target_sdk is not None and target_sdk >= 31 and has_intent_filter:
                exported = False
                export_reason = "sdk31_requires_explicit"
            elif tag == "provider":
                exported = _provider_default_exported(target_sdk)
                export_reason = (
                    "provider_default_true_legacy_sdk"
                    if exported
                    else "provider_default_false"
                )
            else:
                exported = bool(has_intent_filter)
                export_reason = "intent_filter_present" if has_intent_filter else "default_false"

        if exported and not component_enabled:
            exported = False
            export_reason = (
                "application_disabled"
                if not application_enabled
                else "component_disabled"
            )

        permission = element.get(f"{_ANDROID_NS}permission")
        read_permission = element.get(f"{_ANDROID_NS}readPermission")
        write_permission = element.get(f"{_ANDROID_NS}writePermission")
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
                enabled=component_enabled,
                enabled_explicit=enabled_explicit,
                application_enabled=application_enabled,
                exported_explicit=exported_explicit,
                export_reason=export_reason,
                permission=permission,
                read_permission=read_permission,
                write_permission=write_permission,
                authorities=tuple(authorities),
                grant_uri_permissions=grant_uri,
                process=process_name,
            )
        )

    return tuple(records)


def _extract_target_sdk_int(manifest_root: ElementTree.Element) -> int | None:
    uses_sdk = manifest_root.find("uses-sdk")
    if uses_sdk is None:
        return None
    raw_value = uses_sdk.get(f"{_ANDROID_NS}targetSdkVersion")
    if not raw_value:
        return None
    try:
        return int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None


def _manifest_bool_or_none(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in {"true", "1"}


def _manifest_bool(value: str | None, *, default: bool) -> bool:
    parsed = _manifest_bool_or_none(value)
    return default if parsed is None else parsed


def _provider_default_exported(target_sdk: int | None) -> bool:
    # Provider exported defaults changed at targetSdkVersion 17.
    # Unknown target SDK is treated conservatively as legacy-exposed.
    return target_sdk is None or target_sdk <= 16


def _build_evidence(component: ComponentRecord, *, apk_path) -> EvidencePointer:
    location = f"{apk_path.resolve().as_posix()}!AndroidManifest.xml::{component.component_type}:{component.name}"
    description = f"{component.component_type} {component.name}"
    extra = {
        "exported": component.exported,
        "exported_explicit": component.exported_explicit,
        "export_reason": component.export_reason,
        "enabled": component.enabled,
        "enabled_explicit": component.enabled_explicit,
        "application_enabled": component.application_enabled,
        "permission": component.permission,
        "read_permission": component.read_permission,
        "write_permission": component.write_permission,
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
    if strength == "signature":
        return "strong", tuple(levels)
    if strength in {"dangerous", "weak", "unknown"}:
        return "weak", tuple(levels)
    return strength, tuple(levels)


def _component_permissions(component: ComponentRecord) -> tuple[str, ...]:
    if component.component_type == "provider":
        values = (
            component.read_permission or "",
            component.write_permission or "",
            component.permission or "",
        )
    else:
        values = (component.permission or "",)
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        permission = value.strip()
        if permission and permission not in seen:
            deduped.append(permission)
            seen.add(permission)
    return tuple(deduped)


def _provider_permission_guard(
    permissions: Sequence[str],
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> tuple[str, str]:
    strengths: list[str] = []
    display: list[str] = []
    for permission in permissions:
        strength, levels = _permission_strength(
            permission,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        level_display = "/".join(levels) if levels else "unspecified"
        strengths.append(strength)
        display.append(f"{permission} (protectionLevel={level_display})")
    if strengths and all(strength == "strong" for strength in strengths):
        return "strong", "; ".join(display)
    if any(strength == "weak" for strength in strengths):
        return "weak", "; ".join(display)
    return "custom", "; ".join(display)


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
        provider_permissions = tuple(
            perm
            for perm in (
                (component.read_permission or "").strip(),
                (component.write_permission or "").strip(),
                permission,
            )
            if perm
        )
        if not provider_permissions:
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

        provider_guard, permission_display = _provider_permission_guard(
            provider_permissions,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        if provider_guard == "strong":
            return Finding(
                finding_id=f"ipc_provider_permission_{base_id}",
                title=f"Exported provider gated by {permission_display}",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.INFO,
                because=(
                    f"Provider {component.name} is exported and guarded by"
                    f" {permission_display}."
                ),
                remediate=(
                    "Keep custom provider permissions scoped to signature-level callers"
                    " and document expected consumers."
                ),
                metrics={"protection_level": provider_guard},
            )
        if provider_guard == "weak":
            return Finding(
                finding_id=f"ipc_provider_permission_weak_{base_id}",
                title=f"Weak guard on exported provider — {component.name}",
                severity_gate=SeverityLevel.P0,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.FAIL,
                because=(
                    f"Provider {component.name} is exported but guarded by"
                    f" {permission_display}, allowing broad callers."
                ),
                remediate=(
                    "Switch the provider permission to signature or signatureOrSystem"
                    " or make the component private."
                ),
                metrics={"protection_level": provider_guard},
            )
        return Finding(
            finding_id=f"ipc_provider_permission_custom_{base_id}",
            title=f"Exported provider guarded by {permission_display}",
            severity_gate=SeverityLevel.P2,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.WARN,
            because=(
                f"Provider {component.name} relies on {permission_display}."
                " Review that only trusted callers can obtain the permission."
            ),
            remediate=(
                "Confirm the custom permission is distributed only to trusted"
                " packages and consider signature-level enforcement."
            ),
            metrics={"protection_level": provider_guard},
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
    permissioned = sum(1 for comp in components if _component_permissions(comp))
    exported_with_permission = sum(
        1 for comp in components if comp.exported and _component_permissions(comp)
    )
    exported_without_permission = sum(
        1 for comp in components if comp.exported and not _component_permissions(comp)
    )
    providers = [comp for comp in components if comp.component_type == "provider"]
    guard_strengths: Counter[str] = Counter()
    for component in components:
        permissions = _component_permissions(component)
        if not permissions:
            continue
        if component.component_type == "provider":
            strength, _ = _provider_permission_guard(
                permissions,
                protection_levels=protection_levels,
                catalog=catalog,
            )
        else:
            strength, _ = _permission_strength(
                permissions[0],
                protection_levels=protection_levels,
                catalog=catalog,
            )
        guard_strengths[strength] += 1

    type_map: dict[str, Counter[str]] = {}
    for component in components:
        permissions = _component_permissions(component)
        if not permissions:
            continue
        if component.component_type == "provider":
            bucket, _ = _provider_permission_guard(
                permissions,
                protection_levels=protection_levels,
                catalog=catalog,
            )
        else:
            bucket, _ = _permission_strength(
                permissions[0],
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
