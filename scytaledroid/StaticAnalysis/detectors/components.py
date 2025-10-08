"""IPC component exposure detector implementation."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Iterable, List, Mapping, Optional, Sequence
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
    permission: Optional[str]
    authorities: tuple[str, ...] = ()
    grant_uri_permissions: bool = False


def _iter_components(manifest_root: ElementTree.Element) -> Iterable[ComponentRecord]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    records: List[ComponentRecord] = []

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
        authorities: List[str] = []
        if tag == "provider":
            auth_value = element.get(f"{_ANDROID_NS}authorities") or ""
            for token in auth_value.split(","):
                token = token.strip()
                if token:
                    authorities.append(token)

        grant_uri = (
            element.get(f"{_ANDROID_NS}grantUriPermissions") or ""
        ).strip().lower() in {"true", "1"}

        records.append(
            ComponentRecord(
                component_type=tag,
                name=name,
                exported=exported,
                permission=permission,
                authorities=tuple(authorities),
                grant_uri_permissions=grant_uri,
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
    }
    return EvidencePointer(
        location=location,
        description=description,
        extra=extra,
    )


def _classify_component(component: ComponentRecord) -> Optional[Finding]:
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
        if permission.endswith(".permission.READ") or permission.endswith(
            ".permission.WRITE"
        ):
            # Normalised custom permission reference.
            return Finding(
                finding_id=f"ipc_provider_permission_{base_id}",
                title=f"Exported provider gated by {permission}",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.INFO,
                because=(
                    f"Provider {component.name} is exported and guarded by {permission}."
                    " Review protectionLevel for the custom permission."
                ),
                remediate=(
                    "Ensure custom permissions guarding providers are marked"
                    " protectionLevel=signature or signatureOrSystem."
                ),
            )
        return None

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

    return Finding(
        finding_id=f"ipc_{component.component_type}_permission_{base_id}",
        title=f"Exported {component_label} gated by {permission}",
        severity_gate=SeverityLevel.P2,
        category_masvs=MasvsCategory.PLATFORM,
        status=Badge.INFO,
        because=(
            f"Exported {component_label} relies on permission {permission}. Confirm its"
            " protection level is appropriate."
        ),
        remediate=(
            "Verify the guarding permission uses signature or signatureOrSystem"
            " protection level and document the expected caller set."
        ),
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
        components = _iter_components(context.manifest_root)
        findings: List[Finding] = []
        evidence: List[EvidencePointer] = []

        for component in components:
            finding = _classify_component(component)
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

        metrics = _build_metrics(components, manifest_shared_uid)

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
    components: Sequence[ComponentRecord], shared_user_id: Optional[str]
) -> Mapping[str, object]:
    total = len(components)
    exported = sum(1 for comp in components if comp.exported)
    permissioned = sum(1 for comp in components if comp.permission)
    providers = [comp for comp in components if comp.component_type == "provider"]

    return {
        "components_total": total,
        "components_exported": exported,
        "permission_enforced": permissioned,
        "providers": len(providers),
        "shared_user_id": shared_user_id,
    }


__all__ = ["IpcExposureDetector"]
