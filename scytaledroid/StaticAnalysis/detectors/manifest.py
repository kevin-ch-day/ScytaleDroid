"""Manifest-oriented detectors."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
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
from ..modules.network_security.models import NetworkSecurityPolicy
from ..modules.permissions import classify_permission, load_permission_catalog
from .base import BaseDetector, register_detector
from .components import ComponentRecord, iter_manifest_components

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
_STRONG_PERMISSION_LEVELS = {
    "signature",
    "signatureorsystem",
    "signatureorinstaller",
    "installer",
    "privileged",
    "vendorprivileged",
}
_WEAK_PERMISSION_LEVELS = {"dangerous", "normal", "appop", "development"}


def _manifest_pointer(apk_path: Path, description: str, **extra: object) -> EvidencePointer:
    return EvidencePointer(
        location=f"{apk_path.resolve().as_posix()}!AndroidManifest.xml",
        description=description,
        extra={key: value for key, value in extra.items() if value is not None},
    )


def _collect_task_affinities(manifest_root: ElementTree.Element) -> Sequence[str]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    affinities: set[str] = set()
    for element in application:
        affinity = element.get(f"{_ANDROID_NS}taskAffinity")
        if affinity is None:
            continue
        affinity = affinity.strip()
        affinities.add(affinity if affinity else "<empty>")
    return tuple(sorted(affinities))


def _collect_process_map(manifest_root: ElementTree.Element) -> Mapping[str, int]:
    processes = Counter()
    for component in iter_manifest_components(manifest_root):
        process_name = (component.process or "").strip()
        if not process_name:
            continue
        processes[process_name] += 1
    return dict(processes)


def _classify_custom_permissions(
    custom_definitions: Mapping[str, Mapping[str, object]]
) -> Mapping[str, Sequence[str]]:
    buckets: dict[str, list[str]] = {"strong": [], "weak": [], "unknown": []}
    for name, definition in custom_definitions.items():
        levels = tuple(
            str(value).lower()
            for value in definition.get("protection_levels", ())
            if value
        )
        if any(level in _STRONG_PERMISSION_LEVELS for level in levels):
            buckets["strong"].append(name)
        elif any(level in _WEAK_PERMISSION_LEVELS for level in levels) or not levels:
            buckets["weak"].append(name)
        else:
            buckets["unknown"].append(name)
    return {key: tuple(sorted(values)) for key, values in buckets.items() if values}


def _component_inventory(
    manifest_root: ElementTree.Element,
) -> Sequence[ComponentRecord]:
    return tuple(iter_manifest_components(manifest_root))


def _collect_component_affinities(
    manifest_root: ElementTree.Element,
) -> Mapping[str, str]:
    application = manifest_root.find("application")
    if application is None:
        return {}

    affinities: dict[str, str] = {}
    for element in application:
        tag = element.tag.rsplit("}", 1)[-1] if "}" in element.tag else element.tag
        if tag not in _COMPONENT_TAGS:
            continue
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue
        affinity = element.get(f"{_ANDROID_NS}taskAffinity")
        if affinity is None:
            continue
        affinities[name] = affinity.strip() or "<empty>"
    return affinities


def _summarise_component_guards(
    components: Sequence[ComponentRecord],
    *,
    protection_levels: Mapping[str, Sequence[str]],
    catalog,
) -> Mapping[str, object]:
    guard_histogram: Counter[str] = Counter()
    by_type: dict[str, Counter[str]] = {}
    weak_exports: list[str] = []
    dangerous_exports: list[str] = []
    signature_exports: list[str] = []
    unknown_exports: list[str] = []

    for component in components:
        if not component.exported:
            continue
        strength, _ = classify_permission(
            component.permission or None,
            manifest_levels=protection_levels,
            catalog=catalog,
        )
        guard_histogram[strength] += 1
        type_counter = by_type.setdefault(component.component_type, Counter())
        type_counter[strength] += 1
        if strength in {"none", "weak"}:
            weak_exports.append(component.name)
        elif strength == "dangerous":
            dangerous_exports.append(component.name)
        elif strength == "signature":
            signature_exports.append(component.name)
        else:
            unknown_exports.append(component.name)

    return {
        "histogram": dict(guard_histogram),
        "by_type": {key: dict(counter) for key, counter in by_type.items()},
        "weak_exports": tuple(sorted(weak_exports)),
        "dangerous_exports": tuple(sorted(dangerous_exports)),
        "signature_exports": tuple(sorted(signature_exports)),
        "unknown_exports": tuple(sorted(unknown_exports)),
    }


def _network_policy_allows_cleartext(policy: NetworkSecurityPolicy | None) -> bool:
    if policy is None:
        return True
    if policy.base_cleartext is False:
        for domain in policy.domain_policies:
            if domain.cleartext_permitted is True:
                return True
        return False
    if policy.base_cleartext is True:
        return True
    return True


@register_detector
class ManifestBaselineDetector(BaseDetector):
    """Surface manifest hygiene issues and context for correlation."""

    detector_id = "manifest_baseline"
    name = "Manifest baseline detector"
    default_profiles = ("quick", "full")
    section_key = "manifest_hygiene"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        findings: list[Finding] = []
        manifest_flags = context.manifest_flags
        manifest_summary = context.manifest_summary
        apk_path = context.apk_path

        components = _component_inventory(context.manifest_root)
        protection_levels = getattr(context.permissions, "protection_levels", {})
        catalog = getattr(context, "permission_catalog", None) or load_permission_catalog()
        guard_summary = _summarise_component_guards(
            components,
            protection_levels=protection_levels,
            catalog=catalog,
        )
        network_policy = getattr(context, "network_security_policy", None)
        component_counts = Counter(record.component_type for record in components)
        exported_counts = Counter(
            record.component_type for record in components if record.exported
        )
        process_map = _collect_process_map(context.manifest_root)
        custom_process_components = {
            record.name: record.process.strip()
            for record in components
            if record.process and record.process.strip()
        }
        task_affinities = _collect_task_affinities(context.manifest_root)
        component_affinities = _collect_component_affinities(context.manifest_root)
        custom_permissions = dict(context.permissions.custom_definitions)
        custom_permission_buckets = _classify_custom_permissions(custom_permissions)

        if manifest_flags.debuggable:
            findings.append(
                Finding(
                    finding_id="manifest_debuggable_enabled",
                    title="android:debuggable enabled",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.FAIL,
                    because=(
                        "Application manifest sets android:debuggable to true,"
                        " enabling runtime code inspection."
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "application@debuggable",
                            debuggable=manifest_flags.debuggable,
                        ),
                    ),
                    remediate="Strip the debuggable flag from release builds via build types or manifest placeholders.",
                )
            )

        cleartext_risk = bool(manifest_flags.uses_cleartext_traffic)
        if cleartext_risk and not _network_policy_allows_cleartext(network_policy):
            cleartext_risk = False

        if cleartext_risk:
            findings.append(
                Finding(
                    finding_id="manifest_cleartext_enabled",
                    title="Cleartext traffic permitted",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.NETWORK,
                    status=Badge.WARN,
                    because=(
                        "android:usesCleartextTraffic is true. Cleartext endpoints should"
                        " be limited to debug hosts and audited."
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "application@usesCleartextTraffic",
                            uses_cleartext_traffic=manifest_flags.uses_cleartext_traffic,
                        ),
                    ),
                    remediate="Disable cleartext traffic or scope it to a debug-only network security config.",
                )
            )

        weak_exports = tuple(guard_summary.get("weak_exports", ()))
        if weak_exports:
            findings.append(
                Finding(
                    finding_id="manifest_exported_weak_guards",
                    title="Exported components use weak guards",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.WARN,
                    because=(
                        "Exported components rely on normal/dangerous permissions or"
                        " no guard at all: "
                        + ", ".join(weak_exports[:6])
                        + (" …" if len(weak_exports) > 6 else "")
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "component@permission",
                            weak_exports=weak_exports,
                        ),
                    ),
                    remediate=(
                        "Protect exported components with signature-level permissions"
                        " or mark them non-exported."
                    ),
                )
            )

        if weak_exports and manifest_flags.allow_backup is not False:
            findings.append(
                Finding(
                    finding_id="manifest_backup_and_exports",
                    title="Backup plus exported weak components",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.STORAGE,
                    status=Badge.WARN,
                    because=(
                        "android:allowBackup is enabled while exported components"
                        " lack strong permission guards ("
                        + ", ".join(weak_exports[:4])
                        + (" …" if len(weak_exports) > 4 else "")
                        + "). Backup data may contain IPC-accessible secrets."
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "application@allowBackup",
                            allow_backup=manifest_flags.allow_backup,
                            weak_exports=weak_exports,
                        ),
                    ),
                    remediate=(
                        "Disable auto-backup or harden exported components with"
                        " signature-level permissions."
                    ),
                )
            )

        allow_backup = manifest_flags.allow_backup
        full_backup = (manifest_flags.full_backup_content or "").strip()
        if allow_backup is not False:
            findings.append(
                Finding(
                    finding_id="manifest_backup_enabled",
                    title="Auto-backup enabled",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.STORAGE,
                    status=Badge.WARN,
                    because=(
                        "Application data can be exported via Android's backup channel"
                        " (android:allowBackup not set to false)."
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "application@allowBackup",
                            allow_backup=allow_backup,
                            full_backup_content=full_backup or None,
                        ),
                    ),
                    remediate="Set android:allowBackup="
                    "false or provide an explicit backup configuration that excludes sensitive data.",
                )
            )

        if manifest_flags.request_legacy_external_storage:
            findings.append(
                Finding(
                    finding_id="manifest_legacy_external_storage",
                    title="Legacy external storage requested",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.STORAGE,
                    status=Badge.WARN,
                    because=(
                        "android:requestLegacyExternalStorage is true. This bypasses"
                        " scoped storage protections and should be phased out."
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "application@requestLegacyExternalStorage",
                            request_legacy_external_storage=True,
                        ),
                    ),
                    remediate="Adopt scoped storage APIs and drop requestLegacyExternalStorage for production builds.",
                )
            )

        weak_custom_permissions = custom_permission_buckets.get("weak", tuple())
        if weak_custom_permissions:
            findings.append(
                Finding(
                    finding_id="manifest_custom_permissions_weak",
                    title="Custom permissions lack signature protection",
                    severity_gate=SeverityLevel.P1,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.WARN,
                    because=(
                        "The following custom permissions are declared without signature"
                        "-level protection: "
                        + ", ".join(weak_custom_permissions[:6])
                        + (" …" if len(weak_custom_permissions) > 6 else "")
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "permission@protectionLevel",
                            weak_permissions=weak_custom_permissions,
                        ),
                    ),
                    remediate="Set protectionLevel=signature (or signatureOrSystem) for custom permissions guarding exported components.",
                )
            )

        unknown_custom_permissions = custom_permission_buckets.get("unknown", tuple())
        if unknown_custom_permissions:
            findings.append(
                Finding(
                    finding_id="manifest_custom_permissions_review",
                    title="Review custom permission protection levels",
                    severity_gate=SeverityLevel.P2,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.INFO,
                    because=(
                        "Custom permissions use uncommon protection levels: "
                        + ", ".join(unknown_custom_permissions)
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "permission@protectionLevel",
                            review_permissions=unknown_custom_permissions,
                        ),
                    ),
                    remediate="Verify the custom protection levels only grant access to trusted callers.",
                )
            )

        default_affinity = manifest_summary.package_name or ""
        affinity_map = {
            name: value
            for name, value in component_affinities.items()
            if value not in {default_affinity, ""}
        }
        if affinity_map:
            findings.append(
                Finding(
                    finding_id="manifest_task_affinity_custom",
                    title="Custom task affinities present",
                    severity_gate=SeverityLevel.P2,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.INFO,
                    because=(
                        "Components override the default task affinity: "
                        + ", ".join(f"{name}→{affinity}" for name, affinity in list(affinity_map.items())[:6])
                        + (" …" if len(affinity_map) > 6 else "")
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "component@taskAffinity",
                            task_affinities=affinity_map,
                        ),
                    ),
                    remediate="Ensure custom task affinities are required and do not leak activities into other apps.",
                )
            )

        if custom_process_components:
            findings.append(
                Finding(
                    finding_id="manifest_custom_process",
                    title="Components run in custom processes",
                    severity_gate=SeverityLevel.P2,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.INFO,
                    because=(
                        "Manifest assigns custom android:process values. Review isolation"
                        " expectations for: "
                        + ", ".join(
                            f"{name}→{proc}" for name, proc in list(custom_process_components.items())[:6]
                        )
                        + (" …" if len(custom_process_components) > 6 else "")
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "component@process",
                            processes=custom_process_components,
                        ),
                    ),
                    remediate="Document why components require custom processes and ensure permissions isolate IPC boundaries.",
                )
            )

        target_sdk_value: int | None
        try:
            target_sdk_value = int(manifest_summary.target_sdk) if manifest_summary.target_sdk else None
        except (TypeError, ValueError):
            target_sdk_value = None

        if target_sdk_value and target_sdk_value < 31:
            findings.append(
                Finding(
                    finding_id="manifest_target_sdk_stale",
                    title="Target SDK below Android 12",
                    severity_gate=SeverityLevel.P2,
                    category_masvs=MasvsCategory.PLATFORM,
                    status=Badge.INFO,
                    because=(
                        f"targetSdkVersion={manifest_summary.target_sdk}. Upgrading unlocks newer platform protections."
                    ),
                    evidence=(
                        _manifest_pointer(
                            apk_path,
                            "uses-sdk@targetSdkVersion",
                            target_sdk=manifest_summary.target_sdk,
                        ),
                    ),
                    remediate="Adopt the latest targetSdkVersion to inherit modern security restrictions.",
                )
            )

        metrics = {
            "flags": manifest_flags.to_dict(),
            "task_affinities": task_affinities,
            "component_affinities": component_affinities,
            "component_counts": dict(component_counts),
            "exported_counts": dict(exported_counts),
            "custom_process_map": custom_process_components,
            "custom_permission_buckets": custom_permission_buckets,
            "custom_permissions": custom_permissions,
            "process_counts": process_map,
            "target_sdk": manifest_summary.target_sdk,
            "min_sdk": manifest_summary.min_sdk,
            "component_guard_summary": guard_summary,
        }
        if network_policy is not None:
            metrics["network_security"] = {
                "base_cleartext": network_policy.base_cleartext,
                "debug_cleartext": network_policy.debug_overrides_cleartext,
                "trust_user_certificates": network_policy.trust_user_certificates,
                "base_trust_anchors": list(network_policy.base_trust_anchors),
                "domain_entries": len(network_policy.domain_policies),
                "domain_cleartext": sum(
                    1
                    for domain in network_policy.domain_policies
                    if domain.cleartext_permitted is not False
                ),
                "domain_user_cert": sum(
                    1 for domain in network_policy.domain_policies if domain.user_certificates_allowed
                ),
                "domain_pinned": sum(
                    1 for domain in network_policy.domain_policies if domain.pinned_certificates
                ),
            }

        status = Badge.OK
        if any(finding.status is Badge.FAIL for finding in findings):
            status = Badge.FAIL
        elif any(finding.status is Badge.WARN for finding in findings):
            status = Badge.WARN
        elif findings:
            status = Badge.INFO

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=status,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
        )


__all__ = ["ManifestBaselineDetector"]