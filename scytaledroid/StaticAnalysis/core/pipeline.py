"""Core helpers for running static analysis on APK artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple, Type
from xml.etree import ElementTree

from androguard.core.apk import APK

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes, normalise_local_path
from .context import AnalysisConfig, DetectorContext
from .findings import Badge, DetectorResult, Finding
from ..detectors.base import BaseDetector
from ..detectors.components import IpcExposureDetector
from ..detectors.correlation import CorrelationDetector
from ..detectors.crypto import CryptoHygieneDetector
from ..detectors.domain_verification import DomainVerificationDetector
from ..detectors.dynamic import DynamicLoadingDetector
from ..detectors.fileio import FileIoSinksDetector
from ..detectors.integrity import IntegrityIdentityDetector
from ..detectors.interaction import UserInteractionRisksDetector
from ..detectors.manifest import ManifestBaselineDetector
from ..detectors.native import NativeHardeningDetector
from ..detectors.network import NetworkSurfaceDetector
from ..detectors.obfuscation import ObfuscationDetector
from ..detectors.permissions import PermissionsProfileDetector
from ..detectors.provider_acl import ProviderAclDetector
from ..detectors.sdks import SdkInventoryDetector
from ..detectors.secrets import SecretsDetector
from ..detectors.storage import StorageBackupDetector
from ..detectors.webview import WebViewDetector
from ..modules import StringIndex, build_string_index


class StaticAnalysisError(Exception):
    """Raised when an APK cannot be processed."""


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass(frozen=True)
class PipelineStage:
    """Represents a detector invocation in the ordered pipeline."""

    detector_cls: Type[BaseDetector]
    section_key: str
    include_in_quick: bool = True

    def instantiate(self) -> BaseDetector:
        return self.detector_cls()


PIPELINE_STAGES: Tuple[PipelineStage, ...] = (
    PipelineStage(IntegrityIdentityDetector, "integrity"),
    PipelineStage(ManifestBaselineDetector, "manifest_hygiene"),
    PipelineStage(PermissionsProfileDetector, "permissions"),
    PipelineStage(IpcExposureDetector, "ipc_components"),
    PipelineStage(ProviderAclDetector, "provider_acl"),
    PipelineStage(NetworkSurfaceDetector, "network_surface"),
    PipelineStage(DomainVerificationDetector, "domain_verification"),
    PipelineStage(SecretsDetector, "secrets"),
    PipelineStage(StorageBackupDetector, "storage_backup"),
    PipelineStage(WebViewDetector, "webview", include_in_quick=False),
    PipelineStage(CryptoHygieneDetector, "crypto_hygiene", include_in_quick=False),
    PipelineStage(DynamicLoadingDetector, "dynamic_loading", include_in_quick=False),
    PipelineStage(FileIoSinksDetector, "file_io_sinks", include_in_quick=False),
    PipelineStage(UserInteractionRisksDetector, "interaction_risks", include_in_quick=False),
    PipelineStage(SdkInventoryDetector, "sdk_inventory", include_in_quick=False),
    PipelineStage(NativeHardeningDetector, "native_jni", include_in_quick=False),
    PipelineStage(ObfuscationDetector, "obfuscation", include_in_quick=False),
    PipelineStage(CorrelationDetector, "correlation_findings"),
)


@dataclass(frozen=True)
class ManifestSummary:
    """Key manifest attributes extracted from the APK."""

    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    compile_sdk: Optional[str] = None
    app_label: Optional[str] = None
    main_activity: Optional[str] = None

    def to_dict(self) -> MutableMapping[str, Optional[str]]:
        return asdict(self)


@dataclass(frozen=True)
class ComponentSummary:
    """Lists of Android components declared by the application."""

    activities: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    receivers: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()

    def to_dict(self) -> MutableMapping[str, Iterable[str]]:
        return asdict(self)

    def total(self) -> int:
        return sum(len(collection) for collection in self.to_dict().values())


@dataclass(frozen=True)
class PermissionSummary:
    """Permissions declared by the APK."""

    declared: tuple[str, ...] = ()
    dangerous: tuple[str, ...] = ()
    custom: tuple[str, ...] = ()

    def to_dict(self) -> MutableMapping[str, Iterable[str]]:
        return asdict(self)


@dataclass(frozen=True)
class ManifestFlags:
    """Notable manifest booleans converted to python primitives."""

    uses_cleartext_traffic: Optional[bool] = None
    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None
    request_legacy_external_storage: Optional[bool] = None
    full_backup_content: Optional[str] = None
    network_security_config: Optional[str] = None

    def to_dict(self) -> MutableMapping[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class StaticAnalysisReport:
    """Static analysis artefact captured for an APK."""

    file_path: str
    relative_path: Optional[str]
    file_name: str
    file_size: int
    hashes: Mapping[str, str]
    manifest: ManifestSummary = field(default_factory=ManifestSummary)
    manifest_flags: ManifestFlags = field(default_factory=ManifestFlags)
    permissions: PermissionSummary = field(default_factory=PermissionSummary)
    components: ComponentSummary = field(default_factory=ComponentSummary)
    exported_components: ComponentSummary = field(default_factory=ComponentSummary)
    features: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict)
    scan_profile: Optional[str] = None
    analysis_version: str = "2.0.0-alpha"
    findings: tuple[Finding, ...] = ()
    detector_metrics: Mapping[str, object] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, object]:
        """Serialise the report to primitives for JSON storage."""

        payload = {
            "file_path": self.file_path,
            "relative_path": self.relative_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "hashes": dict(self.hashes),
            "manifest": self.manifest.to_dict(),
            "manifest_flags": self.manifest_flags.to_dict(),
            "permissions": self.permissions.to_dict(),
            "components": self.components.to_dict(),
            "exported_components": self.exported_components.to_dict(),
            "features": list(self.features),
            "libraries": list(self.libraries),
            "signatures": list(self.signatures),
            "metadata": dict(self.metadata),
            "scan_profile": self.scan_profile,
            "analysis_version": self.analysis_version,
            "findings": [finding.to_dict() for finding in self.findings],
            "detector_metrics": dict(self.detector_metrics),
            "generated_at": self.generated_at,
        }
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "StaticAnalysisReport":
        """Reconstruct a report from its dictionary representation."""

        manifest = ManifestSummary(**_subset(payload.get("manifest", {}), ManifestSummary))
        flags = ManifestFlags(**_subset(payload.get("manifest_flags", {}), ManifestFlags))
        permissions = PermissionSummary(
            **{
                "declared": tuple(payload.get("permissions", {}).get("declared", ())),
                "dangerous": tuple(payload.get("permissions", {}).get("dangerous", ())),
                "custom": tuple(payload.get("permissions", {}).get("custom", ())),
            }
        )
        components = ComponentSummary(
            **{
                "activities": tuple(payload.get("components", {}).get("activities", ())),
                "services": tuple(payload.get("components", {}).get("services", ())),
                "receivers": tuple(payload.get("components", {}).get("receivers", ())),
                "providers": tuple(payload.get("components", {}).get("providers", ())),
            }
        )
        exported = ComponentSummary(
            **{
                "activities": tuple(
                    payload.get("exported_components", {}).get("activities", ())
                ),
                "services": tuple(
                    payload.get("exported_components", {}).get("services", ())
                ),
                "receivers": tuple(
                    payload.get("exported_components", {}).get("receivers", ())
                ),
                "providers": tuple(
                    payload.get("exported_components", {}).get("providers", ())
                ),
            }
        )

        metadata_raw = payload.get("metadata")
        metadata = metadata_raw if isinstance(metadata_raw, Mapping) else {}

        findings_payload = payload.get("findings")
        findings: tuple[Finding, ...]
        if isinstance(findings_payload, Sequence) and not isinstance(
            findings_payload, (str, bytes)
        ):
            findings = tuple(
                Finding.from_dict(entry)
                for entry in findings_payload
                if isinstance(entry, Mapping)
            )
        else:
            findings = tuple()

        detector_metrics_payload = payload.get("detector_metrics")
        detector_metrics = (
            {str(k): v for k, v in dict(detector_metrics_payload).items()}
            if isinstance(detector_metrics_payload, Mapping)
            else {}
        )

        return cls(
            file_path=str(payload.get("file_path") or ""),
            relative_path=payload.get("relative_path") or None,
            file_name=str(payload.get("file_name") or Path(payload.get("file_path") or "").name),
            file_size=int(payload.get("file_size") or 0),
            hashes={str(k): str(v) for k, v in dict(payload.get("hashes", {})).items()},
            manifest=manifest,
            manifest_flags=flags,
            permissions=permissions,
            components=components,
            exported_components=exported,
            features=tuple(payload.get("features", ())),
            libraries=tuple(payload.get("libraries", ())),
            signatures=tuple(payload.get("signatures", ())),
            metadata=metadata,
            scan_profile=_coerce_optional_str(payload.get("scan_profile")),
            analysis_version=str(payload.get("analysis_version") or "2.0.0-alpha"),
            findings=findings,
            detector_metrics=detector_metrics,
            generated_at=str(payload.get("generated_at") or datetime.now(timezone.utc).isoformat()),
        )


def _subset(source: object, model: type) -> dict[str, object]:
    """Return mapping of dataclass field names in *model* from *source*."""

    if not isinstance(source, Mapping):
        return {}
    fields = {field.name for field in model.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    return {name: source.get(name) for name in fields}


def _coerce_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _coerce_optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return str(value)


def _collect_dangerous_permissions(
    permission_details: Mapping[str, Sequence[object]]
) -> tuple[str, ...]:
    """Return the subset of permissions marked as dangerous by Androguard."""

    dangerous: set[str] = set()
    for name, detail in permission_details.items():
        if not detail:
            continue
        protection_level = detail[0]
        if not isinstance(protection_level, str):
            continue
        if "dangerous" in protection_level.lower():
            dangerous.add(name)
    return tuple(sorted(dangerous))


def _load_manifest_root(apk: APK) -> ElementTree.Element:
    """Return the parsed AndroidManifest root element."""

    try:
        manifest_xml = apk.get_android_manifest_xml()
    except Exception as exc:  # pragma: no cover - defensive, androguard handles parsing
        raise StaticAnalysisError(f"Unable to parse AndroidManifest.xml: {exc}") from exc

    if hasattr(manifest_xml, "tag"):
        # Androguard may return an lxml element when that dependency is available.
        try:
            manifest_xml = ElementTree.tostring(manifest_xml, encoding="utf-8")
        except Exception:
            manifest_xml = ElementTree.tostring(manifest_xml)

    if isinstance(manifest_xml, str):
        manifest_bytes = manifest_xml.encode("utf-8")
    else:
        manifest_bytes = manifest_xml

    try:
        return ElementTree.fromstring(manifest_bytes)
    except ElementTree.ParseError as exc:
        raise StaticAnalysisError(f"Malformed AndroidManifest.xml: {exc}") from exc


def _build_manifest_flags(root: ElementTree.Element) -> ManifestFlags:
    """Extract notable booleans from the manifest tree."""

    application = root.find("application")
    if application is None:
        return ManifestFlags()

    return ManifestFlags(
        uses_cleartext_traffic=_coerce_bool(application.get(f"{_ANDROID_NS}usesCleartextTraffic")),
        debuggable=_coerce_bool(application.get(f"{_ANDROID_NS}debuggable")),
        allow_backup=_coerce_bool(application.get(f"{_ANDROID_NS}allowBackup")),
        request_legacy_external_storage=_coerce_bool(
            application.get(f"{_ANDROID_NS}requestLegacyExternalStorage")
        ),
        full_backup_content=_coerce_optional_str(
            application.get(f"{_ANDROID_NS}fullBackupContent")
        ),
        network_security_config=_coerce_optional_str(
            application.get(f"{_ANDROID_NS}networkSecurityConfig")
        ),
    )


def _extract_compile_sdk(root: ElementTree.Element) -> Optional[str]:
    """Best-effort extraction of compile SDK metadata from the manifest."""

    value = root.get(f"{_ANDROID_NS}compileSdkVersion") or root.get("platformBuildVersionCode")
    if value:
        return str(value)
    return None


def _resolve_relative_path(apk_path: Path, storage_root: Optional[Path]) -> Optional[str]:
    if storage_root is None:
        root = Path(app_config.DATA_DIR).resolve()
        apk_resolved = apk_path.resolve()
        if apk_resolved.is_relative_to(root):
            storage_root = root
        else:
            storage_root = None

    if storage_root is None:
        try:
            return normalise_local_path(apk_path)
        except Exception:
            return None

    try:
        return apk_path.resolve().relative_to(storage_root.resolve()).as_posix()
    except ValueError:
        try:
            return normalise_local_path(apk_path)
        except Exception:
            return None


def run_detector_pipeline(context: DetectorContext) -> Tuple[DetectorResult, ...]:
    """Execute registered detectors in the fixed pipeline order."""

    results: list[DetectorResult] = []
    profile = (context.config.profile or "full").lower()

    for stage in PIPELINE_STAGES:
        detector = stage.instantiate()

        if profile == "quick" and not stage.include_in_quick:
            reason = "skipped by quick profile"
            results.append(_build_skipped_result(detector, stage.section_key, reason))
            continue

        if not detector.applies_to_profile(context.config.profile):
            reason = f"disabled for profile {context.config.profile}"
            results.append(_build_skipped_result(detector, stage.section_key, reason))
            continue

        started = perf_counter()
        try:
            result = detector.run(context)
            duration = round(perf_counter() - started, 4)
        except Exception as exc:  # pragma: no cover - defensive guard
            duration = round(perf_counter() - started, 4)
            results.append(
                _build_error_result(
                    detector,
                    stage.section_key,
                    duration,
                    f"detector failed: {exc}",
                )
            )
            continue

        if not isinstance(result, DetectorResult):
            duration = round(perf_counter() - started, 4)
            results.append(
                _build_error_result(
                    detector,
                    stage.section_key,
                    duration,
                    "detector returned invalid result",
                )
            )
            continue

        updates: dict[str, object] = {}
        if result.detector_id != detector.detector_id:
            updates["detector_id"] = detector.detector_id
        if result.section_key != stage.section_key:
            updates["section_key"] = stage.section_key
        if result.duration_sec <= 0 and duration > 0:
            updates["duration_sec"] = duration
        if updates:
            result = replace(result, **updates)

        results.append(result)

    return tuple(results)


def _build_skipped_result(
    detector: BaseDetector,
    section_key: str,
    reason: str,
) -> DetectorResult:
    return DetectorResult(
        detector_id=detector.detector_id,
        section_key=section_key,
        status=Badge.SKIPPED,
        duration_sec=0.0,
        metrics={"skip_reason": reason},
        evidence=tuple(),
        notes=(reason,),
    )


def _build_error_result(
    detector: BaseDetector,
    section_key: str,
    duration: float,
    message: str,
) -> DetectorResult:
    return DetectorResult(
        detector_id=detector.detector_id,
        section_key=section_key,
        status=Badge.SKIPPED,
        duration_sec=max(duration, 0.0),
        metrics={"error": message},
        evidence=tuple(),
        notes=(message,),
    )


def analyze_apk(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
    config: Optional[AnalysisConfig] = None,
) -> StaticAnalysisReport:
    """Run lightweight static analysis on *apk_path* and return a report."""

    if not apk_path.exists():
        raise StaticAnalysisError(f"APK not found: {apk_path}")

    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    manifest_root = _load_manifest_root(apk)
    flags = _build_manifest_flags(manifest_root)
    compile_sdk = _extract_compile_sdk(manifest_root)

    hashes = compute_hashes(apk_path)
    manifest = ManifestSummary(
        package_name=apk.get_package(),
        version_name=apk.get_androidversion_name(),
        version_code=apk.get_androidversion_code(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        compile_sdk=compile_sdk,
        app_label=apk.get_app_name(),
        main_activity=apk.get_main_activity(),
    )

    declared_permissions = tuple(sorted(apk.get_permissions()))
    permission_details = apk.get_details_permissions()
    dangerous = _collect_dangerous_permissions(permission_details)
    custom_permissions = tuple(sorted(apk.get_declared_permissions()))

    permissions = PermissionSummary(
        declared=declared_permissions,
        dangerous=dangerous,
        custom=custom_permissions,
    )

    components = ComponentSummary(
        activities=tuple(sorted(apk.get_activities())),
        services=tuple(sorted(apk.get_services())),
        receivers=tuple(sorted(apk.get_receivers())),
        providers=tuple(sorted(apk.get_providers())),
    )
    exported = _collect_exported_components(manifest_root)

    features = tuple(sorted(apk.get_features()))
    libraries = tuple(sorted(apk.get_libraries()))
    signatures = tuple(sorted(apk.get_signature_names()))

    report_metadata: Mapping[str, object] = metadata or {}

    relative = _resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size

    analysis_config = config or AnalysisConfig()
    string_index = (
        build_string_index(apk) if analysis_config.enable_string_index else None
    )

    context = _build_detector_context(
        apk_path=apk_path,
        apk=apk,
        manifest_root=manifest_root,
        manifest=manifest,
        manifest_flags=flags,
        permissions=permissions,
        components=components,
        exported=exported,
        features=features,
        libraries=libraries,
        signatures=signatures,
        metadata=report_metadata,
        hashes=hashes,
        config=analysis_config,
        string_index=string_index,
    )

    detector_results = run_detector_pipeline(context)
    findings = tuple(
        finding for result in detector_results for finding in result.findings
    )
    detector_metrics = {
        result.detector_id: dict(result.metrics)
        for result in detector_results
        if result.metrics
    }

    return StaticAnalysisReport(
        file_path=str(apk_path.resolve()),
        relative_path=relative,
        file_name=apk_path.name,
        file_size=file_size,
        hashes=hashes,
        manifest=manifest,
        manifest_flags=flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=features,
        libraries=libraries,
        signatures=signatures,
        metadata=report_metadata,
        scan_profile=analysis_config.profile,
        analysis_version=analysis_config.analysis_version,
        findings=findings,
        detector_metrics=detector_metrics,
    )


def _build_detector_context(
    *,
    apk_path: Path,
    apk: APK,
    manifest_root: ElementTree.Element,
    manifest: ManifestSummary,
    manifest_flags: ManifestFlags,
    permissions: PermissionSummary,
    components: ComponentSummary,
    exported: ComponentSummary,
    features: Sequence[str],
    libraries: Sequence[str],
    signatures: Sequence[str],
    metadata: Mapping[str, object],
    hashes: Mapping[str, str],
    config: AnalysisConfig,
    string_index: Optional[StringIndex],
) -> DetectorContext:
    return DetectorContext(
        apk_path=apk_path,
        apk=apk,
        manifest_root=manifest_root,
        manifest_summary=manifest,
        manifest_flags=manifest_flags,
        permissions=permissions,
        components=components,
        exported_components=exported,
        features=tuple(features),
        libraries=tuple(libraries),
        signatures=tuple(signatures),
        metadata=metadata,
        hashes=hashes,
        string_index=string_index,
        config=config,
    )


def _collect_exported_components(
    manifest_root: ElementTree.Element,
) -> ComponentSummary:
    """Derive exported component lists by inspecting manifest nodes."""

    def exported_names(
        tags: tuple[str, ...], *, default_exported: bool = False
    ) -> tuple[str, ...]:
        names: set[str] = set()
        for tag in tags:
            for element in manifest_root.iter(tag):
                name = element.get(f"{_ANDROID_NS}name")
                if not name:
                    continue
                exported_attr = element.get(f"{_ANDROID_NS}exported")
                if exported_attr is not None:
                    is_exported = exported_attr.strip().lower() == "true"
                else:
                    is_exported = (
                        default_exported
                        if tag == "provider"
                        else _element_has_intent_filter(element)
                    )
                if is_exported:
                    names.add(name)
        return tuple(sorted(names))

    return ComponentSummary(
        activities=exported_names(("activity", "activity-alias")),
        services=exported_names(("service",)),
        receivers=exported_names(("receiver",)),
        providers=exported_names(("provider",), default_exported=False),
    )


def _element_has_intent_filter(element: ElementTree.Element) -> bool:
    """Return True if the manifest element declares an intent-filter child."""

    for child in element:
        tag = child.tag
        if "}" in tag:
            tag = tag.rsplit("}", 1)[-1]
        if tag == "intent-filter":
            return True
    return False


__all__ = [
    "StaticAnalysisError",
    "StaticAnalysisReport",
    "ManifestSummary",
    "ManifestFlags",
    "PermissionSummary",
    "ComponentSummary",
    "PipelineStage",
    "PIPELINE_STAGES",
    "run_detector_pipeline",
    "analyze_apk",
]
