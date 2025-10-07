"""Core helpers for running static analysis on APK artifacts."""

from __future__ import annotations
"""High-level orchestration entry point for static analysis runs."""

from hashlib import sha256
from pathlib import Path
from typing import Mapping, Optional, Sequence
from xml.etree import ElementTree

from androguard.core.apk import APK

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes, normalise_local_path
from scytaledroid.Utils.LoggingUtils.logging_engine import configure_third_party_loggers

from .context import AnalysisConfig, DetectorContext
from .detector_runner import PIPELINE_STAGES, PipelineStage, run_detector_pipeline
from .errors import StaticAnalysisError
from .manifest_utils import (
    build_manifest_flags,
    collect_exported_components,
    extract_compile_sdk,
    load_manifest_root,
)
from .models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)
from ..modules import StringIndex, build_string_index


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

    analysis_config = config or AnalysisConfig()
    report_metadata: dict[str, object] = dict(metadata or {})

    hashes = compute_hashes(apk_path)
    apk_sha256 = hashes.get("sha256", "")
    run_id = _derive_run_id(apk_sha256, analysis_config)

    log_path = configure_third_party_loggers(
        verbosity=analysis_config.verbosity,
        run_id=run_id,
        debug_dir=str(Path(app_config.LOGS_DIR).resolve()),
    )
    if log_path is not None:
        report_metadata["androguard_log_path"] = str(log_path)

    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    manifest_root = load_manifest_root(apk)
    flags = build_manifest_flags(manifest_root)
    compile_sdk = extract_compile_sdk(manifest_root)
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
    try:
        permission_details = apk.get_details_permissions()
    except KeyError:
        permission_details = {}
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
    exported = collect_exported_components(manifest_root)

    features = tuple(sorted(apk.get_features()))
    libraries = tuple(sorted(apk.get_libraries()))
    signatures = tuple(sorted(apk.get_signature_names()))

    relative = _resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size
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


def _derive_run_id(apk_sha256: str, config: AnalysisConfig) -> str:
    """Return a deterministic identifier for debug log artefacts."""

    detector_list = ",".join(sorted(config.enabled_detectors or ()))
    seed = "|".join(
        (
            apk_sha256 or "unknown",
            config.profile,
            config.verbosity,
            config.persistence_mode,
            config.analysis_version,
            detector_list,
        )
    )
    return sha256(seed.encode("utf-8")).hexdigest()[:16]


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


__all__ = [
    "PipelineStage",
    "PIPELINE_STAGES",
    "StaticAnalysisReport",
    "ManifestSummary",
    "ManifestFlags",
    "PermissionSummary",
    "ComponentSummary",
    "StaticAnalysisError",
    "analyze_apk",
]
