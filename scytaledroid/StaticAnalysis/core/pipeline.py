"""Core helpers for running static analysis on APK artifacts."""

from __future__ import annotations

from time import perf_counter
from pathlib import Path
from typing import Mapping, Optional, Sequence

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes
from scytaledroid.Utils.LoggingUtils.logging_engine import configure_third_party_loggers

from .._androguard import APK
from .context import AnalysisConfig, DetectorContext
from .context_builders import (
    build_detector_context,
    collect_dangerous_permissions,
    derive_run_id,
    resolve_relative_path,
)
from .errors import StaticAnalysisError
from .findings import Badge, DetectorResult, EvidencePointer, Finding
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
from .pipeline_artifacts import assemble_pipeline_artifacts
from ..modules import build_string_index
from ..modules.network_security import extract_network_security_policy


def make_detector_result(
    *,
    detector_id: str,
    section_key: str,
    status: Badge,
    started_at: float,
    findings: Sequence[Finding] | None = None,
    metrics: Mapping[str, object] | None = None,
    evidence: Sequence[EvidencePointer] | None = None,
    notes: Sequence[str] | None = None,
    subitems: Sequence[Mapping[str, object]] | None = None,
    raw_debug: Optional[str] = None,
) -> DetectorResult:
    """Build a deterministic :class:`DetectorResult` instance."""

    duration = max(0.0, round(perf_counter() - started_at, 1))
    metrics_payload = dict(metrics or {})
    evidence_payload = tuple(evidence or ())
    notes_payload = tuple(note for note in notes or () if note)
    findings_payload = tuple(findings or ())
    if subitems:
        subitems_payload = tuple(dict(item) for item in subitems)
    else:
        subitems_payload = None

    return DetectorResult(
        detector_id=detector_id,
        section_key=section_key,
        status=status,
        duration_sec=duration,
        metrics=metrics_payload,
        evidence=evidence_payload,
        notes=notes_payload,
        findings=findings_payload,
        subitems=subitems_payload,
        raw_debug=raw_debug,
    )


from .detector_runner import PIPELINE_STAGES, PipelineStage, run_detector_pipeline


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
    run_id = derive_run_id(apk_sha256, analysis_config)
    report_metadata.setdefault("run_id", run_id)

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

    report_metadata.setdefault("toolchain", _resolve_toolchain_versions())

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
    dangerous = collect_dangerous_permissions(permission_details)
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

    relative = resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size
    network_security_policy = extract_network_security_policy(
        apk,
        manifest_reference=flags.network_security_config,
    )

    string_index = (
        build_string_index(apk) if analysis_config.enable_string_index else None
    )

    context = build_detector_context(
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
        network_security_policy=network_security_policy,
    )

    detector_results = run_detector_pipeline(context)
    context.intermediate_results = tuple(detector_results)
    artifacts = assemble_pipeline_artifacts(context)

    if artifacts.trace:
        report_metadata["pipeline_trace"] = artifacts.trace
    if artifacts.summary:
        report_metadata["pipeline_summary"] = artifacts.summary
    if artifacts.reproducibility_bundle:
        report_metadata["repro_bundle"] = artifacts.reproducibility_bundle

    findings = tuple(
        finding for result in artifacts.results for finding in result.findings
    )
    detector_metrics = dict(artifacts.metrics)

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
        detector_results=detector_results,
    )


def _resolve_toolchain_versions() -> Mapping[str, str]:
    versions = {"androguard": "—", "aapt2": "—", "apksigner": "—"}
    try:  # pragma: no cover - dependency introspection
        import androguard

        version = getattr(androguard, "__version__", None)
        if isinstance(version, str) and version.strip():
            versions["androguard"] = version
    except Exception:  # pragma: no cover - best-effort metadata
        pass
    return versions


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
    "make_detector_result",
]
