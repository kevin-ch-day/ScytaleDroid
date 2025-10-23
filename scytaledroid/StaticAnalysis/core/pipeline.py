"""Core helpers for running static analysis on APK artifacts (hardened)."""

from __future__ import annotations

from time import perf_counter
from pathlib import Path
from typing import Mapping, Optional, Sequence

import shlex
import shutil
import subprocess

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
    collect_custom_permission_definitions,
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
from ..modules.permissions import load_permission_catalog
from ..modules.network_security import extract_network_security_policy

# -----------------------
# Small, focused helpers
# -----------------------

def _safe_get_app_label(apk: APK, pkg_name: str, meta: dict) -> str:
    """
    Try Androguard first; if ARSC parsing explodes, try `aapt2 dump badging`;
    finally fall back to package name. Record fallbacks in metadata.
    """
    try:
        label = apk.get_app_name()
        if isinstance(label, str) and label.strip():
            return label
    except Exception as e:
        meta["parse_error_resources"] = True
        meta["label_error"] = str(e)

    # aapt2 fallback (best-effort, short timeout)
    aapt2 = shutil.which("aapt2")
    if aapt2:
        try:
            out = subprocess.check_output(
                shlex.split(f"{aapt2} dump badging {apk.filename}"),
                stderr=subprocess.STDOUT,
                timeout=6,
            ).decode(errors="ignore")
            # Prefer generic label; if not present, accept first localized line
            for line in out.splitlines():
                if line.startswith("application-label:"):
                    meta["label_fallback"] = "aapt2"
                    return line.split(":", 1)[1].strip().strip("'\"")
            for line in out.splitlines():
                if line.startswith("application-label-"):
                    meta["label_fallback"] = "aapt2-localized"
                    return line.split(":", 1)[1].strip().strip("'\"")
        except Exception as e:
            meta["label_fallback_attempt_error"] = str(e)

    meta["label_fallback"] = "package_name"
    return pkg_name


def _safe_get_main_activity(apk: APK, meta: dict) -> Optional[str]:
    try:
        return apk.get_main_activity()
    except Exception as e:
        meta["main_activity_fallback"] = True
        meta["main_activity_error"] = str(e)
        return None


def _safe_tuple(callable_, meta: dict, meta_key: str) -> tuple[str, ...]:
    try:
        data = callable_()  # may return list/tuple/None
        if not data:
            return ()
        return tuple(sorted(data))
    except Exception as e:
        meta[meta_key] = str(e)
        return ()


def _safe_permission_details(apk: APK, meta: dict) -> Mapping[str, Sequence[str]]:
    try:
        return apk.get_details_permissions() or {}
    except Exception as e:
        meta["permissions_fallback"] = True
        meta["permissions_error"] = str(e)
        return {}


def _resolve_toolchain_versions() -> Mapping[str, str]:
    versions = {"androguard": "—", "aapt2": "—", "apksigner": "—"}
    try:  # pragma: no cover - dependency introspection
        import androguard  # type: ignore
        version = getattr(androguard, "__version__", None)
        if isinstance(version, str) and version.strip():
            versions["androguard"] = version
    except Exception:  # pragma: no cover
        pass
    aapt2 = shutil.which("aapt2")
    if aapt2:
        versions["aapt2"] = "present"
    return versions


# -----------------------
# Public helpers
# -----------------------

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
    subitems_payload = tuple(dict(item) for item in subitems) if subitems else None
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
    """Run resilient static analysis on *apk_path* and return a report."""

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
        # Hard-open failure (corrupt zip, etc.)
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    report_metadata.setdefault("toolchain", _resolve_toolchain_versions())

    # Manifest & flags (best-effort)
    manifest_root = load_manifest_root(apk)  # internal code handles its own exceptions
    flags = build_manifest_flags(manifest_root)
    compile_sdk = extract_compile_sdk(manifest_root)

    # Stable identifiers & resilient app metadata
    package_name = apk.get_package() or apk_path.stem
    app_label = _safe_get_app_label(apk, package_name, report_metadata)
    main_activity = _safe_get_main_activity(apk, report_metadata)

    manifest = ManifestSummary(
        package_name=package_name,
        version_name=apk.get_androidversion_name(),
        version_code=apk.get_androidversion_code(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        compile_sdk=compile_sdk,
        app_label=app_label,
        main_activity=main_activity,
    )

    # Permissions (resilient)
    declared_permissions = tuple(sorted(apk.get_permissions() or ()))
    permission_details = _safe_permission_details(apk, report_metadata)
    dangerous = collect_dangerous_permissions(permission_details)
    custom_permissions = tuple(sorted(apk.get_declared_permissions() or ()))
    custom_definitions = collect_custom_permission_definitions(manifest_root)
    permission_catalog = load_permission_catalog()

    protection_levels: dict[str, tuple[str, ...]] = {}
    for name, detail in (permission_details or {}).items():
        if not detail:
            continue
        level_raw = detail[0]
        if isinstance(level_raw, str):
            parts = tuple(
                part.strip().lower() for part in level_raw.split("|") if part.strip()
            )
            if parts:
                protection_levels[name] = parts
    for name, definition in custom_definitions.items():
        levels = tuple(
            str(part).lower()
            for part in definition.get("protection_levels", ())
            if part
        )
        if levels:
            protection_levels[name] = levels

    catalog_snapshot = permission_catalog.to_snapshot(declared_permissions)

    permissions = PermissionSummary(
        declared=declared_permissions,
        dangerous=dangerous,
        custom=custom_permissions,
        protection_levels=protection_levels,
        custom_definitions=custom_definitions,
        catalog_snapshot=catalog_snapshot,
    )

    # Components (resilient)
    activities = _safe_tuple(apk.get_activities, report_metadata, "activities_error")
    services = _safe_tuple(apk.get_services, report_metadata, "services_error")
    receivers = _safe_tuple(apk.get_receivers, report_metadata, "receivers_error")
    providers = _safe_tuple(apk.get_providers, report_metadata, "providers_error")

    components = ComponentSummary(
        activities=activities,
        services=services,
        receivers=receivers,
        providers=providers,
    )
    exported = collect_exported_components(manifest_root)

    # Other metadata (resilient)
    features = _safe_tuple(apk.get_features, report_metadata, "features_error")
    libraries = _safe_tuple(apk.get_libraries, report_metadata, "libraries_error")
    signatures = _safe_tuple(apk.get_signature_names, report_metadata, "signatures_error")

    relative = resolve_relative_path(apk_path, storage_root)
    file_size = apk_path.stat().st_size

    # Network Security Config (resilient)
    try:
        network_security_policy = extract_network_security_policy(
            apk,
            manifest_reference=flags.network_security_config,
        )
    except Exception as e:
        report_metadata["network_security_policy_error"] = str(e)
        network_security_policy = None

    # String index (optional & resilient)
    string_index = None
    if analysis_config.enable_string_index:
        try:
            string_index = build_string_index(apk)
        except Exception as e:
            report_metadata["string_index_error"] = str(e)

    # Build detector context
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
        permission_catalog=permission_catalog,
    )

    # Run detectors (pipeline itself should be robust, but keep trace)
    detector_results = run_detector_pipeline(context)
    context.intermediate_results = tuple(detector_results)
    artifacts = assemble_pipeline_artifacts(context)

    # Enrich metadata with pipeline artifacts (best-effort)
    if artifacts.trace:
        report_metadata["pipeline_trace"] = artifacts.trace
    if artifacts.summary:
        report_metadata["pipeline_summary"] = artifacts.summary
    if artifacts.reproducibility_bundle:
        report_metadata["repro_bundle"] = artifacts.reproducibility_bundle
    if artifacts.matrices:
        report_metadata["analysis_matrices"] = artifacts.matrices
    if artifacts.indicators:
        report_metadata["analysis_indicators"] = artifacts.indicators
    if artifacts.workload:
        report_metadata["workload_profile"] = artifacts.workload

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
        analysis_matrices=artifacts.matrices,
        analysis_indicators=artifacts.indicators,
        workload_profile=artifacts.workload,
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
    "make_detector_result",
]
