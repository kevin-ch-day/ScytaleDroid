"""Core helpers for running static analysis on APK artifacts (hardened)."""

from __future__ import annotations

import functools
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_engine import configure_third_party_loggers

from .._androguard import APK
from ..engine import aapt2_fallback
from ..engine.strings import _analyse_strings_from_index
from ..engine.strings_capture import _classify_resource_parse_state, _summarize_bounds_warnings
from ..detectors.correlation.runtime_state import snapshot_runtime_stats
from ..modules import build_string_index
from ..modules.string_analysis.origins import is_code_origin, is_resource_origin
from ..modules.network_security import extract_network_security_policy
from ..modules.permissions import load_permission_catalog
from .context import AnalysisConfig
from .context_builders import (
    build_detector_context,
    collect_dangerous_permissions,
    derive_run_id,
    resolve_relative_path,
)
from .detector_runner import PIPELINE_STAGES, PipelineStage, run_detector_pipeline
from .errors import StaticAnalysisError
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
from .resource_fallback import merge_metadata, open_apk_with_fallback
from .results_builder import make_detector_result

# Last non-debug verbosity passed to ``configure_third_party_loggers`` (``None`` = debug or cold).
_apk_non_debug_log_verbosity: str | None = None
_HASH_DIGEST_LENGTHS: Mapping[str, int] = {"md5": 32, "sha1": 40, "sha256": 64}


def _next_apk_logger_reconfigure(
    verbosity: str, last_non_debug: str | None
) -> tuple[bool, str | None]:
    """Return whether to call ``configure_third_party_loggers`` and the next ``last_non_debug`` value."""

    if verbosity == "debug":
        return True, None
    if last_non_debug != verbosity:
        return True, verbosity
    return False, last_non_debug


# -----------------------
# Small, focused helpers
# -----------------------

def _safe_get_app_label(apk: APK, pkg_name: str, meta: dict) -> str:
    """
    Try Androguard first; if ARSC parsing explodes, try `aapt2 dump badging`;
    finally fall back to package name. Record fallbacks in metadata.
    """
    try:
        label, _ = _run_with_fd_capture(apk.get_app_name)
        if isinstance(label, str) and label.strip():
            return label
    except Exception as e:
        meta["parse_error_resources"] = True
        meta["label_error"] = str(e)

    # aapt2 fallback (best-effort, short timeout)
    if aapt2_fallback.has_aapt2():
        try:
            out = aapt2_fallback.dump_badging(apk.filename)
            if not out:
                raise RuntimeError("aapt2 dump badging returned no output")
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


def _safe_get_main_activity(apk: APK, meta: dict) -> str | None:
    try:
        result, _ = _run_with_fd_capture(apk.get_main_activity)
        return result
    except Exception as e:
        meta["main_activity_fallback"] = True
        meta["main_activity_error"] = str(e)
        return None


def _safe_tuple(callable_, meta: dict, meta_key: str) -> tuple[str, ...]:
    try:
        data, _ = _run_with_fd_capture(callable_)  # may return list/tuple/None
        if not data:
            return ()
        return tuple(sorted(data))
    except Exception as e:
        meta[meta_key] = str(e)
        return ()


def _safe_permission_details(apk: APK, meta: dict) -> Mapping[str, Sequence[str]]:
    try:
        details, _ = _run_with_fd_capture(apk.get_details_permissions)
        return details or {}
    except Exception as e:
        meta["permissions_fallback"] = True
        meta["permissions_error"] = str(e)
        return {}


def _extract_bounds_warnings(text: str) -> list[str]:
    if not text:
        return []
    lines: list[str] = []
    for raw in text.replace("\r", "\n").split("\n"):
        candidate = raw.strip()
        if not candidate:
            continue
        lowered = candidate.lower()
        if "out of bound" in lowered or "complex entry" in lowered:
            lines.append(candidate)
    return lines


def _run_with_fd_capture(callable_obj):
    stdout_fd = os.dup(1)
    stderr_fd = os.dup(2)
    temp = tempfile.TemporaryFile(mode="w+b")
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(temp.fileno(), 1)
        os.dup2(temp.fileno(), 2)
        result = callable_obj()
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        os.close(stdout_fd)
        os.close(stderr_fd)
    temp.seek(0)
    raw = temp.read()
    temp.close()
    return result, raw.decode("utf-8", errors="replace")


def _load_apk_safely(apk_path: Path, meta: dict) -> APK:
    fallback = open_apk_with_fallback(apk_path)
    meta.update(merge_metadata(meta, fallback))
    if fallback.warnings:
        log.warning(
            "Resource table parsing emitted bounds warnings",
            category="static_analysis",
            extra={
                "event": "apk.resource_bounds_warning",
                "apk_path": str(apk_path),
                "warning_lines": fallback.warnings,
            },
        )
    if fallback.apk is None:
        reason = fallback.fallback_reason or "androguard_open_failed"
        raise StaticAnalysisError(f"Failed to open APK with Androguard ({reason}).")
    return fallback.apk


@functools.lru_cache(maxsize=1)
def _frozen_toolchain_versions() -> tuple[tuple[str, str], ...]:
    """Cached toolchain probe (immutable tuple for ``lru_cache`` safety)."""

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
    apksigner = shutil.which("apksigner")
    if apksigner:
        versions["apksigner"] = "present"
    return tuple(versions.items())


def _resolve_toolchain_versions() -> Mapping[str, str]:
    return dict(_frozen_toolchain_versions())


def _build_parser_provenance(metadata: Mapping[str, object]) -> dict[str, object]:
    fallback = metadata.get("resource_fallback")
    fallback_payload = fallback if isinstance(fallback, Mapping) else {}
    fallback_used = _coerce_bool(fallback_payload.get("fallback_used"))
    fallback_reason = str(fallback_payload.get("fallback_reason") or "").strip() or None
    resource_string_fallback_count = _coerce_int(metadata.get("resource_string_fallback_count")) or 0
    resource_string_fallback_used = resource_string_fallback_count > 0

    label_source = str(metadata.get("label_fallback") or "").strip() or "androguard"
    if label_source == "package_name":
        label_source = "package_name_fallback"

    warning_count = 0
    warning_summary: dict[str, object] = {}
    warnings = metadata.get("resource_bounds_warnings")
    if isinstance(warnings, Sequence) and not isinstance(warnings, (str, bytes)):
        warning_lines = [str(line).strip() for line in warnings if str(line).strip()]
        warning_count = len(warning_lines)
        if warning_lines:
            warning_summary = _summarize_bounds_warnings(warning_lines)
            parse_state = _classify_resource_parse_state(
                warning_lines,
                resource_string_count=_coerce_int(metadata.get("string_index_resource_strings")),
                parse_error_resources=_coerce_bool(metadata.get("parse_error_resources")),
                resource_fallback_used=fallback_used,
            )
            if resource_string_fallback_used:
                parse_state = {
                    "parse_state": "fallback_recovered",
                    "parse_partial": False,
                    "reparse_candidate": False,
                }
        else:
            parse_state = {
                "parse_state": "none",
                "parse_partial": False,
                "reparse_candidate": False,
            }
    else:
        warning_count = _coerce_int(fallback_payload.get("warning_count")) or 0
        parse_state = {
            "parse_state": "none",
            "parse_partial": False,
            "reparse_candidate": False,
        }

    return {
        "manifest_source": str(metadata.get("manifest_source") or "androguard"),
        "manifest_semantics_source": str(
            metadata.get("manifest_semantics_source") or metadata.get("manifest_source") or "androguard"
        ),
        "resource_open_source": "aapt2_metadata_fallback"
        if fallback_used
        else ("androguard+aapt2_resource_strings" if resource_string_fallback_used else "androguard"),
        "resource_fallback_used": fallback_used,
        "resource_fallback_reason": fallback_reason,
        "resource_string_fallback_used": resource_string_fallback_used,
        "resource_string_fallback_count": resource_string_fallback_count,
        "resource_bounds_warning_count": warning_count,
        "resource_bounds_warning_severity": str(warning_summary.get("severity") or "none"),
        "resource_bounds_warning_kind": str(warning_summary.get("warning_kind") or "none"),
        "resource_parse_state": str(parse_state.get("parse_state") or "none"),
        "resource_parse_partial": bool(parse_state.get("parse_partial")),
        "resource_reparse_candidate": bool(parse_state.get("reparse_candidate")),
        "label_source": label_source,
        "string_index_source": "androguard"
        if not str(metadata.get("string_index_error") or "").strip()
        else "string_index_unavailable",
        "aapt2_available": _coerce_bool(fallback_payload.get("aapt2_available")),
    }


def _merge_resource_bounds_warnings(
    metadata: MutableMapping[str, object],
    warnings: Sequence[object] | None,
) -> None:
    """Merge parser warning lines into report metadata without duplicating them."""

    if not warnings:
        return
    existing = metadata.get("resource_bounds_warnings")
    merged: list[str] = []
    if isinstance(existing, Sequence) and not isinstance(existing, (str, bytes)):
        merged.extend(str(line) for line in existing if str(line).strip())
    for line in warnings:
        text = str(line).strip()
        if text and text not in merged:
            merged.append(text)
    if merged:
        metadata["resource_bounds_warnings"] = merged


def _string_warning_log_context(metadata: Mapping[str, object]) -> dict[str, object]:
    keys = (
        "execution_id",
        "session_stamp",
        "session_label",
        "run_id",
        "package_name",
        "normalized_package_name",
        "sha256",
        "base_apk_sha256",
        "artifact_role",
        "artifact_index",
        "artifact_total",
        "is_split_member",
    )
    return {
        key: metadata[key]
        for key in keys
        if metadata.get(key) is not None
    }


def _normalize_hash(value: object, *, length: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if len(normalized) != length:
        return None
    if any(ch not in "0123456789abcdef" for ch in normalized):
        return None
    return normalized


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None
    return None


def _coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _summarize_string_index_metadata(string_index: object) -> dict[str, object]:
    strings = tuple(getattr(string_index, "strings", tuple()) or tuple())
    by_origin_type: Mapping[str, int]
    if hasattr(string_index, "counts_by_origin_type"):
        counts = getattr(string_index, "counts_by_origin_type")()
        by_origin_type = dict(counts) if isinstance(counts, Mapping) else {}
    else:
        rolled: MutableMapping[str, int] = {}
        for entry in strings:
            origin_type = str(getattr(entry, "origin_type", "unknown") or "unknown")
            rolled[origin_type] = rolled.get(origin_type, 0) + 1
        by_origin_type = dict(rolled)

    code_strings = 0
    resource_strings = 0
    native_strings = 0
    asset_strings = 0
    for origin_type, count in by_origin_type.items():
        if is_code_origin(origin_type):
            code_strings += int(count)
        elif is_resource_origin(origin_type):
            resource_strings += int(count)
        elif origin_type == "native":
            native_strings += int(count)
        elif origin_type == "asset":
            asset_strings += int(count)

    return {
        "string_index_total_strings": len(strings),
        "string_index_by_origin_type": by_origin_type,
        "string_index_code_strings": code_strings,
        "string_index_resource_strings": resource_strings,
        "string_index_native_strings": native_strings,
        "string_index_asset_strings": asset_strings,
        "resource_string_fallback_count": int(getattr(string_index, "aapt2_resource_fallback_count", 0) or 0),
    }


def _resolve_trusted_metadata_hashes(apk_path: Path, metadata: Mapping[str, object]) -> tuple[dict[str, str] | None, str]:
    digests: dict[str, str] = {}
    for algo, expected_length in _HASH_DIGEST_LENGTHS.items():
        normalized = _normalize_hash(metadata.get(algo), length=expected_length)
        if normalized is None:
            return None, f"missing_or_invalid_{algo}"
        digests[algo] = normalized

    actual_size = apk_path.stat().st_size
    declared_size = _coerce_int(metadata.get("file_size"))
    if declared_size is not None and declared_size != actual_size:
        return None, "file_size_mismatch"

    try:
        expected_canonical = artifact_store.canonical_apk_path(digests["sha256"]).resolve()
    except Exception:
        return None, "canonical_path_error"
    if apk_path.resolve() != expected_canonical:
        return None, "not_canonical_store_path"

    canonical_store_path = metadata.get("canonical_store_path")
    if isinstance(canonical_store_path, str) and canonical_store_path.strip():
        candidate = Path(canonical_store_path.strip())
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            if candidate.resolve() != expected_canonical:
                return None, "canonical_store_path_mismatch"
        except Exception:
            return None, "canonical_store_path_unresolvable"

    return digests, "canonical_store_verified"


def _resolve_hashes_for_analysis(apk_path: Path, metadata: Mapping[str, object]) -> tuple[dict[str, str], dict[str, object]]:
    trusted_hashes, provenance_reason = _resolve_trusted_metadata_hashes(apk_path, metadata)
    if trusted_hashes is not None:
        return trusted_hashes, {
            "hash_source": "trusted_metadata",
            "hash_recomputed": False,
            "hash_provenance_ok": True,
            "hash_provenance_reason": provenance_reason,
        }

    return compute_hashes(apk_path), {
        "hash_source": "computed",
        "hash_recomputed": True,
        "hash_provenance_ok": False,
        "hash_provenance_reason": provenance_reason,
    }


def analyze_apk(
    apk_path: Path,
    *,
    metadata: Mapping[str, object | None] = None,
    storage_root: Path | None = None,
    config: AnalysisConfig | None = None,
    runtime_state: MutableMapping[str, object] | None = None,
    stage_observer: object | None = None,
) -> StaticAnalysisReport:
    """Run resilient static analysis on *apk_path* and return a report."""

    if not apk_path.exists():
        raise StaticAnalysisError(f"APK not found: {apk_path}")

    analysis_started = time.monotonic()
    analysis_config = config or AnalysisConfig()
    report_metadata: dict[str, object] = dict(metadata or {})

    hash_started = time.monotonic()
    hashes, hash_meta = _resolve_hashes_for_analysis(apk_path, report_metadata)
    report_metadata.update(hash_meta)
    report_metadata["hash_seconds"] = time.monotonic() - hash_started
    apk_sha256 = hashes.get("sha256", "")
    run_id = derive_run_id(apk_sha256, analysis_config)
    report_metadata.setdefault("run_id", run_id)

    global _apk_non_debug_log_verbosity
    verbosity = analysis_config.verbosity
    should_configure, _apk_non_debug_log_verbosity = _next_apk_logger_reconfigure(
        verbosity, _apk_non_debug_log_verbosity
    )
    if should_configure:
        log_path = configure_third_party_loggers(
            verbosity=verbosity,
            run_id=run_id,
            debug_dir=str(Path(app_config.LOGS_DIR).resolve()),
        )
    else:
        log_path = None
    if log_path is not None:
        report_metadata["androguard_log_path"] = str(log_path)

    try:
        apk = _load_apk_safely(apk_path, report_metadata)
    except Exception as exc:
        # Hard-open failure (corrupt zip, etc.)
        raise StaticAnalysisError(f"Failed to open APK: {exc}") from exc

    report_metadata.setdefault("toolchain", _resolve_toolchain_versions())
    report_metadata.setdefault("manifest_source", "androguard")
    report_metadata.setdefault("manifest_semantics_source", "androguard")

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
        is_split_member = bool(report_metadata.get("is_split_member"))
        split_member_policy = str(analysis_config.split_member_string_index_policy or "full")
        report_metadata["string_index_include_resources"] = bool(
            analysis_config.string_index_include_resources
        )
        report_metadata["string_index_split_member_policy"] = split_member_policy
        report_metadata["string_index_mode"] = (
            "split_lightweight" if is_split_member and split_member_policy == "lightweight" else "full"
        )
        string_index_started = time.monotonic()
        try:
            string_index = build_string_index(
                apk,
                include_resources=analysis_config.string_index_include_resources,
                is_split_member=is_split_member,
                split_member_policy=split_member_policy,
                log_context=_string_warning_log_context(report_metadata),
            )
            report_metadata["string_index_seconds"] = time.monotonic() - string_index_started
            if string_index is not None:
                string_index_warnings = tuple(
                    getattr(string_index, "resource_bounds_warnings", ()) or ()
                )
                _merge_resource_bounds_warnings(report_metadata, string_index_warnings)
                report_metadata.update(_summarize_string_index_metadata(string_index))
                try:
                    payload = _analyse_strings_from_index(
                        string_index,
                        mode=analysis_config.post_run_string_mode,
                        min_entropy=analysis_config.post_run_string_min_entropy,
                        max_samples=analysis_config.post_run_string_max_samples,
                        cleartext_only=analysis_config.post_run_string_cleartext_only,
                        include_https_risk=analysis_config.post_run_string_include_https_risk,
                        artifact_context=report_metadata,
                        warnings=string_index_warnings,
                    )
                    if isinstance(payload, Mapping):
                        payload = dict(payload)
                        payload.setdefault("aggregation_scope", "single_artifact")
                    report_metadata["post_run_string_payload"] = payload
                except Exception as exc:
                    report_metadata["post_run_string_payload_error"] = str(exc)
        except Exception as e:
            report_metadata["string_index_seconds"] = time.monotonic() - string_index_started
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
        runtime_state=runtime_state,
    )
    if callable(stage_observer):
        # Optional stage-level progress hook (used by CLI batch runs). Must not affect analysis.
        context.stage_observer = stage_observer

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
    correlation_runtime_stats = snapshot_runtime_stats(getattr(context, "runtime_state", None))
    if correlation_runtime_stats:
        report_metadata["correlation_runtime_stats"] = correlation_runtime_stats
    report_metadata["parser_provenance"] = _build_parser_provenance(report_metadata)
    report_metadata["artifact_total_wall_s"] = time.monotonic() - analysis_started

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
    "_resolve_hashes_for_analysis",
]
