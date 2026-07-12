"""Report generation and summary helpers for static analysis scan execution."""

from __future__ import annotations

import re
import time
from collections import Counter
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...core import (
    AnalysisConfig,
    SecretsSamplerConfig,
    StaticAnalysisError,
    StaticAnalysisReport,
    analyze_apk,
)
from ...core.findings import Badge, DetectorResult, SeverityLevel
from ...engine.strings_capture import _summarize_bounds_warnings
from ...modules import resolve_category
from ...persistence import ReportStorageError, save_report
from ..core.models import AppRunResult, ArtifactOutcome, RunParameters, ScopeSelection
from .heartbeat_state import set_stage as _hb_set_stage
from .run_health import merge_skipped_detectors, rollup_parse_fallback_signals

ResourceWarningLine = tuple[str, str]


def _append_resource_warning(
    warnings: list[str],
    report: StaticAnalysisReport,
    package_name: str,
    artifact_label: str,
) -> list[ResourceWarningLine]:
    """Append resource-parser warnings and return user-facing inline warning lines."""
    metadata = report.metadata

    if not isinstance(metadata, Mapping):
        return []

    fallback = metadata.get("resource_fallback")
    if isinstance(fallback, Mapping) and fallback.get("fallback_used"):
        reason = fallback.get("fallback_reason") or "aapt2"
        warnings.append(
            "Resource fallback used for APK parsing "
            f"(package={package_name}, artifact={artifact_label}, reason={reason})."
        )

    lines = metadata.get("resource_bounds_warnings")
    if not isinstance(lines, list) or not lines:
        return []

    counts: list[int] = []

    for line in lines:
        if not isinstance(line, str):
            continue

        match = re.search(r"Count:\s*(\d+)", line)
        if match:
            try:
                counts.append(int(match.group(1)))
            except ValueError:
                continue

    count_hint = f" counts={sorted(set(counts))}" if counts else ""
    summary = _summarize_bounds_warnings(list(lines))
    level = str(summary.get("render_level") or "warn")
    parser_provenance = metadata.get("parser_provenance")
    parser_map = parser_provenance if isinstance(parser_provenance, Mapping) else {}
    resource_string_count = metadata.get("string_index_resource_strings")
    parse_error_resources = bool(metadata.get("parse_error_resources"))
    resource_fallback_used = bool(metadata.get("resource_fallback_used"))
    resource_parse_partial = bool(metadata.get("resource_parse_partial") or parser_map.get("resource_parse_partial"))
    resource_parse_state = str(metadata.get("resource_parse_state") or parser_map.get("resource_parse_state") or "")
    resource_string_fallback_count = int(
        metadata.get("resource_string_fallback_count") or parser_map.get("resource_string_fallback_count") or 0
    )
    if level == "info":
        warnings.append(
            "Resource table parser emitted a minor complex-entry bounds note "
            f"(package={package_name}, artifact={artifact_label}{count_hint}). "
            "String/resource coverage may be slightly incomplete; a re-run is usually unnecessary."
        )
        headline = "Resource table parser note (minor complex-entry warning)."
        guidance = (
            "String/resource coverage may be slightly incomplete; re-run only if this APK needs deep string/resource review."
        )
    else:
        recovered = resource_string_fallback_count > 0
        likely_partial = (
            not recovered
            and (parse_error_resources or not resource_fallback_used or resource_string_count in (None, 0))
        )
        if likely_partial:
            warnings.append(
                "Resource table parser emitted bounds warnings that likely indicate a partial resource parse "
                f"(package={package_name}, artifact={artifact_label}{count_hint}). "
                "String/resource results may be materially incomplete; re-run this APK if deep resource review matters."
            )
            headline = "Resource table parse appears partial (string/resource parsing)."
            guidance = (
                "String/resource results may be materially incomplete; re-run this APK if deep resource/resource-string review matters."
            )
        else:
            warnings.append(
                "Resource table parser emitted bounds warnings "
                f"(package={package_name}, artifact={artifact_label}{count_hint}). "
                "String/resource results were recovered with fallback parsing; re-run only if manual resource review needs confirmation."
            )
            if resource_parse_state == "fallback_recovered" or (
                resource_string_fallback_count > 0 and not resource_parse_partial
            ):
                return []
            headline = "Resource table bounds warning with fallback recovery."
            guidance = (
                "String/resource results include fallback-recovered resource strings; re-run only if manual resource review needs confirmation."
            )

    inline_lines: list[ResourceWarningLine] = [
        (level, headline),
        (level, f"Package: {package_name}"),
    ]

    app_label = metadata.get("app_label")
    if isinstance(app_label, str) and app_label.strip() and app_label.strip() != package_name:
        inline_lines.append((level, f"App: {app_label.strip()}"))

    inline_lines.append((level, f"Artifact: {artifact_label}"))

    if counts:
        inline_lines.append((level, f"Count values: {', '.join(str(val) for val in sorted(set(counts)))}"))

    inline_lines.append((level, guidance))
    inline_lines.append((level, "Detector coverage warning only; APK analysis execution is still OK unless execution errors are reported."))

    return inline_lines


_BADGE_PIPELINE_RANK: dict[str, int] = {
    Badge.SKIPPED.value: 0,
    Badge.OK.value: 1,
    Badge.INFO.value: 2,
    Badge.WARN.value: 3,
    Badge.FAIL.value: 4,
    Badge.ERROR.value: 5,
}


def _rollup_status_counts_per_detector(app_result: AppRunResult) -> Counter[str] | None:
    """Merge detector badges across split artifacts using worst status per ``detector_id``.

    Summing per-artifact ``pipeline_summary.status_counts`` double-counts the same logical
    detector across base + split APKs; this roll-up matches operator mental model for
    package-level progress and reduces inflated WARN totals.
    """

    worst_by_detector: dict[str, Badge] = {}
    saw_any = False
    for artifact in app_result.artifacts:
        report = getattr(artifact, "report", None)
        if report is None:
            continue
        for result in getattr(report, "detector_results", ()) or ():
            if not isinstance(result, DetectorResult):
                continue
            saw_any = True
            det = str(result.detector_id or result.section_key or "").strip() or "unknown"
            st = result.status
            prev = worst_by_detector.get(det)
            if prev is None or _BADGE_PIPELINE_RANK.get(st.value, -1) > _BADGE_PIPELINE_RANK.get(
                prev.value, -1
            ):
                worst_by_detector[det] = st
    if not saw_any:
        return None
    out: Counter[str] = Counter()
    for badge in worst_by_detector.values():
        out[badge.value] += 1
    return out


def _summarize_app_pipeline(app_result: AppRunResult) -> dict[str, object]:
    """Summarize detector status and timing metadata across all artifacts for one app.

    ``status_counts`` / ``warn_count`` / ``ok_count`` use **worst badge per ``detector_id``**
    across base + split APKs when ``detector_results`` are present, so session roll-ups are not
    inflated by split repetition. Policy/finding gate rows are deduped per detector/section pair.
    """
    status_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    policy_fail_detectors: list[dict[str, object]] = []
    finding_fail_detectors: list[dict[str, object]] = []
    error_detectors: list[dict[str, object]] = []
    slowest: list[dict[str, object]] = []

    detector_total = 0
    detector_executed = 0
    detector_skipped = 0
    total_duration_sec = 0.0
    skipped_detector_rows_collect: list[Mapping[str, object]] = []
    policy_fail_keys: set[tuple[str, str]] = set()
    finding_fail_keys: set[tuple[str, str]] = set()

    for artifact in app_result.artifacts:
        report = artifact.report
        metadata = report.metadata if isinstance(getattr(report, "metadata", None), Mapping) else {}
        summary = metadata.get("pipeline_summary") if isinstance(metadata.get("pipeline_summary"), Mapping) else None

        if isinstance(summary, Mapping):
            detector_total += int(summary.get("detector_total", 0) or 0)
            detector_executed += int(summary.get("detector_executed", 0) or 0)
            detector_skipped += int(summary.get("detector_skipped", 0) or 0)
            total_duration_sec += float(summary.get("total_duration_sec", 0.0) or 0.0)

            for key, value in (summary.get("severity_counts") or {}).items():
                severity_counts[str(key)] += int(value or 0)

            payload_policy = summary.get("policy_fail_detectors")
            if isinstance(payload_policy, list):
                for row in payload_policy:
                    if not isinstance(row, Mapping):
                        continue
                    det = str(row.get("detector") or "").strip()
                    sec = str(row.get("section") or "").strip()
                    key_t = (det, sec)
                    if key_t in policy_fail_keys:
                        continue
                    policy_fail_keys.add(key_t)
                    policy_fail_detectors.append(dict(row))

            payload_finding = summary.get("finding_fail_detectors")
            if isinstance(payload_finding, list):
                for row in payload_finding:
                    if not isinstance(row, Mapping):
                        continue
                    det = str(row.get("detector") or "").strip()
                    sec = str(row.get("section") or "").strip()
                    key_t = (det, sec)
                    if key_t in finding_fail_keys:
                        continue
                    finding_fail_keys.add(key_t)
                    finding_fail_detectors.append(dict(row))

            payload_err = summary.get("error_detectors")
            if isinstance(payload_err, list):
                error_detectors.extend(row for row in payload_err if isinstance(row, Mapping))

            payload = summary.get("slowest_detectors")
            if isinstance(payload, list):
                slowest.extend([row for row in payload if isinstance(row, Mapping)])

            skips = summary.get("skipped_detectors")
            if isinstance(skips, list):
                skipped_detector_rows_collect.extend(row for row in skips if isinstance(row, Mapping))

    rolled = _rollup_status_counts_per_detector(app_result)
    if rolled is not None:
        status_counts = rolled
    else:
        for artifact in app_result.artifacts:
            report = artifact.report
            metadata = report.metadata if isinstance(getattr(report, "metadata", None), Mapping) else {}
            summary = metadata.get("pipeline_summary") if isinstance(metadata.get("pipeline_summary"), Mapping) else None
            if not isinstance(summary, Mapping):
                continue
            for key, value in (summary.get("status_counts") or {}).items():
                status_counts[str(key)] += int(value or 0)

    slowest_sorted = sorted(
        slowest,
        key=lambda row: float(row.get("duration_sec", 0.0) or 0.0),
        reverse=True,
    )

    policy_fail_count = len(policy_fail_detectors)
    finding_fail_count = len(finding_fail_detectors)

    skipped_detectors_merged = merge_skipped_detectors(skipped_detector_rows_collect)

    fallback_meta = rollup_parse_fallback_signals(app_result)

    merged_error_detectors_seen: set[tuple[str, str]] = set()
    dedup_errors: list[dict[str, object]] = []
    for row in error_detectors:
        if not isinstance(row, Mapping):
            continue
        detector = str(row.get("detector") or row.get("section") or "").strip()
        reason = str(row.get("reason") or "").strip()
        key = (detector, reason)
        if key in merged_error_detectors_seen:
            continue
        merged_error_detectors_seen.add(key)
        dedup_errors.append(dict(row))

    error_detector_events = len(dedup_errors)

    detector_error_counts = Counter()
    for row in dedup_errors:
        detector = str(row.get("detector") or row.get("section") or "?").strip() or "?"
        detector_error_counts[detector] += 1

    return {
        "detector_total": detector_total,
        "detector_executed": detector_executed,
        "detector_skipped": detector_skipped,
        "total_duration_sec": total_duration_sec,
        "status_counts": {k: int(v) for k, v in status_counts.items()},
        "severity_counts": {k: int(v) for k, v in severity_counts.items()},
        "policy_fail_count": policy_fail_count,
        "finding_fail_count": finding_fail_count,
        "error_count": error_detector_events,
        "detector_error_events": error_detector_events,
        "detector_error_counts_by_id": dict(detector_error_counts),
        "policy_fail_detectors": policy_fail_detectors,
        "finding_fail_detectors": finding_fail_detectors,
        "error_detectors": dedup_errors,
        "slowest_detectors": slowest_sorted[:3],
        "ok_count": int(status_counts.get("OK", 0)),
        "warn_count": int(status_counts.get("WARN", 0)),
        "fail_count": int(policy_fail_count + finding_fail_count),
        "skipped_detectors": skipped_detectors_merged,
        "skipped_detectors_raw_events": len(skipped_detector_rows_collect),
        "skipped_detectors_unique_rows": len(skipped_detectors_merged),
        "resource_fallback_used_artifacts": fallback_meta["resource_fallback_used_artifacts"],
        "resource_bounds_warning_artifacts": fallback_meta["resource_bounds_warning_artifacts"],
        "label_parse_signal_artifacts": fallback_meta["label_parse_signal_artifacts"],
        "parse_fallback_events_est": fallback_meta["parse_fallback_events_est"],
    }


def _execute_single_artifact(
    artifact,
    params: RunParameters,
    selection: ScopeSelection,
    base_dir: Path,
    *,
    extra_metadata: Mapping[str, object] | None = None,
    phase_timing_sink: MutableMapping[str, float] | None = None,
    precomputed_report: StaticAnalysisReport | None = None,
    runtime_state: MutableMapping[str, object] | None = None,
):
    """Run analysis for a single APK artifact and return report plus scan summary."""

    if precomputed_report is not None:
        report, json_path, error, skipped = finish_report_after_analysis(
            precomputed_report,
            params,
            base_dir,
            phase_timing_sink=phase_timing_sink,
        )
    else:
        report, json_path, error, skipped = generate_report(
            artifact,
            base_dir,
            params,
            extra_metadata=extra_metadata,
            phase_timing_sink=phase_timing_sink,
            runtime_state=runtime_state,
        )

    if skipped:
        return None, None, tuple(), error, True

    if error:
        return None, None, tuple(), error, False

    duration = report.metadata.get("duration_seconds", 0.0) if isinstance(report.metadata, Mapping) else 0.0

    timings = tuple(
        (result.detector_id or "detector", float(getattr(result, "duration_sec", 0.0) or 0.0))
        for result in getattr(report, "detector_results", [])
    )

    total_detector_time = sum(value for _, value in timings)

    if (duration or 0.0) <= 0.0 and total_detector_time > 0.0:
        duration = total_detector_time

    summary = _summarize_artifact(artifact, report, json_path, duration)

    return report, summary, timings, None, False


def _summarize_artifact(
    artifact,
    report: StaticAnalysisReport,
    json_path: Path | None,
    duration: float,
) -> ArtifactOutcome:
    """Build the per-artifact outcome object used by scan orchestration."""
    severity = Counter[str]()

    for result in report.detector_results:
        for finding in result.findings:
            severity[_severity_token(finding.severity_gate)] += 1

    return ArtifactOutcome(
        label=artifact.artifact_label or artifact.display_path,
        report=report,
        severity=severity,
        duration_seconds=duration,
        saved_path=str(json_path) if json_path else None,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        metadata=artifact.metadata,
    )


def build_scan_report_metadata_payload(
    artifact,
    params: RunParameters,
    *,
    extra_metadata: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Merge artifact + run metadata used by ``analyze_apk`` (shared with pool workers)."""

    metadata_payload: dict[str, object] = dict(artifact.metadata)

    metadata_payload["run_profile"] = params.profile
    metadata_payload["run_scope"] = params.scope
    metadata_payload["run_scope_label"] = params.scope_label
    metadata_payload["selected_tests"] = list(params.selected_tests)

    if params.session_stamp:
        metadata_payload["session_stamp"] = params.session_stamp

    if not metadata_payload.get("category"):
        package_name = getattr(artifact, "package_name", None)

        if not isinstance(package_name, str) or not package_name.strip():
            package_name = metadata_payload.get("package_name")

        if isinstance(package_name, str) and package_name.strip():
            metadata_payload["category"] = resolve_category(package_name, metadata_payload)

    if extra_metadata:
        metadata_payload.update(
            {
                key: value
                for key, value in extra_metadata.items()
                if value is not None
            }
        )

    return metadata_payload


def finish_report_after_analysis(
    report: StaticAnalysisReport,
    params: RunParameters,
    base_dir: Path,
    *,
    phase_timing_sink: MutableMapping[str, float] | None = None,
):
    """Persist (or skip) after ``analyze_apk`` — mirrors :func:`generate_report` post-analyze branches."""

    if params.dry_run:
        try:
            _hb_set_stage("dry_run:not_persisted")
        except Exception:
            pass

        return report, None, "dry-run (not persisted)", True

    persistence_ready = bool(getattr(params, "persistence_ready", True))

    if not persistence_ready:
        try:
            _hb_set_stage("persist:skipped")
        except Exception:
            pass

        return report, None, None, False

    try:
        try:
            _hb_set_stage("persist:save_report")
        except Exception:
            pass

        t1 = time.monotonic()
        execution_id = getattr(params, "execution_id", None)
        try:
            saved_paths = save_report(
                report,
                execution_id=execution_id,
            )
        except TypeError as exc:
            # Compatibility bridge for older test doubles / wrappers that still expose
            # the legacy save_report(report) signature.
            if "unexpected keyword argument 'execution_id'" not in str(exc):
                raise
            saved_paths = save_report(report)
        if phase_timing_sink is not None:
            phase_timing_sink["persist_wall_s"] = phase_timing_sink.get("persist_wall_s", 0.0) + (
                time.monotonic() - t1
            )

        try:
            _hb_set_stage("persist:done")
        except Exception:
            pass

        return report, saved_paths.json_path, None, False

    except ReportStorageError as exc:
        log.error(str(exc), category="static_analysis")

        try:
            _hb_set_stage("error:persist")
        except Exception:
            pass

        return report, None, str(exc), False


def generate_report(
    artifact,
    base_dir: Path,
    params: RunParameters,
    *,
    extra_metadata: Mapping[str, object] | None = None,
    phase_timing_sink: MutableMapping[str, float] | None = None,
    runtime_state: MutableMapping[str, object] | None = None,
):
    """Generate and optionally persist one static analysis report."""
    metadata_payload = build_scan_report_metadata_payload(
        artifact,
        params,
        extra_metadata=extra_metadata,
    )

    def _stage_observer(evt: object) -> None:
        """Expose detector stage progress to heartbeat state without printing."""
        if not isinstance(evt, dict):
            return

        if evt.get("event") != "stage_start":
            return

        section = str(evt.get("section_key") or evt.get("detector_id") or "unknown")
        idx = evt.get("stage_index")
        total = evt.get("stage_total")

        try:
            _hb_set_stage(
                f"detector:{section}",
                stage_index=int(idx) if isinstance(idx, (int, float, str)) else None,
                stage_total=int(total) if isinstance(total, (int, float, str)) else None,
            )
        except Exception:
            return

    stage_observer = _stage_observer

    try:
        try:
            _hb_set_stage("prepare:analyze_apk")
        except Exception:
            pass

        t0 = time.monotonic()
        report = analyze_apk(
            artifact.path,
            metadata=metadata_payload,
            storage_root=base_dir,
            config=build_analysis_config(params),
            runtime_state=runtime_state,
            stage_observer=stage_observer,
        )
        if phase_timing_sink is not None:
            phase_timing_sink["analyze_apk_wall_s"] = phase_timing_sink.get("analyze_apk_wall_s", 0.0) + (
                time.monotonic() - t0
            )

    except StaticAnalysisError as exc:
        try:
            _hb_set_stage("error:analyze_apk")
        except Exception:
            pass

        return None, None, str(exc), True

    return finish_report_after_analysis(
        report,
        params,
        base_dir,
        phase_timing_sink=phase_timing_sink,
    )


def build_analysis_config(params: RunParameters) -> AnalysisConfig:
    """Build core static-analysis configuration from CLI run parameters."""
    profile_map = {
        "metadata": "quick",
        "permissions": "quick",
        "lightweight": "quick",
        "full": "full",
        "split": "quick",
        "strings": "quick",
        "webview": "quick",
        "nsc": "quick",
        "ipc": "quick",
        "crypto": "quick",
        "sdk": "quick",
    }

    profile = profile_map.get(params.profile, "full")
    enabled_detectors = _map_tests_to_detectors(params)
    enable_string_index = params.profile not in {"metadata", "permissions"}
    # Quick pipeline presets skip ARSC resource strings unless the operator picked the strings preset.
    string_index_include_resources = profile == "full" or params.profile == "strings"
    split_member_string_index_policy = "full" if params.profile == "strings" else "lightweight"

    sampler = SecretsSamplerConfig(
        entropy_threshold=max(0.0, float(params.secrets_entropy)),
        hits_per_bucket=max(1, int(params.secrets_hits_per_bucket or 1)),
        scope=params.secrets_scope_canonical,
    )

    return AnalysisConfig(
        profile=profile,
        verbosity=params.log_level,
        enabled_detectors=enabled_detectors or None,
        enable_string_index=enable_string_index,
        string_index_include_resources=string_index_include_resources,
        split_member_string_index_policy=split_member_string_index_policy,
        post_run_string_mode=params.strings_mode,
        post_run_string_min_entropy=float(params.string_min_entropy),
        post_run_string_max_samples=params.string_max_samples,
        post_run_string_cleartext_only=bool(params.string_cleartext_only),
        post_run_string_include_https_risk=params.string_include_https_risk,
        secrets_sampler=sampler,
    )


def _map_tests_to_detectors(params: RunParameters) -> tuple[str, ...]:
    """Map CLI profile/test selection to core detector identifiers."""
    if params.profile == "metadata":
        return ("integrity_identity",)

    if params.profile == "permissions":
        return ("permissions_profile",)

    if params.profile == "strings":
        return ("secrets", "webview", "network_surface")

    if params.profile == "webview":
        return ("webview_hygiene",)

    if params.profile == "nsc":
        return ("network_surface",)

    if params.profile == "ipc":
        return ("ipc_components", "provider_acl")

    if params.profile == "crypto":
        return ("crypto_hygiene",)

    if params.profile == "sdk":
        return ("sdk_inventory",)

    return tuple()


def _severity_token(level: SeverityLevel) -> str:
    """Return compact severity token used in artifact summaries."""
    return {
        SeverityLevel.P0: "H",
        SeverityLevel.P1: "M",
        SeverityLevel.P2: "L",
        SeverityLevel.NOTE: "I",
    }.get(level, "I")


__all__ = [
    "_append_resource_warning",
    "_execute_single_artifact",
    "_summarize_app_pipeline",
    "build_analysis_config",
    "generate_report",
]
