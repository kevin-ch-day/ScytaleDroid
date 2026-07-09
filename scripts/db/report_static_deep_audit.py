#!/usr/bin/env python3
"""Read-only deep audit over static evidence quality, readiness, and bridge gaps."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

QUALITY_TIER_DEFINITIONS = {
    "A+": "95-100 excellent / publication-grade static evidence",
    "A": "90-94 paper-ready static evidence",
    "B+": "85-89 strong evidence, minor gaps",
    "B": "80-84 usable evidence, some limitations",
    "C+": "70-79 partial but research-useful",
    "C": "60-69 partial / needs improvement",
    "D": "40-59 diagnostic only",
    "F": "0-39 invalid / excluded",
}

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "run_evidence_quality.csv",
    "app_static_readiness.csv",
    "static_bridge_readiness.csv",
    "split_performance_hotspots.csv",
    "paper_pattern_matrix.csv",
    "static_hidden_pattern_candidates.csv",
    "profile_group_summary.csv",
    "recommended_next_actions.json",
)

KNOWN_LIMITATIONS = [
    "Static archive JSON is per-APK artifact evidence while canonical DB rows are package/base-report scoped; counts are intentionally not forced to match one-for-one.",
    "Detector warning/policy-gate posture is surfaced as interpretation debt, not treated as an execution crash when detector_errors remain zero.",
    "Static-to-dynamic corroboration is derived from current dynamic evidence packs and top DNS/SNI overlap, not deeper full-flow attribution.",
    "Quality/readiness scores are research audit heuristics for prioritization and paper support, not app risk or vulnerability severity scores.",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session",
        "--session-stamp",
        dest="session_stamp",
        default=None,
        help="Static session stamp. Defaults to the newest completed static run-health session.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/static_deep_audit/<stamp>/.",
    )
    return parser


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _package_key(value: Any) -> str | None:
    text = _norm_text_or_none(value)
    return text.lower() if text else None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _repo_rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(_REPO_ROOT.resolve()))
    except Exception:
        return str(path)


def _run_health_dir(data_dir: Path) -> Path:
    return data_dir / "store" / "apk"


def _reports_archive_dir(data_dir: Path, session_stamp: str) -> Path:
    return data_dir / "static_analysis" / "reports" / "archive" / session_stamp


def _quality_tier(score: float) -> str:
    if score >= 95.0:
        return "A+"
    if score >= 90.0:
        return "A"
    if score >= 85.0:
        return "B+"
    if score >= 80.0:
        return "B"
    if score >= 70.0:
        return "C+"
    if score >= 60.0:
        return "C"
    if score >= 40.0:
        return "D"
    return "F"


def _latest_completed_session(data_dir: Path) -> str | None:
    candidates = sorted(_run_health_dir(data_dir).glob("*_run_health.json"))
    best: tuple[float, str] | None = None
    fallback: tuple[float, str] | None = None
    for path in candidates:
        mtime = path.stat().st_mtime
        session = path.name.removesuffix("_run_health.json")
        fallback = max(fallback or (mtime, session), (mtime, session))
        payload = _read_json(path)
        if not isinstance(payload, Mapping):
            continue
        if _norm_text(payload.get("workflow_completion_status")).lower() != "complete":
            continue
        if _norm_text(payload.get("final_run_status")).lower() != "complete":
            continue
        if not list(payload.get("apps") or []):
            continue
        best = max(best or (mtime, session), (mtime, session))
    if best is not None:
        return best[1]
    if fallback is not None:
        return fallback[1]
    return None


def _resolve_session_stamp(data_dir: Path, requested: str | None) -> str | None:
    token = _norm_text_or_none(requested)
    if token:
        return token
    return _latest_completed_session(data_dir)


def _load_run_health(data_dir: Path, session_stamp: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[str]]:
    warnings: list[str] = []
    path = _run_health_dir(data_dir) / f"{session_stamp}_run_health.json"
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        warnings.append(f"run_health_missing:{_repo_rel(path)}")
        return {}, {}, warnings

    package_rows: dict[str, dict[str, Any]] = {}
    for app in payload.get("apps") or []:
        if not isinstance(app, Mapping):
            continue
        package_name = _package_key(app.get("package_name"))
        if not package_name:
            continue
        finding_persistence = app.get("finding_persistence")
        persistence_map = finding_persistence if isinstance(finding_persistence, Mapping) else {}
        package_rows[package_name] = {
            "display_name": _norm_text_or_none(app.get("app_label") or app.get("package_name")),
            "runtime_findings": _safe_int(persistence_map.get("runtime_findings")),
            "persisted_findings_db": _safe_int(persistence_map.get("persisted_findings_db")),
            "capped_not_persisted": _safe_int(persistence_map.get("capped_not_persisted")),
            "runtime_p0_findings": _safe_int(persistence_map.get("runtime_p0_findings")),
            "persisted_p0_findings_db": _safe_int(persistence_map.get("persisted_p0_findings_db")),
            "capped_p0_not_persisted": _safe_int(persistence_map.get("capped_p0_not_persisted")),
            "artifact_count": _safe_int(app.get("discovered_artifacts")),
            "final_status": _norm_text_or_none(app.get("final_status")),
            "workflow_completion_status": _norm_text_or_none(app.get("workflow_completion_status")),
            "db_persistence_status": _norm_text_or_none(app.get("db_persistence_status")),
            "detector_posture": _norm_text_or_none(app.get("detector_posture")),
            "finding_fidelity_status": _norm_text_or_none(app.get("finding_fidelity_status")),
            "detector_warnings_agg": _safe_int(app.get("detector_warnings_agg")),
            "detector_failures_agg": _safe_int(app.get("detector_failures_agg")),
            "detector_errors_agg": _safe_int(app.get("detector_errors_agg")),
            "report_paths_short": list(app.get("report_paths_short") or []),
        }
    return dict(payload), package_rows, warnings


def _load_optional_db(session_stamp: str) -> tuple[dict[str, Any], list[str]]:
    from scripts.db import report_static_findings_fidelity_audit as fidelity_audit

    return fidelity_audit._load_optional_db(session_stamp)


def _load_report_rows(archive_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from scripts.db import report_static_run_performance_audit as perf_audit

    return perf_audit._load_report_rows(archive_dir)


def _load_session_header(session_stamp: str) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    row: dict[str, Any] = {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:  # pragma: no cover - live DB
        return {}, [f"db_unavailable:session_header_import_failed:{type(exc).__name__}"]

    try:
        result = core_q.run_sql(
            """
            SELECT *
            FROM v_static_session_health_v2
            WHERE session_stamp = %s
            ORDER BY refreshed_at_utc DESC, static_session_id DESC
            LIMIT 1
            """,
            (session_stamp,),
            fetch="one",
            dictionary=True,
            query_name="report_static_deep_audit.session_header",
        )
        if isinstance(result, Mapping):
            row = dict(result)
    except Exception as exc:  # pragma: no cover - live DB
        warnings.append(f"db_warning:session_header_query_failed:{type(exc).__name__}")
    return row, warnings


def _load_db_package_rows(session_stamp: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    warnings: list[str] = []
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:  # pragma: no cover - live DB
        return {}, [f"db_unavailable:package_rows_import_failed:{type(exc).__name__}"]

    try:
        rows = core_q.run_sql(
            """
            SELECT
              sar.id AS static_run_id,
              a.package_name,
              COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
              NULLIF(a.profile_key, '') AS profile_key,
              UPPER(COALESCE(sar.status, '')) AS run_status,
              sar.findings_total AS persisted_findings_db,
              sar.findings_runtime_total,
              sar.findings_capped_total,
              sar.schema_version,
              sar.tool_semver,
              sar.tool_git_commit,
              CASE WHEN h.static_run_id IS NULL THEN 0 ELSE 1 END AS handoff_ready,
              COALESCE(pm.permission_rows, 0) AS permission_rows,
              COALESCE(ss.summary_rows, 0) AS string_summary_rows,
              COALESCE(samp.sample_rows, 0) AS string_sample_rows,
              COALESCE(corr.correlation_rows, 0) AS correlation_rows
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            LEFT JOIN v_static_handoff_v1 h
              ON h.static_run_id = sar.id
            LEFT JOIN (
              SELECT run_id, COUNT(*) AS permission_rows
              FROM static_permission_matrix
              GROUP BY run_id
            ) pm
              ON pm.run_id = sar.id
            LEFT JOIN (
              SELECT session_stamp, LOWER(TRIM(package_name)) AS package_name_lc, COUNT(*) AS summary_rows
              FROM static_string_summary
              GROUP BY session_stamp, LOWER(TRIM(package_name))
            ) ss
              ON BINARY ss.session_stamp = BINARY sar.session_stamp
             AND BINARY ss.package_name_lc = BINARY LOWER(TRIM(a.package_name))
            LEFT JOIN (
              SELECT static_run_id, COUNT(*) AS sample_rows
              FROM static_string_samples
              GROUP BY static_run_id
            ) samp
              ON samp.static_run_id = sar.id
            LEFT JOIN (
              SELECT static_run_id, COUNT(*) AS correlation_rows
              FROM static_correlation_results
              GROUP BY static_run_id
            ) corr
              ON corr.static_run_id = sar.id
            WHERE BINARY sar.session_stamp = BINARY %s
            ORDER BY sar.id
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
            query_name="report_static_deep_audit.package_rows",
        ) or []
    except Exception as exc:  # pragma: no cover - live DB
        warnings.append(f"db_warning:package_rows_query_failed:{type(exc).__name__}")
        return {}, warnings

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        package = _package_key(row.get("package_name"))
        if not package:
            continue
        out[package] = dict(row)
    return out, warnings


def _collect_dynamic_bridge(
    *,
    output_root: Path,
    target_static_run_ids: set[int],
    target_packages: set[str],
) -> dict[str, dict[str, Any]]:
    bridge: dict[str, dict[str, Any]] = {}
    evidence_root = output_root / "evidence" / "dynamic"
    if not evidence_root.exists():
        return bridge

    for run_dir in sorted(evidence_root.iterdir()):
        if not run_dir.is_dir():
            continue
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
        if not isinstance(plan, Mapping):
            continue
        package = _package_key(plan.get("package_name"))
        static_run_id = _safe_int(plan.get("static_run_id"), default=-1)
        if package not in target_packages and static_run_id not in target_static_run_ids:
            continue
        summary = _read_json(run_dir / "analysis" / "summary.json") or {}
        overlap = _read_json(run_dir / "analysis" / "static_dynamic_overlap.json") or {}
        timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json") or {}
        bucket = bridge.setdefault(
            package or f"run:{static_run_id}",
            {
                "linked_dynamic_run_count": 0,
                "linked_dynamic_valid_run_count": 0,
                "corroborated_dynamic_run_count": 0,
                "timeline_run_count": 0,
                "timeline_complete_run_count": 0,
                "overlap_count_total": 0,
                "overlap_ratio_sum": 0.0,
                "overlap_ratio_count": 0,
                "dynamic_run_ids": [],
            },
        )
        bucket["linked_dynamic_run_count"] += 1
        bucket["dynamic_run_ids"].append(run_dir.name)
        capture = summary.get("capture") if isinstance(summary.get("capture"), Mapping) else {}
        if bool(capture.get("pcap_valid")):
            bucket["linked_dynamic_valid_run_count"] += 1
        overlap_count = _safe_int(overlap.get("overlap_count"))
        if overlap_count > 0:
            bucket["corroborated_dynamic_run_count"] += 1
            bucket["overlap_count_total"] += overlap_count
        overlap_ratio = overlap.get("overlap_ratio_total")
        if overlap_ratio not in (None, ""):
            bucket["overlap_ratio_sum"] += _safe_float(overlap_ratio)
            bucket["overlap_ratio_count"] += 1
        if isinstance(timeline, Mapping) and bool(timeline):
            bucket["timeline_run_count"] += 1
            if bool(timeline.get("timeline_complete")):
                bucket["timeline_complete_run_count"] += 1

    for bucket in bridge.values():
        count = _safe_int(bucket.get("overlap_ratio_count"))
        bucket["average_overlap_ratio"] = (
            round(_safe_float(bucket.get("overlap_ratio_sum")) / float(count), 4) if count > 0 else None
        )
        bucket["dynamic_run_ids"] = sorted(str(value) for value in bucket.get("dynamic_run_ids") or [])
    return bridge


def _aggregate_artifact_rows(
    report_rows: Sequence[Mapping[str, Any]],
    detector_stage_rows: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    by_package: dict[str, dict[str, Any]] = {}
    detector_by_package: dict[str, Counter[str]] = defaultdict(Counter)

    for stage in detector_stage_rows:
        package = _package_key(stage.get("package_name"))
        detector_id = _norm_text_or_none(stage.get("detector_id")) or "unknown"
        if not package:
            continue
        detector_by_package[package][detector_id] += _safe_float(stage.get("duration_sec"))

    for row in report_rows:
        package = _package_key(row.get("package_name"))
        if not package:
            continue
        bucket = by_package.setdefault(
            package,
            {
                "archive_report_count": 0,
                "base_report_count": 0,
                "split_report_count": 0,
                "archive_duration_total_sec": 0.0,
                "artifact_wall_clock_total_sec": 0.0,
                "string_index_total_sec": 0.0,
                "hash_total_sec": 0.0,
                "parse_signal_events": 0,
                "resource_parse_partial_events": 0,
                "resource_reparse_candidate_events": 0,
                "finding_failure_events": 0,
                "policy_failure_events": 0,
                "execution_error_events": 0,
                "warning_stage_events": 0,
                "timing_available_reports": 0,
            },
        )
        bucket["archive_report_count"] += 1
        if bool(row.get("is_split")):
            bucket["split_report_count"] += 1
        else:
            bucket["base_report_count"] += 1
        duration = row.get("duration_seconds")
        if duration not in (None, ""):
            bucket["archive_duration_total_sec"] += _safe_float(duration)
            bucket["timing_available_reports"] += 1
        wall = row.get("artifact_total_wall_s")
        if wall not in (None, ""):
            bucket["artifact_wall_clock_total_sec"] += _safe_float(wall)
        bucket["string_index_total_sec"] += _safe_float(row.get("string_index_seconds"))
        bucket["hash_total_sec"] += _safe_float(row.get("hash_seconds"))
        bucket["parse_signal_events"] += (
            _safe_int(row.get("resource_fallback_used"))
            + _safe_int(row.get("resource_bounds_warning"))
            + _safe_int(row.get("resource_parse_partial"))
            + _safe_int(row.get("resource_reparse_candidate"))
            + _safe_int(row.get("label_parse_signal"))
        )
        bucket["resource_parse_partial_events"] += _safe_int(row.get("resource_parse_partial"))
        bucket["resource_reparse_candidate_events"] += _safe_int(row.get("resource_reparse_candidate"))
        bucket["finding_failure_events"] += _safe_int(row.get("finding_failure_count"))
        bucket["policy_failure_events"] += _safe_int(row.get("policy_failure_count"))
        bucket["execution_error_events"] += _safe_int(row.get("execution_error_count"))
        bucket["warning_stage_events"] += _safe_int(row.get("warning_stage_count"))

    for package, bucket in by_package.items():
        ranking = detector_by_package.get(package) or Counter()
        if ranking:
            detector_id, total_duration = max(ranking.items(), key=lambda item: (item[1], item[0]))
            bucket["slowest_detector_id"] = detector_id
            bucket["slowest_detector_duration_sec"] = round(total_duration, 3)
        else:
            bucket["slowest_detector_id"] = None
            bucket["slowest_detector_duration_sec"] = None
        bucket["archive_duration_total_sec"] = round(bucket["archive_duration_total_sec"], 3)
        bucket["artifact_wall_clock_total_sec"] = round(bucket["artifact_wall_clock_total_sec"], 3)
        bucket["string_index_total_sec"] = round(bucket["string_index_total_sec"], 3)
        bucket["hash_total_sec"] = round(bucket["hash_total_sec"], 3)
    return by_package


def _quality_components(row: Mapping[str, Any]) -> dict[str, Any]:
    workflow_completion_status = _norm_text(row.get("workflow_completion_status")).lower()
    db_persistence_status = _norm_text(row.get("db_persistence_status")).lower()
    final_status = _norm_text(row.get("final_status")).lower()
    runtime_findings = max(_safe_int(row.get("runtime_findings")), 0)
    persisted_findings = max(_safe_int(row.get("persisted_findings_db")), 0)
    capped_findings = max(_safe_int(row.get("capped_not_persisted")), 0)
    runtime_p0 = max(_safe_int(row.get("runtime_p0_findings")), 0)
    persisted_p0 = max(_safe_int(row.get("persisted_p0_findings_db")), 0)
    handoff_ready = bool(row.get("handoff_ready"))
    permission_rows = _safe_int(row.get("permission_rows"))
    string_summary_rows = _safe_int(row.get("string_summary_rows"))
    string_sample_rows = _safe_int(row.get("string_sample_rows"))
    correlation_rows = _safe_int(row.get("correlation_rows"))
    base_report_count = _safe_int(row.get("base_report_count"))
    archive_report_count = _safe_int(row.get("archive_report_count"))
    discovered_artifacts = max(_safe_int(row.get("discovered_artifacts")), 0)
    detector_errors = max(_safe_int(row.get("detector_errors_agg")), 0)
    detector_warnings = max(_safe_int(row.get("detector_warnings_agg")), 0)
    detector_failures = max(_safe_int(row.get("detector_failures_agg")), 0)
    timing_reports = _safe_int(row.get("timing_available_reports"))

    workflow_score = 0.0
    workflow_score += 10.0 if workflow_completion_status == "complete" else 0.0
    workflow_score += 7.0 if db_persistence_status == "ok" else 3.0 if db_persistence_status == "partial" else 0.0
    workflow_score += 5.0 if detector_errors == 0 else 0.0
    workflow_score += 3.0 if final_status == "complete" else 1.0 if final_status == "partial" else 0.0

    fidelity_score = 0.0
    if runtime_findings <= 0:
        fidelity_score += 5.0
    else:
        fidelity_score += 10.0 * min(1.0, persisted_findings / float(max(runtime_findings, 1)))
        fidelity_score += 5.0 * max(0.0, 1.0 - (capped_findings / float(max(runtime_findings, 1))))
    if runtime_p0 <= 0:
        fidelity_score += 10.0
    else:
        fidelity_score += 10.0 * min(1.0, persisted_p0 / float(max(runtime_p0, 1)))

    canonical_score = 0.0
    canonical_score += 5.0 if persisted_findings > 0 or runtime_findings > 0 else 0.0
    canonical_score += 5.0 if permission_rows > 0 else 0.0
    canonical_score += 5.0 if string_summary_rows > 0 else 0.0
    canonical_score += 5.0 if string_sample_rows > 0 or correlation_rows > 0 else 0.0

    observability_score = 0.0
    observability_score += 6.0 if base_report_count > 0 else 0.0
    if discovered_artifacts > 0:
        observability_score += 5.0 * min(1.0, archive_report_count / float(discovered_artifacts))
    observability_score += 4.0 if timing_reports > 0 else 0.0

    handoff_score = 0.0
    handoff_score += 12.0 if handoff_ready else 0.0
    handoff_score += 4.0 if _norm_text_or_none(row.get("schema_version")) else 0.0
    handoff_score += 4.0 if _norm_text_or_none(row.get("tool_semver")) else 0.0

    penalty = 0.0
    penalty += min(8.0, detector_warnings * 0.35)
    penalty += min(10.0, detector_failures * 1.25)
    penalty += 4.0 if final_status == "partial" else 0.0
    penalty += 3.0 if string_sample_rows == 0 else 0.0
    penalty += 2.5 if _safe_int(row.get("parse_signal_events")) > 0 else 0.0
    penalty += 2.5 if _safe_int(row.get("resource_parse_partial_events")) > 0 else 0.0
    penalty += 1.5 if _safe_int(row.get("resource_reparse_candidate_events")) > 0 else 0.0
    penalty += 3.0 if _performance_hotspot(row) else 0.0

    penalty_reasons: list[str] = []
    if detector_warnings > 0:
        penalty_reasons.append(f"detector_warnings={detector_warnings}")
    if detector_failures > 0:
        penalty_reasons.append(f"detector_failures={detector_failures}")
    if final_status == "partial":
        penalty_reasons.append("package_final_status_partial")
    if string_sample_rows == 0:
        penalty_reasons.append("string_sample_gap")
    if _safe_int(row.get("parse_signal_events")) > 0:
        penalty_reasons.append("parse_signal_noise")
    if _safe_int(row.get("resource_parse_partial_events")) > 0:
        penalty_reasons.append("resource_parse_partial")
    if _safe_int(row.get("resource_reparse_candidate_events")) > 0:
        penalty_reasons.append("resource_reparse_candidate")
    if _performance_hotspot(row):
        penalty_reasons.append("performance_hotspot")

    total = workflow_score + fidelity_score + canonical_score + observability_score + handoff_score - penalty
    return {
        "workflow_score": round(workflow_score, 2),
        "fidelity_score": round(fidelity_score, 2),
        "canonical_score": round(canonical_score, 2),
        "observability_score": round(observability_score, 2),
        "handoff_score": round(handoff_score, 2),
        "penalty_total": round(penalty, 2),
        "penalty_reasons": "; ".join(penalty_reasons),
        "static_evidence_quality_score": round(max(0.0, min(total, 100.0)), 2),
    }


def _quality_score(row: Mapping[str, Any]) -> float:
    return float(_quality_components(row)["static_evidence_quality_score"])


def _split_heavy(row: Mapping[str, Any]) -> bool:
    split_reports = _safe_int(row.get("split_report_count"))
    return split_reports >= 5 or split_reports >= 10


def _performance_hotspot(row: Mapping[str, Any]) -> bool:
    return (
        _safe_float(row.get("artifact_wall_clock_total_sec")) >= 60.0
        or _safe_float(row.get("string_index_total_sec")) >= 10.0
        or _safe_float(row.get("slowest_detector_duration_sec")) >= 8.0
    )


def _top_gap(row: Mapping[str, Any]) -> str:
    if not bool(row.get("handoff_ready")):
        return "needs_handoff_repair"
    if _norm_text(row.get("workflow_completion_status")).lower() != "complete":
        return "incomplete_session"
    if _norm_text(row.get("db_persistence_status")).lower() not in {"ok", "complete"}:
        return "needs_persistence_repair"
    if _safe_int(row.get("capped_not_persisted")) > 0:
        return "review_finding_caps"
    if _safe_int(row.get("linked_dynamic_run_count")) > 0 and _safe_int(row.get("linked_dynamic_valid_run_count")) == 0:
        return "recollect_valid_dynamic_evidence"
    if _safe_int(row.get("string_summary_rows")) == 0:
        return "add_static_string_surface"
    if _safe_int(row.get("linked_dynamic_run_count")) == 0:
        return "collect_dynamic_baselines"
    if (
        _safe_int(row.get("linked_dynamic_run_count")) > 0
        and _safe_int(row.get("corroborated_dynamic_run_count")) == 0
        and _safe_int(row.get("string_summary_rows")) > 0
    ):
        return "expand_static_dynamic_corroboration"
    if _performance_hotspot(row) and _split_heavy(row):
        return "reduce_split_cost"
    if _safe_int(row.get("resource_parse_partial_events")) > 0:
        return "review_partial_resource_parse"
    if _safe_int(row.get("resource_reparse_candidate_events")) > 0:
        return "review_partial_resource_parse"
    if _safe_int(row.get("parse_signal_events")) > 0:
        return "review_parse_signals"
    if _norm_text(row.get("detector_posture")).lower() not in {"", "clean"} or _norm_text(row.get("final_status")).lower() == "partial":
        return "review_detector_posture"
    return "healthy"


def _recommended_action(row: Mapping[str, Any]) -> str:
    gap = _top_gap(row)
    mapping = {
        "needs_handoff_repair": "repair_static_handoff_contract",
        "incomplete_session": "rerun_or_finalize_static_session",
        "needs_persistence_repair": "repair_static_persistence",
        "review_finding_caps": "review_detector_caps_before_paper_use",
        "recollect_valid_dynamic_evidence": "recollect_valid_dynamic_evidence",
        "add_static_string_surface": "repair_static_string_surface",
        "collect_dynamic_baselines": "collect_dynamic_baselines",
        "expand_static_dynamic_corroboration": "expand_dynamic_collection_for_corroboration",
        "reduce_split_cost": "review_base_only_or_split_fast_path",
        "review_partial_resource_parse": "review_partial_resource_parse",
        "review_parse_signals": "review_resource_parse_fallbacks",
        "review_detector_posture": "review_detector_gates_and_warnings",
        "healthy": "ready_for_paper_use",
    }
    return mapping.get(gap, "review_needed")


def _readiness_tier(row: Mapping[str, Any]) -> str:
    gap = _top_gap(row)
    if gap in {"needs_handoff_repair", "incomplete_session", "needs_persistence_repair", "add_static_string_surface"}:
        return "incomplete_or_contract_gap"
    if gap == "review_finding_caps":
        return "review_capped_findings"
    if gap == "recollect_valid_dynamic_evidence":
        return "needs_valid_dynamic_recollection"
    if gap == "collect_dynamic_baselines":
        return "ready_for_dynamic_collection"
    if gap == "expand_static_dynamic_corroboration":
        return "needs_dynamic_corroboration"
    if gap in {"reduce_split_cost", "review_parse_signals", "review_partial_resource_parse"}:
        return "optimization_review"
    if gap == "review_detector_posture":
        return "review_detector_posture"
    return "paper_ready"


def _pattern_flags(row: Mapping[str, Any]) -> dict[str, int]:
    return {
        "split_heavy_flag": int(_split_heavy(row)),
        "detector_posture_flag": int(
            _norm_text(row.get("detector_posture")).lower() not in {"", "clean"}
            or _norm_text(row.get("final_status")).lower() == "partial"
        ),
        "capped_findings_flag": int(_safe_int(row.get("capped_not_persisted")) > 0),
        "parse_signal_flag": int(_safe_int(row.get("parse_signal_events")) > 0),
        "resource_parse_partial_flag": int(_safe_int(row.get("resource_parse_partial_events")) > 0),
        "resource_reparse_candidate_flag": int(_safe_int(row.get("resource_reparse_candidate_events")) > 0),
        "handoff_gap_flag": int(not bool(row.get("handoff_ready"))),
        "dynamic_bridge_gap_flag": int(_safe_int(row.get("linked_dynamic_run_count")) == 0),
        "dynamic_validity_gap_flag": int(
            _safe_int(row.get("linked_dynamic_run_count")) > 0 and _safe_int(row.get("linked_dynamic_valid_run_count")) == 0
        ),
        "corroboration_gap_flag": int(
            _safe_int(row.get("linked_dynamic_run_count")) > 0
            and _safe_int(row.get("corroborated_dynamic_run_count")) == 0
        ),
        "performance_hotspot_flag": int(_performance_hotspot(row)),
        "string_surface_gap_flag": int(
            _safe_int(row.get("string_summary_rows")) == 0 or _safe_int(row.get("string_sample_rows")) == 0
        ),
    }


def generate_static_deep_audit(
    *,
    session_stamp: str,
    data_dir: Path,
    output_root: Path,
    output_dir: Path,
) -> dict[str, Any]:
    run_health, run_health_packages, run_health_warnings = _load_run_health(data_dir, session_stamp)
    db_state, db_notes = _load_optional_db(session_stamp)
    session_header, header_warnings = _load_session_header(session_stamp)
    db_package_rows, package_db_warnings = _load_db_package_rows(session_stamp)
    archive_dir = _reports_archive_dir(data_dir, session_stamp)
    report_rows, perf_meta = _load_report_rows(archive_dir)
    artifact_rollups = _aggregate_artifact_rows(report_rows, perf_meta.get("detector_stage_rows") or [])

    target_run_ids = {
        _safe_int(row.get("static_run_id"))
        for row in db_package_rows.values()
        if _safe_int(row.get("static_run_id")) > 0
    }
    dynamic_bridge = _collect_dynamic_bridge(
        output_root=output_root,
        target_static_run_ids={value for value in target_run_ids if value > 0},
        target_packages=set(run_health_packages) | set(db_package_rows),
    )

    package_names = sorted(set(run_health_packages) | set(db_package_rows) | set(artifact_rollups))
    run_rows: list[dict[str, Any]] = []
    bridge_rows: list[dict[str, Any]] = []
    hotspot_rows: list[dict[str, Any]] = []
    pattern_rows: list[dict[str, Any]] = []
    hidden_pattern_rows: list[dict[str, Any]] = []
    profile_summary: dict[str, dict[str, Any]] = {}
    quality_tier_counts: Counter[str] = Counter()
    readiness_tier_counts: Counter[str] = Counter()
    pattern_flag_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()

    for package in package_names:
        rh = run_health_packages.get(package, {})
        db_row = db_package_rows.get(package, {})
        artifact_row = artifact_rollups.get(package, {})
        bridge_row = dynamic_bridge.get(package, {})

        row: dict[str, Any] = {
            "package_name": package,
            "display_name": _norm_text_or_none(rh.get("display_name"))
            or _norm_text_or_none(db_row.get("display_name"))
            or package,
            "profile_key": _norm_text_or_none(db_row.get("profile_key")),
            "static_run_id": _safe_int(db_row.get("static_run_id"), default=None) if db_row else None,
            "workflow_completion_status": _norm_text_or_none(
                ((run_health.get("workflow_completion_status")) if isinstance(run_health, Mapping) else None)
            )
            or _norm_text_or_none(rh.get("workflow_completion_status"))
            or "unknown",
            "final_status": _norm_text_or_none(rh.get("final_status")) or "unknown",
            "db_persistence_status": _norm_text_or_none(rh.get("db_persistence_status")) or "unknown",
            "detector_posture": _norm_text_or_none(rh.get("detector_posture")) or "unknown",
            "finding_fidelity_status": _norm_text_or_none(rh.get("finding_fidelity_status")) or "unknown",
            "discovered_artifacts": _safe_int(rh.get("artifact_count")),
            "runtime_findings": _safe_int(rh.get("runtime_findings")),
            "persisted_findings_db": _safe_int(rh.get("persisted_findings_db"))
            or _safe_int(db_row.get("persisted_findings_db")),
            "capped_not_persisted": _safe_int(rh.get("capped_not_persisted"))
            or _safe_int(db_row.get("findings_capped_total")),
            "runtime_p0_findings": _safe_int(((rh.get("finding_persistence") or {}) if isinstance(rh.get("finding_persistence"), Mapping) else {}).get("runtime_p0_findings")),
            "persisted_p0_findings_db": _safe_int(((rh.get("finding_persistence") or {}) if isinstance(rh.get("finding_persistence"), Mapping) else {}).get("persisted_p0_findings_db")),
            "detector_warnings_agg": _safe_int(rh.get("detector_warnings_agg")),
            "detector_failures_agg": _safe_int(rh.get("detector_failures_agg")),
            "detector_errors_agg": _safe_int(rh.get("detector_errors_agg")),
            "permission_rows": _safe_int(db_row.get("permission_rows")),
            "string_summary_rows": _safe_int(db_row.get("string_summary_rows")),
            "string_sample_rows": _safe_int(db_row.get("string_sample_rows")),
            "correlation_rows": _safe_int(db_row.get("correlation_rows")),
            "handoff_ready": int(bool(db_row.get("handoff_ready"))),
            "schema_version": _norm_text_or_none(db_row.get("schema_version")),
            "tool_semver": _norm_text_or_none(db_row.get("tool_semver")),
            "tool_git_commit": _norm_text_or_none(db_row.get("tool_git_commit")),
            **artifact_row,
            **bridge_row,
        }

        quality_detail = _quality_components(row)
        quality_score = float(quality_detail["static_evidence_quality_score"])
        quality_tier = _quality_tier(quality_score)
        readiness_tier = _readiness_tier(row)
        top_gap = _top_gap(row)
        recommended_action = _recommended_action(row)
        flags = _pattern_flags(row)

        row.update(
            {
                "static_evidence_quality_score": quality_score,
                "static_evidence_quality_tier": quality_tier,
                "static_readiness_tier": readiness_tier,
                "top_gap": top_gap,
                "recommended_action": recommended_action,
                "linked_dynamic_run_count": _safe_int(bridge_row.get("linked_dynamic_run_count")),
                "linked_dynamic_valid_run_count": _safe_int(bridge_row.get("linked_dynamic_valid_run_count")),
                "corroborated_dynamic_run_count": _safe_int(bridge_row.get("corroborated_dynamic_run_count")),
                "timeline_run_count": _safe_int(bridge_row.get("timeline_run_count")),
                "timeline_complete_run_count": _safe_int(bridge_row.get("timeline_complete_run_count")),
                "average_overlap_ratio": bridge_row.get("average_overlap_ratio"),
                "dynamic_bridge_state": (
                    "no_dynamic_runs"
                    if _safe_int(bridge_row.get("linked_dynamic_run_count")) == 0
                    else "dynamic_runs_invalid"
                    if _safe_int(bridge_row.get("linked_dynamic_valid_run_count")) == 0
                    else "corroboration_gap"
                    if _safe_int(bridge_row.get("corroborated_dynamic_run_count")) == 0
                    else "corroborated"
                ),
                **quality_detail,
                **flags,
            }
        )
        row["pattern_flag_count"] = int(sum(flags.values()))

        run_rows.append(
            {
                key: row.get(key)
                for key in (
                    "package_name",
                    "display_name",
                    "profile_key",
                    "static_run_id",
                    "workflow_completion_status",
                    "final_status",
                    "db_persistence_status",
                    "detector_posture",
                    "finding_fidelity_status",
                    "runtime_findings",
                    "persisted_findings_db",
                    "capped_not_persisted",
                    "permission_rows",
                    "string_summary_rows",
                    "string_sample_rows",
                    "correlation_rows",
                    "archive_report_count",
                    "base_report_count",
                    "split_report_count",
                    "artifact_wall_clock_total_sec",
                    "string_index_total_sec",
                    "slowest_detector_id",
                    "slowest_detector_duration_sec",
                    "parse_signal_events",
                    "resource_parse_partial_events",
                    "resource_reparse_candidate_events",
                    "handoff_ready",
                    "linked_dynamic_run_count",
                    "linked_dynamic_valid_run_count",
                    "corroborated_dynamic_run_count",
                    "average_overlap_ratio",
                    "dynamic_bridge_state",
                    "workflow_score",
                    "fidelity_score",
                    "canonical_score",
                    "observability_score",
                    "handoff_score",
                    "penalty_total",
                    "penalty_reasons",
                    "static_evidence_quality_score",
                    "static_evidence_quality_tier",
                    "static_readiness_tier",
                    "top_gap",
                    "recommended_action",
                )
            }
        )

        bridge_rows.append(
            {
                "package_name": row["package_name"],
                "display_name": row["display_name"],
                "static_run_id": row["static_run_id"],
                "handoff_ready": row["handoff_ready"],
                "linked_dynamic_run_count": row["linked_dynamic_run_count"],
                "linked_dynamic_valid_run_count": row["linked_dynamic_valid_run_count"],
                "corroborated_dynamic_run_count": row["corroborated_dynamic_run_count"],
                "timeline_run_count": row["timeline_run_count"],
                "timeline_complete_run_count": row["timeline_complete_run_count"],
                "average_overlap_ratio": row["average_overlap_ratio"],
                "dynamic_bridge_state": row["dynamic_bridge_state"],
                "top_gap": top_gap,
                "recommended_action": recommended_action,
            }
        )

        if _performance_hotspot(row) or _split_heavy(row):
            hotspot_rows.append(
                {
                    "package_name": row["package_name"],
                    "display_name": row["display_name"],
                    "split_report_count": row.get("split_report_count"),
                    "archive_report_count": row.get("archive_report_count"),
                    "artifact_wall_clock_total_sec": row.get("artifact_wall_clock_total_sec"),
                    "string_index_total_sec": row.get("string_index_total_sec"),
                    "slowest_detector_id": row.get("slowest_detector_id"),
                    "slowest_detector_duration_sec": row.get("slowest_detector_duration_sec"),
                    "recommended_action": recommended_action,
                }
            )

        pattern_row = {
            "package_name": row["package_name"],
            "display_name": row["display_name"],
            "profile_key": row["profile_key"],
            "static_evidence_quality_tier": quality_tier,
            "static_readiness_tier": readiness_tier,
            "top_gap": top_gap,
            "recommended_action": recommended_action,
            **flags,
            "pattern_flag_count": row["pattern_flag_count"],
        }
        pattern_rows.append(pattern_row)

        hidden_pattern_rows.append(
            {
                "package_name": row["package_name"],
                "display_name": row["display_name"],
                "profile_key": row["profile_key"],
                "dynamic_bridge_state": row["dynamic_bridge_state"],
                "static_evidence_quality_tier": quality_tier,
                "static_readiness_tier": readiness_tier,
                "split_heavy": _split_heavy(row),
                "performance_hotspot": _performance_hotspot(row),
                "detector_posture": row["detector_posture"],
                "finding_fidelity_status": row["finding_fidelity_status"],
                "permission_rows": row["permission_rows"],
                "string_summary_rows": row["string_summary_rows"],
                "string_sample_rows": row["string_sample_rows"],
                "correlation_rows": row["correlation_rows"],
                "linked_dynamic_run_count": row["linked_dynamic_run_count"],
                "corroborated_dynamic_run_count": row["corroborated_dynamic_run_count"],
                "average_overlap_ratio": row["average_overlap_ratio"],
                "pattern_flag_count": row["pattern_flag_count"],
                "top_gap": top_gap,
                "recommended_action": recommended_action,
                "research_pattern": (
                    "high_static_surface_without_dynamic_collection"
                    if (
                        (
                            _safe_int(row["permission_rows"]) >= 60
                            or _safe_int(row["string_summary_rows"]) > 0
                            or _safe_int(row["correlation_rows"]) > 0
                        )
                        and _safe_int(row["linked_dynamic_run_count"]) == 0
                    )
                    else "static_dynamic_mismatch_candidate"
                    if _safe_int(row["linked_dynamic_run_count"]) > 0 and _safe_int(row["corroborated_dynamic_run_count"]) == 0
                    else "split_cost_outlier"
                    if _split_heavy(row) and _performance_hotspot(row)
                    else "detector_posture_review"
                    if _norm_text(row["detector_posture"]).lower() not in {"", "clean"}
                    else "none"
                ),
            }
        )

        quality_tier_counts[quality_tier] += 1
        readiness_tier_counts[readiness_tier] += 1
        action_counts[recommended_action] += 1
        for key, value in flags.items():
            if value:
                pattern_flag_counts[key.replace("_flag", "")] += 1

        profile_key = _norm_text_or_none(row.get("profile_key")) or "UNCLASSIFIED"
        profile_bucket = profile_summary.setdefault(
            profile_key,
            {
                "profile_key": profile_key,
                "package_count": 0,
                "quality_score_sum": 0.0,
                "paper_ready_count": 0,
                "handoff_ready_count": 0,
                "linked_dynamic_packages": 0,
                "capped_packages": 0,
                "split_heavy_packages": 0,
                "detector_review_packages": 0,
                "top_gap_counts": Counter(),
            },
        )
        profile_bucket["package_count"] += 1
        profile_bucket["quality_score_sum"] += quality_score
        profile_bucket["paper_ready_count"] += int(readiness_tier == "paper_ready")
        profile_bucket["handoff_ready_count"] += int(bool(row["handoff_ready"]))
        profile_bucket["linked_dynamic_packages"] += int(_safe_int(row["linked_dynamic_run_count"]) > 0)
        profile_bucket["capped_packages"] += int(_safe_int(row["capped_not_persisted"]) > 0)
        profile_bucket["split_heavy_packages"] += int(_split_heavy(row))
        profile_bucket["detector_review_packages"] += int(readiness_tier == "review_detector_posture")
        profile_bucket["top_gap_counts"][top_gap] += 1

    profile_rows: list[dict[str, Any]] = []
    for bucket in sorted(profile_summary.values(), key=lambda item: (-item["package_count"], item["profile_key"])):
        top_gap_counts = bucket["top_gap_counts"]
        top_gap = ""
        if top_gap_counts:
            top_gap = max(sorted(top_gap_counts.items()), key=lambda item: item[1])[0]
        profile_rows.append(
            {
                "profile_key": bucket["profile_key"],
                "package_count": bucket["package_count"],
                "avg_static_evidence_quality_score": round(
                    bucket["quality_score_sum"] / float(max(bucket["package_count"], 1)), 2
                ),
                "paper_ready_count": bucket["paper_ready_count"],
                "handoff_ready_count": bucket["handoff_ready_count"],
                "linked_dynamic_packages": bucket["linked_dynamic_packages"],
                "capped_packages": bucket["capped_packages"],
                "split_heavy_packages": bucket["split_heavy_packages"],
                "detector_review_packages": bucket["detector_review_packages"],
                "top_gap": top_gap,
            }
        )

    run_rows.sort(key=lambda row: (row["recommended_action"] != "ready_for_paper_use", row["package_name"]))
    bridge_rows.sort(key=lambda row: (-_safe_int(row.get("linked_dynamic_run_count")), row["package_name"]))
    hotspot_rows.sort(
        key=lambda row: (
            -_safe_float(row.get("artifact_wall_clock_total_sec")),
            -_safe_int(row.get("split_report_count")),
            row["package_name"],
        )
    )
    pattern_rows.sort(key=lambda row: (-_safe_int(row.get("pattern_flag_count")), row["package_name"]))
    hidden_pattern_rows.sort(key=lambda row: (-_safe_int(row.get("pattern_flag_count")), row["package_name"]))

    recommended_actions = {
        "generated_at": datetime.now(UTC).isoformat(),
        "session_stamp": session_stamp,
        "top_recommended_actions": dict(sorted(action_counts.items(), key=lambda item: (-item[1], item[0]))),
        "highest_attention_packages": [
            {
                "package_name": row["package_name"],
                "display_name": row["display_name"],
                "top_gap": row["top_gap"],
                "recommended_action": row["recommended_action"],
                "static_readiness_tier": row["static_readiness_tier"],
                "static_evidence_quality_tier": row["static_evidence_quality_tier"],
            }
            for row in sorted(
                run_rows,
                key=lambda item: (
                    item["recommended_action"] == "ready_for_paper_use",
                    _safe_int(item.get("pattern_flag_count")),
                    item["package_name"],
                ),
            )[:10]
        ],
    }

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "data_root": str(data_dir),
        "session_stamp": session_stamp,
        "report_type": "static_deep_audit",
        "experimental_audit": True,
        "no_db_writes": True,
        "quality_tier_definitions": {"static_evidence_quality": QUALITY_TIER_DEFINITIONS},
        "session_header": {
            "session_status": _norm_text_or_none(session_header.get("session_status")),
            "session_disposition": _norm_text_or_none(session_header.get("session_disposition")),
            "health_class": _norm_text_or_none(session_header.get("health_class")),
            "usability_class": _norm_text_or_none(session_header.get("usability_class")),
            "schema_version": _norm_text_or_none(session_header.get("schema_version")),
            "total_run_count": _safe_int(session_header.get("total_run_count")),
            "completed_run_count": _safe_int(session_header.get("completed_run_count")),
            "session_link_rows": _safe_int(session_header.get("session_link_rows")),
            "rollup_rows": _safe_int(session_header.get("rollup_rows")),
        },
        "run_health": {
            "workflow_completion_status": _norm_text_or_none(run_health.get("workflow_completion_status")),
            "final_run_status": _norm_text_or_none(run_health.get("final_run_status")),
            "detector_posture": _norm_text_or_none(run_health.get("detector_posture")),
            "finding_fidelity_status": _norm_text_or_none(run_health.get("finding_fidelity_status")),
            "db_persistence_status": _norm_text_or_none(
                ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("db_persistence_status")
            ),
        },
        "static_run_count": len(run_rows),
        "package_count": len(run_rows),
        "archive_report_count": len(report_rows),
        "archive_base_artifact_count": sum(_safe_int(row.get("base_report_count")) for row in run_rows),
        "archive_split_artifact_count": sum(_safe_int(row.get("split_report_count")) for row in run_rows),
        "runtime_findings_total": _safe_int(
            ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("findings_runtime_total")
        ),
        "persisted_db_findings_total": _safe_int(
            ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("findings_persisted_db_total")
        ),
        "capped_not_persisted_total": _safe_int(
            ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("findings_capped_not_persisted_total")
        ),
        "p0_runtime_findings_total": _safe_int(
            ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("p0_runtime_findings_total")
        ),
        "p0_persisted_db_findings_total": _safe_int(
            ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("p0_persisted_db_findings_total")
        ),
        "p0_capped_not_persisted_total": _safe_int(
            ((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("p0_capped_not_persisted_total")
        ),
        "packages_with_handoff_ready": sum(int(bool(row.get("handoff_ready"))) for row in run_rows),
        "packages_with_dynamic_bridge": sum(int(_safe_int(row.get("linked_dynamic_run_count")) > 0) for row in run_rows),
        "packages_with_corroborated_dynamic_bridge": sum(
            int(_safe_int(row.get("corroborated_dynamic_run_count")) > 0) for row in run_rows
        ),
        "packages_with_capped_findings": sum(int(_safe_int(row.get("capped_not_persisted")) > 0) for row in run_rows),
        "packages_with_parse_signals": sum(int(_safe_int(row.get("parse_signal_events")) > 0) for row in run_rows),
        "packages_with_partial_resource_parse": sum(
            int(_safe_int(row.get("resource_parse_partial_events")) > 0) for row in run_rows
        ),
        "packages_with_resource_reparse_candidates": sum(
            int(_safe_int(row.get("resource_reparse_candidate_events")) > 0) for row in run_rows
        ),
        "packages_split_heavy": sum(int(_split_heavy(row)) for row in run_rows),
        "quality_tier_counts": dict(sorted(quality_tier_counts.items())),
        "readiness_tier_counts": dict(sorted(readiness_tier_counts.items())),
        "pattern_flag_counts": dict(sorted(pattern_flag_counts.items())),
        "top_recommended_actions": dict(sorted(action_counts.items(), key=lambda item: (-item[1], item[0]))),
        "profile_group_counts": {row["profile_key"]: row["package_count"] for row in profile_rows},
        "output_files": list(OUTPUT_FILES),
        "warnings": run_health_warnings + db_notes + header_warnings + package_db_warnings + list(perf_meta.get("warnings") or []),
        "known_limitations": list(KNOWN_LIMITATIONS),
    }

    _write_csv(output_dir / "run_evidence_quality.csv", run_rows)
    _write_csv(output_dir / "app_static_readiness.csv", run_rows)
    _write_csv(output_dir / "static_bridge_readiness.csv", bridge_rows)
    _write_csv(output_dir / "split_performance_hotspots.csv", hotspot_rows)
    _write_csv(output_dir / "paper_pattern_matrix.csv", pattern_rows)
    _write_csv(output_dir / "static_hidden_pattern_candidates.csv", hidden_pattern_rows)
    _write_csv(output_dir / "profile_group_summary.csv", profile_rows)
    _write_json(output_dir / "recommended_next_actions.json", recommended_actions)
    _write_json(output_dir / "summary.json", summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    data_dir = _REPO_ROOT / "data"
    output_root = _REPO_ROOT / "output"
    session_stamp = _resolve_session_stamp(data_dir, args.session_stamp)
    if not session_stamp:
        sys.stderr.write("No static run-health sessions found.\n")
        return 1
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else output_root / "audit" / "static_deep_audit" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = generate_static_deep_audit(
        session_stamp=session_stamp,
        data_dir=data_dir,
        output_root=output_root,
        output_dir=output_dir,
    )
    sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
