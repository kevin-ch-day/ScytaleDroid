#!/usr/bin/env python3
"""Read-only audit of static-session performance and split-evidence value.

Builds a filesystem-first audit bundle over one static session archive and, when
available, corroborates with current DB rows and static persistence logs.

Examples:

  PYTHONPATH=. python scripts/db/report_static_run_performance_audit.py --session-stamp 20260613-all-full
  PYTHONPATH=. python scripts/db/report_static_run_performance_audit.py --session-stamp 20260613-all-full --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "package_runtime_summary.csv",
    "apk_artifact_runtime_summary.csv",
    "split_heavy_packages.csv",
    "detector_stage_summary.csv",
    "base_vs_split_evidence_summary.csv",
    "finding_failure_summary.csv",
    "parse_signal_summary.csv",
    "static_performance_recommendations.json",
)

PERSIST_APP_RE = re.compile(
    r"Static persistence app finalized \| .*app_index=(?P<app_index>\d+), .*package_name=(?P<package>[^,]+), .*session_stamp=(?P<session>[^,]+), .*static_run_id=(?P<static_run_id>\d+)",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session-stamp",
        default=None,
        help="Static session stamp. Defaults to the newest reports/archive/<session>/ directory.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/static_run_performance/<stamp>/.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_dt(value: Any) -> datetime | None:
    text = _norm_text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


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
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _reports_root(data_dir: Path) -> Path:
    return data_dir / "static_analysis" / "reports" / "archive"


def _latest_session_stamp(reports_root: Path) -> str | None:
    candidates = [p for p in reports_root.iterdir() if p.is_dir()] if reports_root.exists() else []
    if not candidates:
        return None
    latest = max(candidates, key=lambda p: (p.stat().st_mtime, p.name))
    return latest.name


def _resolve_session_stamp(data_dir: Path, requested: str | None) -> str | None:
    token = _norm_text_or_none(requested)
    if token:
        return token
    return _latest_session_stamp(_reports_root(data_dir))


def _report_duration_seconds(payload: Mapping[str, Any]) -> tuple[float | None, str]:
    metadata = payload.get("metadata")
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    pipeline_summary = metadata_map.get("pipeline_summary")
    summary_map = pipeline_summary if isinstance(pipeline_summary, Mapping) else {}

    total_duration = _safe_float(summary_map.get("total_duration_sec"))
    if total_duration and total_duration > 0:
        return total_duration, "pipeline_summary"

    detector_results = payload.get("detector_results")
    if isinstance(detector_results, list):
        total = 0.0
        seen = False
        for row in detector_results:
            if not isinstance(row, Mapping):
                continue
            duration = _safe_float(row.get("duration_sec"))
            if duration is None:
                continue
            seen = True
            total += duration
        if seen:
            return total, "detector_results_sum"

    return None, "missing"


def _serialise_findings(payload: Mapping[str, Any]) -> tuple[set[str], Counter[str]]:
    ids: set[str] = set()
    titles: Counter[str] = Counter()
    for finding in payload.get("findings") or []:
        if not isinstance(finding, Mapping):
            continue
        finding_id = _norm_text(finding.get("finding_id"))
        if finding_id:
            ids.add(finding_id)
        title = _norm_text(finding.get("title"))
        if title:
            titles[title] += 1
    return ids, titles


def _has_positive_metric(mapping: Mapping[str, Any], keys: Sequence[str]) -> bool:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return True
    return False


def _flatten_split_evidence_flags(detector_metrics: Mapping[str, Any]) -> dict[str, int]:
    ipc = detector_metrics.get("ipc_components")
    ipc_map = ipc if isinstance(ipc, Mapping) else {}
    perm = detector_metrics.get("permissions_profile")
    perm_map = perm if isinstance(perm, Mapping) else {}
    secrets = detector_metrics.get("secrets_credentials")
    secrets_map = secrets if isinstance(secrets, Mapping) else {}
    dfir = detector_metrics.get("dfir_hints")
    dfir_map = dfir if isinstance(dfir, Mapping) else {}
    network = detector_metrics.get("network_surface")
    network_map = network if isinstance(network, Mapping) else {}
    return {
        "component_metric_present": int(
            _has_positive_metric(
                ipc_map,
                (
                    "components_total",
                    "components_exported",
                    "exported_without_permission",
                    "providers",
                ),
            )
        ),
        "permission_metric_present": int(
            _has_positive_metric(
                perm_map,
                ("total_declared", "dangerous_total", "custom_total"),
            )
        ),
        "provider_metric_present": int(_has_positive_metric(ipc_map, ("providers",))),
        "string_or_secret_metric_present": int(
            _has_positive_metric(secrets_map, ("matched_strings", "filtered_strings"))
            or _has_positive_metric(dfir_map, ("path_hint_count", "permission_hint_count"))
        ),
        "network_metric_present": int(
            bool(network_map.get("surface")) or bool(network_map.get("NSC"))
        ),
    }


def _artifact_parse_signal_flags(metadata_map: Mapping[str, Any]) -> dict[str, int]:
    fallback = metadata_map.get("resource_fallback")
    fallback_used = 1 if isinstance(fallback, Mapping) and bool(fallback.get("fallback_used")) else 0
    bounds = metadata_map.get("resource_bounds_warnings")
    bounds_used = 1 if isinstance(bounds, list) and bool(bounds) else 0
    label_fallback = _norm_text(metadata_map.get("label_fallback")).lower()
    label_signal = 1 if label_fallback in {"aapt2", "aapt2-localized"} or bool(metadata_map.get("parse_error_resources")) else 0
    parser = metadata_map.get("parser_provenance")
    parser_map = parser if isinstance(parser, Mapping) else {}
    resource_parse_partial = 1 if bool(
        parser_map.get("resource_parse_partial", metadata_map.get("resource_parse_partial"))
    ) else 0
    resource_reparse_candidate = 1 if bool(
        parser_map.get("resource_reparse_candidate", metadata_map.get("resource_reparse_candidate"))
    ) else 0
    return {
        "resource_fallback_used": fallback_used,
        "resource_bounds_warning": bounds_used,
        "resource_parse_partial": resource_parse_partial,
        "resource_reparse_candidate": resource_reparse_candidate,
        "label_parse_signal": label_signal,
        "parse_signal_events_est": (
            fallback_used
            + bounds_used
            + resource_parse_partial
            + resource_reparse_candidate
            + label_signal
        ),
    }


def _infer_harvest_session(report_rows: Sequence[Mapping[str, Any]]) -> str | None:
    counter: Counter[str] = Counter()
    for row in report_rows:
        receipt_path = _norm_text_or_none(row.get("receipt_path"))
        if receipt_path and "receipts/harvest/" in receipt_path:
            parts = Path(receipt_path).parts
            if "harvest" in parts:
                idx = parts.index("harvest")
                if idx + 1 < len(parts):
                    counter[parts[idx + 1]] += 1
        manifest_path = _norm_text_or_none(row.get("harvest_manifest_path"))
        if manifest_path and "/runs/" in manifest_path.replace("\\", "/"):
            parts = Path(manifest_path).parts
            if "runs" in parts:
                idx = parts.index("runs")
                if idx + 1 < len(parts):
                    counter[parts[idx + 1]] += 1
    if not counter:
        return None
    return counter.most_common(1)[0][0]


def _load_harvest_expectations(data_dir: Path, session_label: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "session_label": session_label,
        "clean_packages": {},
        "blocked_count": 0,
        "clean_package_count": 0,
        "clean_artifact_count": 0,
        "receipt_count": 0,
    }
    if not session_label:
        return out
    receipts_dir = data_dir / "receipts" / "harvest" / session_label
    if not receipts_dir.exists():
        return out
    clean_packages: dict[str, dict[str, Any]] = {}
    blocked = 0
    for path in sorted(receipts_dir.glob("*.json")):
        payload = _read_json(path)
        if not isinstance(payload, Mapping):
            continue
        out["receipt_count"] += 1
        package_block = payload.get("package")
        package_map = package_block if isinstance(package_block, Mapping) else {}
        inventory_block = payload.get("inventory")
        inventory_map = inventory_block if isinstance(inventory_block, Mapping) else {}
        status_block = payload.get("status")
        status_map = status_block if isinstance(status_block, Mapping) else {}
        package_name = _norm_text(package_map.get("package_name"))
        if not package_name:
            continue
        capture_status = _norm_text(status_map.get("capture_status")).lower()
        apk_paths = [
            _norm_text(item)
            for item in inventory_map.get("apk_paths") or []
            if _norm_text(item)
        ]
        row = {
            "package_name": package_name,
            "display_name": _norm_text_or_none(package_map.get("app_label")),
            "expected_artifact_count": len(apk_paths),
            "expected_split_artifact_count": max(0, len(apk_paths) - 1),
            "expected_base_artifact_count": 1 if apk_paths else 0,
            "snapshot_id": _safe_int(package_map.get("snapshot_id")),
            "version_code": _norm_text_or_none(package_map.get("version_code")),
            "version_name": _norm_text_or_none(package_map.get("version_name")),
            "primary_path": _norm_text_or_none(inventory_map.get("primary_path")),
        }
        if capture_status == "clean":
            clean_packages[package_name] = row
        else:
            blocked += 1
    out["clean_packages"] = clean_packages
    out["blocked_count"] = blocked
    out["clean_package_count"] = len(clean_packages)
    out["clean_artifact_count"] = int(
        sum(int(row["expected_artifact_count"]) for row in clean_packages.values())
    )
    return out


def _table_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (name,),
        fetch="one",
        dictionary=True,
        query_name="report_static_run_performance.table_exists",
    )
    return bool(row and int(row.get("c") or 0))


def _table_columns(core_q: Any, name: str) -> set[str]:
    rows = core_q.run_sql(
        """
        SELECT COLUMN_NAME
        FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (name,),
        fetch="all",
        dictionary=True,
        query_name="report_static_run_performance.table_columns",
    ) or []
    return {str(row.get("COLUMN_NAME") or "") for row in rows if str(row.get("COLUMN_NAME") or "")}


def _run_fk_column(core_q: Any, table_name: str) -> str | None:
    columns = _table_columns(core_q, table_name)
    if "run_id" in columns:
        return "run_id"
    if "static_run_id" in columns:
        return "static_run_id"
    return None


def _init_optional_db(session_stamp: str) -> tuple[dict[str, Any], list[str]]:
    notes: list[str] = []
    counts: dict[str, Any] = {
        "db_name": None,
        "static_run_rows": 0,
        "completed_run_rows": 0,
        "started_run_rows": 0,
        "failed_run_rows": 0,
        "status_breakdown": {},
        "finding_rows": 0,
        "permission_matrix_rows": 0,
        "string_summary_rows": 0,
        "string_sample_rows": 0,
        "session_rollup_rows": 0,
    }
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:  # noqa: BLE001 - diagnostic script
        notes.append(f"db_unavailable:import_failed:{type(exc).__name__}")
        return counts, notes

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        notes.append("db_unavailable:engine_disabled")
        return counts, notes

    try:
        db_row = core_q.run_sql(
            "SELECT DATABASE() AS dbname",
            fetch="one",
            dictionary=True,
            query_name="report_static_run_performance.db_name",
        )
        counts["db_name"] = _norm_text_or_none((db_row or {}).get("dbname"))
    except Exception as exc:  # noqa: BLE001
        notes.append(f"db_unavailable:connect_failed:{type(exc).__name__}")
        return counts, notes

    if not _table_exists(core_q, "static_analysis_runs"):
        notes.append("db_unavailable:static_analysis_runs_missing")
        return counts, notes

    status_rows = core_q.run_sql(
        """
        SELECT UPPER(COALESCE(status, 'UNKNOWN')) AS status, COUNT(*) AS c
        FROM static_analysis_runs
        WHERE session_stamp = %s
        GROUP BY UPPER(COALESCE(status, 'UNKNOWN'))
        """,
        (session_stamp,),
        fetch="all",
        dictionary=True,
        query_name="report_static_run_performance.status_breakdown",
    ) or []
    status_breakdown = {str(row.get("status") or "UNKNOWN"): int(row.get("c") or 0) for row in status_rows}
    counts["status_breakdown"] = status_breakdown
    counts["static_run_rows"] = int(sum(status_breakdown.values()))
    counts["completed_run_rows"] = int(status_breakdown.get("COMPLETED", 0))
    counts["started_run_rows"] = int(status_breakdown.get("STARTED", 0))
    counts["failed_run_rows"] = int(status_breakdown.get("FAILED", 0))

    def _scalar(sql: str, query_name: str) -> int:
        row = core_q.run_sql(
            sql,
            (session_stamp,),
            fetch="one",
            dictionary=True,
            query_name=query_name,
        )
        return int((row or {}).get("c") or 0)

    finding_fk = _run_fk_column(core_q, "static_analysis_findings")
    if finding_fk:
        counts["finding_rows"] = _scalar(
            f"""
            SELECT COUNT(*) AS c
            FROM static_analysis_findings saf
            JOIN static_analysis_runs sar ON sar.id = saf.{finding_fk}
            WHERE sar.session_stamp = %s
            """,
            "report_static_run_performance.finding_rows",
        )
    else:
        notes.append("db_note:static_analysis_findings_missing_run_fk")

    if _table_exists(core_q, "static_permission_matrix"):
        matrix_fk = _run_fk_column(core_q, "static_permission_matrix")
        if matrix_fk:
            counts["permission_matrix_rows"] = _scalar(
                f"""
                SELECT COUNT(*) AS c
                FROM static_permission_matrix spm
                JOIN static_analysis_runs sar ON sar.id = spm.{matrix_fk}
                WHERE sar.session_stamp = %s
                """,
                "report_static_run_performance.permission_matrix_rows",
            )
        else:
            notes.append("db_note:static_permission_matrix_missing_run_fk")

    if _table_exists(core_q, "static_string_summary"):
        string_summary_fk = _run_fk_column(core_q, "static_string_summary")
        if string_summary_fk:
            counts["string_summary_rows"] = _scalar(
                f"""
                SELECT COUNT(*) AS c
                FROM static_string_summary sss
                JOIN static_analysis_runs sar ON sar.id = sss.{string_summary_fk}
                WHERE sar.session_stamp = %s
                """,
                "report_static_run_performance.string_summary_rows",
            )
        else:
            counts["string_summary_rows"] = _scalar(
                """
                SELECT COUNT(*) AS c
                FROM static_string_summary
                WHERE session_stamp = %s
                """,
                "report_static_run_performance.string_summary_rows_session",
            )
            notes.append("db_note:static_string_summary_used_session_stamp")

    if _table_exists(core_q, "static_string_samples"):
        string_sample_fk = _run_fk_column(core_q, "static_string_samples")
        if string_sample_fk:
            counts["string_sample_rows"] = _scalar(
                f"""
                SELECT COUNT(*) AS c
                FROM static_string_samples sss
                JOIN static_analysis_runs sar ON sar.id = sss.{string_sample_fk}
                WHERE sar.session_stamp = %s
                """,
                "report_static_run_performance.string_sample_rows",
            )
        else:
            notes.append("db_note:static_string_samples_missing_run_fk")
    counts["session_rollup_rows"] = _scalar(
        """
        SELECT COUNT(*) AS c
        FROM static_session_rollups
        WHERE session_stamp = %s
        """,
        "report_static_run_performance.session_rollup_rows",
    ) if _table_exists(core_q, "static_session_rollups") else 0
    return counts, notes


def _load_persistence_log_summary(session_stamp: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "persisted_package_count": 0,
        "persisted_packages": [],
        "max_app_index": 0,
        "last_logged_at": None,
    }
    log_path = _REPO_ROOT / "logs" / "static_analysis.log"
    if not log_path.exists():
        return out
    packages: set[str] = set()
    max_app_index = 0
    last_dt: datetime | None = None
    try:
        for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = PERSIST_APP_RE.search(line)
            if not match:
                continue
            if match.group("session") != session_stamp:
                continue
            packages.add(match.group("package"))
            max_app_index = max(max_app_index, int(match.group("app_index")))
            ts_match = re.match(r"\[(?P<ts>[^\]]+)\]", line)
            if ts_match:
                try:
                    last_dt = datetime.strptime(ts_match.group("ts"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
                except ValueError:
                    pass
    except OSError:
        return out
    out["persisted_package_count"] = len(packages)
    out["persisted_packages"] = sorted(packages)[:25]
    out["max_app_index"] = max_app_index
    out["last_logged_at"] = last_dt.isoformat().replace("+00:00", "Z") if last_dt else None
    return out


def _load_report_rows(archive_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    report_rows: list[dict[str, Any]] = []
    detector_stage_rows: list[dict[str, Any]] = []
    parse_rows: list[dict[str, Any]] = []
    finding_failure_rows: list[dict[str, Any]] = []
    warnings: list[str] = []

    for report_path in sorted(archive_dir.glob("*.json")):
        payload = _read_json(report_path)
        if not isinstance(payload, Mapping):
            warnings.append(f"report_parse_failed:{report_path.name}")
            continue

        metadata = payload.get("metadata")
        metadata_map = metadata if isinstance(metadata, Mapping) else {}
        pipeline_summary = metadata_map.get("pipeline_summary")
        summary_map = pipeline_summary if isinstance(pipeline_summary, Mapping) else {}
        detector_metrics = payload.get("detector_metrics")
        detector_metrics_map = detector_metrics if isinstance(detector_metrics, Mapping) else {}
        package_name = _norm_text(metadata_map.get("package_name"))
        if not package_name:
            package_name = _norm_text(metadata_map.get("normalized_package_name"))
        if not package_name:
            package_name = _norm_text(metadata_map.get("manifest_package_name"))
        if not package_name:
            warnings.append(f"missing_package_name:{report_path.name}")
            continue

        report_duration, duration_source = _report_duration_seconds(payload)
        generated_at = _parse_dt(payload.get("generated_at"))
        finding_ids, finding_titles = _serialise_findings(payload)
        parse_flags = _artifact_parse_signal_flags(metadata_map)
        split_flags = _flatten_split_evidence_flags(detector_metrics_map)
        correlation_runtime = (
            metadata_map.get("correlation_runtime_stats")
            if isinstance(metadata_map.get("correlation_runtime_stats"), Mapping)
            else {}
        )
        is_split = bool(metadata_map.get("is_split_member"))
        artifact_name = _norm_text_or_none(metadata_map.get("artifact")) or "base"
        status_counts = summary_map.get("status_counts")
        status_counts_map = status_counts if isinstance(status_counts, Mapping) else {}

        artifact_row = {
            "report_sha256": report_path.stem,
            "package_name": package_name,
            "display_name": _norm_text_or_none(metadata_map.get("app_label")),
            "artifact_name": artifact_name,
            "artifact_kind": _norm_text_or_none(metadata_map.get("artifact_kind")) or "apk",
            "is_split": int(is_split),
            "base_apk_sha256": _norm_text_or_none(metadata_map.get("base_apk_sha256")),
            "apk_set_id": _safe_int(metadata_map.get("apk_set_id")),
            "generated_at": generated_at.isoformat().replace("+00:00", "Z") if generated_at else None,
            "duration_seconds": round(report_duration, 3) if isinstance(report_duration, float) else None,
            "duration_source": duration_source,
            "artifact_total_wall_s": round(_safe_float(metadata_map.get("artifact_total_wall_s")) or 0.0, 6)
            if _safe_float(metadata_map.get("artifact_total_wall_s")) is not None
            else None,
            "hash_seconds": round(_safe_float(metadata_map.get("hash_seconds")) or 0.0, 6)
            if _safe_float(metadata_map.get("hash_seconds")) is not None
            else None,
            "string_index_seconds": round(_safe_float(metadata_map.get("string_index_seconds")) or 0.0, 6)
            if _safe_float(metadata_map.get("string_index_seconds")) is not None
            else None,
            "hash_source": _norm_text_or_none(metadata_map.get("hash_source")),
            "hash_recomputed": int(bool(metadata_map.get("hash_recomputed"))),
            "correlation_cache_hits": int(
                sum(
                    int(value or 0)
                    for key, value in correlation_runtime.items()
                    if str(key).endswith("_cache_hits")
                )
            ),
            "correlation_cache_misses": int(
                sum(
                    int(value or 0)
                    for key, value in correlation_runtime.items()
                    if str(key).endswith("_cache_misses")
                )
            ),
            "total_findings": int(summary_map.get("total_findings", 0) or 0),
            "warning_stage_count": int(status_counts_map.get("WARN", 0) or 0),
            "policy_failure_count": int(summary_map.get("policy_fail_count", 0) or 0),
            "finding_failure_count": int(summary_map.get("finding_fail_count", 0) or 0),
            "execution_error_count": int(summary_map.get("error_count", 0) or 0),
            "skipped_stage_count": int(summary_map.get("detector_skipped", 0) or 0),
            "detector_total": int(summary_map.get("detector_total", 0) or 0),
            "detector_executed": int(summary_map.get("detector_executed", 0) or 0),
            "finding_ids_count": len(finding_ids),
            "finding_titles_count": int(sum(finding_titles.values())),
            "receipt_path": _norm_text_or_none(metadata_map.get("receipt_path")),
            "harvest_manifest_path": _norm_text_or_none(metadata_map.get("harvest_manifest_path")),
            "research_usable": bool(metadata_map.get("research_usable")),
            **parse_flags,
            **split_flags,
        }
        report_rows.append(artifact_row)
        parse_rows.append(
            {
                "package_name": package_name,
                "display_name": artifact_row["display_name"],
                "artifact_name": artifact_name,
                "is_split": int(is_split),
                **parse_flags,
            }
        )

        for detector in payload.get("detector_results") or []:
            if not isinstance(detector, Mapping):
                continue
            detector_id = _norm_text_or_none(detector.get("detector_id")) or _norm_text_or_none(detector.get("section_key")) or "unknown"
            status = _norm_text_or_none(detector.get("status")) or "UNKNOWN"
            duration = _safe_float(detector.get("duration_sec")) or 0.0
            metrics = detector.get("metrics")
            metrics_map = metrics if isinstance(metrics, Mapping) else {}
            detector_stage_rows.append(
                {
                    "package_name": package_name,
                    "display_name": artifact_row["display_name"],
                    "artifact_name": artifact_name,
                    "is_split": int(is_split),
                    "detector_id": detector_id,
                    "status": status,
                    "duration_sec": duration,
                    "policy_gate": int(bool(metrics_map.get("policy_gate"))),
                    "finding_count": len(detector.get("findings") or []),
                }
            )

        for failure_kind, key in (("finding", "finding_fail_detectors"), ("policy", "policy_fail_detectors"), ("execution", "error_detectors")):
            for row in summary_map.get(key) or []:
                if not isinstance(row, Mapping):
                    continue
                finding_failure_rows.append(
                    {
                        "package_name": package_name,
                        "display_name": artifact_row["display_name"],
                        "artifact_name": artifact_name,
                        "is_split": int(is_split),
                        "failure_kind": failure_kind,
                        "detector_id": _norm_text_or_none(row.get("detector")) or _norm_text_or_none(row.get("section")) or "unknown",
                        "reason": _norm_text_or_none(row.get("reason")),
                    }
                )

        artifact_row["_finding_ids"] = finding_ids
        artifact_row["_finding_titles"] = finding_titles

    return report_rows, {
        "detector_stage_rows": detector_stage_rows,
        "parse_rows": parse_rows,
        "finding_failure_rows": finding_failure_rows,
        "warnings": warnings,
    }


def _aggregate_detector_stage_summary(stage_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    detector_rollup: dict[str, dict[str, Any]] = {}
    for row in stage_rows:
        detector_id = _norm_text_or_none(row.get("detector_id")) or "unknown"
        bucket = detector_rollup.setdefault(
            detector_id,
            {
                "detector_id": detector_id,
                "stage_runs": 0,
                "base_artifact_runs": 0,
                "split_artifact_runs": 0,
                "total_duration_sec": 0.0,
                "base_duration_sec": 0.0,
                "split_duration_sec": 0.0,
                "ok_count": 0,
                "warn_count": 0,
                "fail_count": 0,
                "error_count": 0,
                "skipped_count": 0,
                "policy_fail_stage_count": 0,
                "finding_fail_stage_count": 0,
            },
        )
        bucket["stage_runs"] += 1
        duration = float(row.get("duration_sec") or 0.0)
        bucket["total_duration_sec"] += duration
        if bool(row.get("is_split")):
            bucket["split_artifact_runs"] += 1
            bucket["split_duration_sec"] += duration
        else:
            bucket["base_artifact_runs"] += 1
            bucket["base_duration_sec"] += duration
        status = _norm_text(row.get("status")).upper()
        if status == "OK":
            bucket["ok_count"] += 1
        elif status == "WARN":
            bucket["warn_count"] += 1
        elif status == "FAIL":
            bucket["fail_count"] += 1
            if bool(row.get("policy_gate")):
                bucket["policy_fail_stage_count"] += 1
            else:
                bucket["finding_fail_stage_count"] += 1
        elif status == "ERROR":
            bucket["error_count"] += 1
        elif status == "SKIPPED":
            bucket["skipped_count"] += 1
    rows: list[dict[str, Any]] = []
    for row in detector_rollup.values():
        runs = int(row["stage_runs"] or 0)
        rows.append(
            {
                **row,
                "total_duration_sec": round(float(row["total_duration_sec"]), 3),
                "base_duration_sec": round(float(row["base_duration_sec"]), 3),
                "split_duration_sec": round(float(row["split_duration_sec"]), 3),
                "avg_duration_sec": round(float(row["total_duration_sec"]) / runs, 3) if runs else None,
                "avg_base_duration_sec": round(float(row["base_duration_sec"]) / int(row["base_artifact_runs"]), 3)
                if int(row["base_artifact_runs"] or 0)
                else None,
                "avg_split_duration_sec": round(float(row["split_duration_sec"]) / int(row["split_artifact_runs"]), 3)
                if int(row["split_artifact_runs"] or 0)
                else None,
            }
        )
    return sorted(rows, key=lambda item: (-float(item["total_duration_sec"]), item["detector_id"]))


def _aggregate_failure_summary(failure_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rollup: dict[tuple[str, str], dict[str, Any]] = {}
    for row in failure_rows:
        key = (_norm_text_or_none(row.get("package_name")) or "unknown", _norm_text_or_none(row.get("detector_id")) or "unknown")
        bucket = rollup.setdefault(
            key,
            {
                "package_name": key[0],
                "display_name": row.get("display_name"),
                "detector_id": key[1],
                "finding_failure_events": 0,
                "policy_failure_events": 0,
                "execution_error_events": 0,
                "base_artifact_events": 0,
                "split_artifact_events": 0,
                "reasons": Counter(),
            },
        )
        kind = _norm_text(row.get("failure_kind"))
        if kind == "finding":
            bucket["finding_failure_events"] += 1
        elif kind == "policy":
            bucket["policy_failure_events"] += 1
        elif kind == "execution":
            bucket["execution_error_events"] += 1
        if bool(row.get("is_split")):
            bucket["split_artifact_events"] += 1
        else:
            bucket["base_artifact_events"] += 1
        reason = _norm_text_or_none(row.get("reason"))
        if reason:
            bucket["reasons"][reason] += 1
    out: list[dict[str, Any]] = []
    for bucket in rollup.values():
        reasons = "; ".join(f"{reason} ({count})" for reason, count in bucket["reasons"].most_common(5))
        out.append(
            {
                "package_name": bucket["package_name"],
                "display_name": bucket["display_name"],
                "detector_id": bucket["detector_id"],
                "finding_failure_events": bucket["finding_failure_events"],
                "policy_failure_events": bucket["policy_failure_events"],
                "execution_error_events": bucket["execution_error_events"],
                "base_artifact_events": bucket["base_artifact_events"],
                "split_artifact_events": bucket["split_artifact_events"],
                "reasons": reasons or None,
            }
        )
    return sorted(
        out,
        key=lambda item: (
            -int(item["finding_failure_events"]),
            -int(item["policy_failure_events"]),
            -int(item["execution_error_events"]),
            item["package_name"],
            item["detector_id"],
        ),
    )


def _aggregate_package_rows(
    report_rows: Sequence[Mapping[str, Any]],
    harvest_expectations: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    per_package: dict[str, dict[str, Any]] = {}
    clean_packages = harvest_expectations.get("clean_packages")
    clean_package_map = clean_packages if isinstance(clean_packages, Mapping) else {}
    for row in report_rows:
        package_name = _norm_text_or_none(row.get("package_name")) or "unknown"
        bucket = per_package.setdefault(
            package_name,
            {
                "package_name": package_name,
                "display_name": row.get("display_name"),
                "archive_artifacts": 0,
                "base_artifacts": 0,
                "split_artifacts": 0,
                "archive_first_generated_at": None,
                "archive_last_generated_at": None,
                "detector_duration_sec_sum": 0.0,
                "artifact_total_wall_s_sum": 0.0,
                "hash_seconds_sum": 0.0,
                "string_index_seconds_sum": 0.0,
                "total_findings": 0,
                "warning_stage_count": 0,
                "policy_failure_count": 0,
                "finding_failure_count": 0,
                "execution_error_count": 0,
                "parse_signal_events_est": 0,
                "resource_fallback_used_artifacts": 0,
                "resource_bounds_warning_artifacts": 0,
                "resource_parse_partial_artifacts": 0,
                "resource_reparse_candidate_artifacts": 0,
                "label_parse_signal_artifacts": 0,
                "timed_artifacts": 0,
                "wall_timed_artifacts": 0,
                "base_finding_ids": set(),
                "split_finding_ids": set(),
                "base_titles": Counter(),
                "split_titles": Counter(),
                "split_artifacts_with_findings": 0,
                "split_component_metric_artifacts": 0,
                "split_permission_metric_artifacts": 0,
                "split_provider_metric_artifacts": 0,
                "split_string_or_secret_metric_artifacts": 0,
                "split_network_metric_artifacts": 0,
                "correlation_cache_hits": 0,
                "correlation_cache_misses": 0,
            },
        )
        bucket["archive_artifacts"] += 1
        if bool(row.get("is_split")):
            bucket["split_artifacts"] += 1
            if int(row.get("total_findings") or 0) > 0:
                bucket["split_artifacts_with_findings"] += 1
            bucket["split_component_metric_artifacts"] += int(row.get("component_metric_present") or 0)
            bucket["split_permission_metric_artifacts"] += int(row.get("permission_metric_present") or 0)
            bucket["split_provider_metric_artifacts"] += int(row.get("provider_metric_present") or 0)
            bucket["split_string_or_secret_metric_artifacts"] += int(row.get("string_or_secret_metric_present") or 0)
            bucket["split_network_metric_artifacts"] += int(row.get("network_metric_present") or 0)
            bucket["split_finding_ids"].update(set(row.get("_finding_ids") or set()))
            bucket["split_titles"].update(row.get("_finding_titles") or Counter())
        else:
            bucket["base_artifacts"] += 1
            bucket["base_finding_ids"].update(set(row.get("_finding_ids") or set()))
            bucket["base_titles"].update(row.get("_finding_titles") or Counter())
        generated_at = _parse_dt(row.get("generated_at"))
        if generated_at is not None:
            first_dt = _parse_dt(bucket.get("archive_first_generated_at"))
            last_dt = _parse_dt(bucket.get("archive_last_generated_at"))
            if first_dt is None or generated_at < first_dt:
                bucket["archive_first_generated_at"] = generated_at.isoformat().replace("+00:00", "Z")
            if last_dt is None or generated_at > last_dt:
                bucket["archive_last_generated_at"] = generated_at.isoformat().replace("+00:00", "Z")
        duration = _safe_float(row.get("duration_seconds"))
        if duration is not None:
            bucket["detector_duration_sec_sum"] += duration
            bucket["timed_artifacts"] += 1
        artifact_wall = _safe_float(row.get("artifact_total_wall_s"))
        if artifact_wall is not None:
            bucket["artifact_total_wall_s_sum"] += artifact_wall
            bucket["wall_timed_artifacts"] += 1
        hash_seconds = _safe_float(row.get("hash_seconds"))
        if hash_seconds is not None:
            bucket["hash_seconds_sum"] += hash_seconds
        string_index_seconds = _safe_float(row.get("string_index_seconds"))
        if string_index_seconds is not None:
            bucket["string_index_seconds_sum"] += string_index_seconds
        bucket["total_findings"] += int(row.get("total_findings") or 0)
        bucket["warning_stage_count"] += int(row.get("warning_stage_count") or 0)
        bucket["policy_failure_count"] += int(row.get("policy_failure_count") or 0)
        bucket["finding_failure_count"] += int(row.get("finding_failure_count") or 0)
        bucket["execution_error_count"] += int(row.get("execution_error_count") or 0)
        bucket["parse_signal_events_est"] += int(row.get("parse_signal_events_est") or 0)
        bucket["resource_fallback_used_artifacts"] += int(row.get("resource_fallback_used") or 0)
        bucket["resource_bounds_warning_artifacts"] += int(row.get("resource_bounds_warning") or 0)
        bucket["resource_parse_partial_artifacts"] += int(row.get("resource_parse_partial") or 0)
        bucket["resource_reparse_candidate_artifacts"] += int(row.get("resource_reparse_candidate") or 0)
        bucket["label_parse_signal_artifacts"] += int(row.get("label_parse_signal") or 0)
        bucket["correlation_cache_hits"] += int(row.get("correlation_cache_hits") or 0)
        bucket["correlation_cache_misses"] += int(row.get("correlation_cache_misses") or 0)

    package_rows: list[dict[str, Any]] = []
    split_rows: list[dict[str, Any]] = []
    parse_rows: list[dict[str, Any]] = []
    total_artifacts = max(1, len(report_rows))
    total_split_artifacts = max(1, sum(1 for row in report_rows if bool(row.get("is_split"))))
    for package_name, bucket in per_package.items():
        expected = clean_package_map.get(package_name)
        expected_artifacts = _safe_int((expected or {}).get("expected_artifact_count"))
        expected_split_artifacts = _safe_int((expected or {}).get("expected_split_artifact_count"))
        expected_base_artifacts = _safe_int((expected or {}).get("expected_base_artifact_count"))
        base_finding_ids = set(bucket["base_finding_ids"])
        split_finding_ids = set(bucket["split_finding_ids"])
        base_titles = Counter(bucket["base_titles"])
        split_titles = Counter(bucket["split_titles"])
        split_only_ids = split_finding_ids - base_finding_ids
        shared_ids = split_finding_ids & base_finding_ids
        base_only_ids = base_finding_ids - split_finding_ids
        shared_titles = set(base_titles.keys()) & set(split_titles.keys())
        split_only_titles = set(split_titles.keys()) - set(base_titles.keys())
        row = {
            "package_name": package_name,
            "display_name": bucket["display_name"],
            "expected_artifacts": expected_artifacts,
            "expected_base_artifacts": expected_base_artifacts,
            "expected_split_artifacts": expected_split_artifacts,
            "archive_artifacts": bucket["archive_artifacts"],
            "base_artifacts": bucket["base_artifacts"],
            "split_artifacts": bucket["split_artifacts"],
            "complete_in_archive": int(
                expected_artifacts is not None and int(bucket["archive_artifacts"]) >= int(expected_artifacts)
            ),
            "artifact_count_delta": (
                int(bucket["archive_artifacts"]) - int(expected_artifacts)
                if expected_artifacts is not None
                else None
            ),
            "artifact_share_pct": round(100.0 * int(bucket["archive_artifacts"]) / total_artifacts, 2),
            "split_share_of_session_pct": round(100.0 * int(bucket["split_artifacts"]) / total_split_artifacts, 2)
            if total_split_artifacts
            else 0.0,
            "detector_duration_sec_sum": round(float(bucket["detector_duration_sec_sum"]), 3),
            "avg_artifact_duration_sec": round(float(bucket["detector_duration_sec_sum"]) / int(bucket["timed_artifacts"]), 3)
            if int(bucket["timed_artifacts"] or 0)
            else None,
            "artifact_total_wall_s_sum": round(float(bucket["artifact_total_wall_s_sum"]), 3),
            "avg_artifact_wall_s": round(float(bucket["artifact_total_wall_s_sum"]) / int(bucket["wall_timed_artifacts"]), 3)
            if int(bucket["wall_timed_artifacts"] or 0)
            else None,
            "hash_seconds_sum": round(float(bucket["hash_seconds_sum"]), 3),
            "string_index_seconds_sum": round(float(bucket["string_index_seconds_sum"]), 3),
            "total_findings": bucket["total_findings"],
            "warning_stage_count": bucket["warning_stage_count"],
            "policy_failure_count": bucket["policy_failure_count"],
            "finding_failure_count": bucket["finding_failure_count"],
            "execution_error_count": bucket["execution_error_count"],
            "parse_signal_events_est": bucket["parse_signal_events_est"],
            "archive_first_generated_at": bucket["archive_first_generated_at"],
            "archive_last_generated_at": bucket["archive_last_generated_at"],
            "archive_span_sec": (
                round(
                    (
                        _parse_dt(bucket["archive_last_generated_at"]) - _parse_dt(bucket["archive_first_generated_at"])
                    ).total_seconds(),
                    3,
                )
                if bucket["archive_first_generated_at"] and bucket["archive_last_generated_at"]
                else None
            ),
            "base_finding_ids_count": len(base_finding_ids),
            "split_finding_ids_count": len(split_finding_ids),
            "shared_finding_ids_count": len(shared_ids),
            "split_only_finding_ids_count": len(split_only_ids),
            "base_only_finding_ids_count": len(base_only_ids),
            "shared_finding_titles_count": len(shared_titles),
            "split_only_finding_titles_count": len(split_only_titles),
            "split_artifacts_with_findings": bucket["split_artifacts_with_findings"],
            "split_component_metric_artifacts": bucket["split_component_metric_artifacts"],
            "split_permission_metric_artifacts": bucket["split_permission_metric_artifacts"],
            "split_provider_metric_artifacts": bucket["split_provider_metric_artifacts"],
            "split_string_or_secret_metric_artifacts": bucket["split_string_or_secret_metric_artifacts"],
            "split_network_metric_artifacts": bucket["split_network_metric_artifacts"],
            "correlation_cache_hits": bucket["correlation_cache_hits"],
            "correlation_cache_misses": bucket["correlation_cache_misses"],
        }
        package_rows.append(row)
        split_rows.append(
            {
                "package_name": package_name,
                "display_name": bucket["display_name"],
                "archive_artifacts": bucket["archive_artifacts"],
                "base_artifacts": bucket["base_artifacts"],
                "split_artifacts": bucket["split_artifacts"],
                "artifact_share_pct": row["artifact_share_pct"],
                "split_share_of_session_pct": row["split_share_of_session_pct"],
                "detector_duration_sec_sum": row["detector_duration_sec_sum"],
                "avg_artifact_duration_sec": row["avg_artifact_duration_sec"],
                "total_findings": row["total_findings"],
                "split_only_finding_ids_count": row["split_only_finding_ids_count"],
                "split_only_finding_titles_count": row["split_only_finding_titles_count"],
                "split_artifacts_with_findings": row["split_artifacts_with_findings"],
                "split_component_metric_artifacts": row["split_component_metric_artifacts"],
                "split_permission_metric_artifacts": row["split_permission_metric_artifacts"],
                "split_provider_metric_artifacts": row["split_provider_metric_artifacts"],
                "split_string_or_secret_metric_artifacts": row["split_string_or_secret_metric_artifacts"],
                "split_network_metric_artifacts": row["split_network_metric_artifacts"],
                "complete_in_archive": row["complete_in_archive"],
            }
        )
        parse_rows.append(
            {
                "package_name": package_name,
                "display_name": bucket["display_name"],
                "archive_artifacts": bucket["archive_artifacts"],
                "resource_fallback_used_artifacts": bucket["resource_fallback_used_artifacts"],
                "resource_bounds_warning_artifacts": bucket["resource_bounds_warning_artifacts"],
                "resource_parse_partial_artifacts": bucket["resource_parse_partial_artifacts"],
                "resource_reparse_candidate_artifacts": bucket["resource_reparse_candidate_artifacts"],
                "label_parse_signal_artifacts": bucket["label_parse_signal_artifacts"],
                "parse_signal_events_est": bucket["parse_signal_events_est"],
                "split_artifacts": bucket["split_artifacts"],
            }
        )
    package_rows.sort(key=lambda item: (-float(item["detector_duration_sec_sum"]), -int(item["archive_artifacts"]), item["package_name"]))
    split_rows.sort(key=lambda item: (-int(item["split_artifacts"]), -float(item["detector_duration_sec_sum"]), item["package_name"]))
    parse_rows.sort(key=lambda item: (-int(item["parse_signal_events_est"]), item["package_name"]))
    return package_rows, split_rows, parse_rows


def _timing_coverage(report_rows: Sequence[Mapping[str, Any]]) -> float:
    if not report_rows:
        return 0.0
    available = sum(1 for row in report_rows if _safe_float(row.get("duration_seconds")) is not None)
    return available / len(report_rows)


def _build_recommendation(
    *,
    report_rows: Sequence[Mapping[str, Any]],
    package_rows: Sequence[Mapping[str, Any]],
    detector_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    timing_coverage = _timing_coverage(report_rows)
    total_artifacts = len(report_rows)
    split_artifacts = sum(1 for row in report_rows if bool(row.get("is_split")))
    split_share = (split_artifacts / total_artifacts) if total_artifacts else 0.0
    total_duration = sum(float(row.get("total_duration_sec") or 0.0) for row in detector_rows)
    top_stage = detector_rows[0] if detector_rows else None
    top_stage_share = (
        float(top_stage.get("total_duration_sec") or 0.0) / total_duration
        if top_stage and total_duration > 0
        else 0.0
    )
    packages_with_split_only = sum(1 for row in package_rows if int(row.get("split_only_finding_ids_count") or 0) > 0)
    split_only_package_ratio = (packages_with_split_only / len(package_rows)) if package_rows else 0.0
    split_metric_packages = sum(
        1
        for row in package_rows
        if int(row.get("split_component_metric_artifacts") or 0) > 0
        or int(row.get("split_permission_metric_artifacts") or 0) > 0
        or int(row.get("split_provider_metric_artifacts") or 0) > 0
    )
    split_metric_package_ratio = (split_metric_packages / len(package_rows)) if package_rows else 0.0

    recommendation = "keep_full_split_scan_default"
    rationale: list[str] = []
    if timing_coverage < 0.8:
        recommendation = "collect_more_timing_data_first"
        rationale.append("Timing coverage across archive reports is incomplete.")
    elif top_stage_share >= 0.55:
        recommendation = "optimize_detector_stage_timing_first"
        rationale.append(
            f"{top_stage.get('detector_id')} dominates detector-stage time ({top_stage_share:.1%} of measured stage duration)."
        )
    elif split_share >= 0.5 and split_only_package_ratio < 0.25 and split_metric_package_ratio < 0.25:
        recommendation = "add_base_first_fast_profile"
        rationale.append("Split artifacts dominate volume while measured split-only evidence stays limited.")
    elif split_share >= 0.5:
        recommendation = "add_selective_split_scan_profile"
        rationale.append("Split artifacts dominate volume but still add measurable extra evidence for many packages.")
    else:
        rationale.append("Full split-aware scanning is not yet contradicted by the measured evidence.")

    follow_on = []
    if recommendation == "optimize_detector_stage_timing_first" and split_share >= 0.5:
        follow_on.append(
            "After stage-timing work, evaluate a clearer base-first or selective-split operator profile because split artifacts are a large share of the workload."
        )
    if split_metric_package_ratio > 0:
        follow_on.append(
            f"Split manifests are not empty: {split_metric_package_ratio:.1%} of packages showed split-side component/permission/provider metric activity."
        )

    return {
        "recommended_action": recommendation,
        "timing_coverage_pct": round(100.0 * timing_coverage, 2),
        "split_artifact_share_pct": round(100.0 * split_share, 2),
        "top_stage_share_pct": round(100.0 * top_stage_share, 2),
        "top_stage_detector_id": top_stage.get("detector_id") if top_stage else None,
        "packages_with_split_only_finding_id_proxy": packages_with_split_only,
        "packages_with_split_only_finding_id_proxy_pct": round(100.0 * split_only_package_ratio, 2),
        "packages_with_split_metric_activity_pct": round(100.0 * split_metric_package_ratio, 2),
        "rationale": rationale,
        "follow_on_notes": follow_on,
        "candidate_profile_labels": [
            "full-split-aware",
            "base-first-fast",
            "base-plus-selected-splits",
            "research-paper-full",
        ],
        "no_db_writes": True,
        "experimental_audit": True,
    }


def _session_state(
    *,
    expected_artifacts: int | None,
    archive_reports: int,
    expected_packages: int | None,
    archive_packages: int,
    db_counts: Mapping[str, Any],
    persistence_log: Mapping[str, Any],
) -> tuple[str, bool]:
    completed_runs = int(db_counts.get("completed_run_rows") or 0)
    if expected_packages and completed_runs >= expected_packages:
        return "completed", True
    if expected_artifacts and archive_reports >= expected_artifacts:
        if int(persistence_log.get("persisted_package_count") or 0) > 0 or completed_runs > 0:
            return "artifact_archive_complete_db_persistence_in_progress", False
        return "artifact_archive_complete_db_not_started", False
    if archive_reports > 0 and archive_packages > 0:
        return "artifact_scan_in_progress", False
    return "no_archive_reports", False


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    from scytaledroid.Config import app_config
    from scytaledroid.StaticAnalysis.cli.execution.static_parallel_workers import (
        effective_parallel_artifact_worker_count,
    )

    data_dir = Path(app_config.DATA_DIR)
    output_dir_root = Path(app_config.OUTPUT_DIR)
    session_stamp = _resolve_session_stamp(data_dir, args.session_stamp)
    if not session_stamp:
        sys.stderr.write("No static session archive directories found.\n")
        return 1

    archive_dir = _reports_root(data_dir) / session_stamp
    if not archive_dir.exists():
        sys.stderr.write(f"Static archive directory not found for session {session_stamp}: {archive_dir}\n")
        return 1

    out_dir = (
        Path(args.output_dir)
        if args.output_dir
        else output_dir_root / "audit" / "static_run_performance" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    _log(args.verbose, f"Loading report archive: {archive_dir}")
    report_rows, extras = _load_report_rows(archive_dir)
    detector_stage_rows = extras["detector_stage_rows"]
    finding_failure_rows = extras["finding_failure_rows"]
    warnings = list(extras["warnings"])

    if not report_rows:
        warnings.append("no_report_rows_loaded")

    harvest_session = _infer_harvest_session(report_rows)
    harvest_expectations = _load_harvest_expectations(data_dir, harvest_session)

    _log(args.verbose, "Aggregating package, detector, and split-evidence summaries")
    package_rows, split_rows, parse_rows = _aggregate_package_rows(report_rows, harvest_expectations)
    detector_rows = _aggregate_detector_stage_summary(detector_stage_rows)
    failure_rows = _aggregate_failure_summary(finding_failure_rows)

    db_counts, db_notes = _init_optional_db(session_stamp)
    warnings.extend(db_notes)
    persistence_log = _load_persistence_log_summary(session_stamp)

    archive_generated = [_parse_dt(row.get("generated_at")) for row in report_rows]
    archive_generated = [value for value in archive_generated if value is not None]
    archive_started = min(archive_generated) if archive_generated else None
    archive_finished = max(archive_generated) if archive_generated else None

    expected_packages = _safe_int(harvest_expectations.get("clean_package_count"))
    expected_artifacts = _safe_int(harvest_expectations.get("clean_artifact_count"))
    archive_reports = len(report_rows)
    archive_packages = len({_norm_text_or_none(row.get("package_name")) for row in report_rows if _norm_text_or_none(row.get("package_name"))})
    session_state, session_complete = _session_state(
        expected_artifacts=expected_artifacts,
        archive_reports=archive_reports,
        expected_packages=expected_packages,
        archive_packages=archive_packages,
        db_counts=db_counts,
        persistence_log=persistence_log,
    )

    recommendation = _build_recommendation(
        report_rows=report_rows,
        package_rows=package_rows,
        detector_rows=detector_rows,
    )

    top_parse_packages = [
        {
            "package_name": row["package_name"],
            "display_name": row.get("display_name"),
            "parse_signal_events_est": row["parse_signal_events_est"],
            "resource_parse_partial_artifacts": row.get("resource_parse_partial_artifacts"),
            "resource_reparse_candidate_artifacts": row.get("resource_reparse_candidate_artifacts"),
        }
        for row in parse_rows[:10]
        if int(row.get("parse_signal_events_est") or 0) > 0
    ]
    top_split_heavy = [
        {
            "package_name": row["package_name"],
            "display_name": row.get("display_name"),
            "archive_artifacts": row["archive_artifacts"],
            "split_artifacts": row["split_artifacts"],
            "detector_duration_sec_sum": row["detector_duration_sec_sum"],
        }
        for row in split_rows[:10]
    ]

    artifact_timing_available = sum(
        1 for row in report_rows if _safe_float(row.get("duration_seconds")) is not None
    )
    artifact_wall_timing_available = sum(
        1 for row in report_rows if _safe_float(row.get("artifact_total_wall_s")) is not None
    )
    total_artifact_wall_clock = sum(float(row.get("artifact_total_wall_s") or 0.0) for row in report_rows)
    total_hash_seconds = sum(float(row.get("hash_seconds") or 0.0) for row in report_rows)
    total_string_index_seconds = sum(float(row.get("string_index_seconds") or 0.0) for row in report_rows)
    total_correlation_cache_hits = sum(int(row.get("correlation_cache_hits") or 0) for row in report_rows)
    total_correlation_cache_misses = sum(int(row.get("correlation_cache_misses") or 0) for row in report_rows)
    artifact_policy_failures = sum(int(row.get("policy_failure_count") or 0) for row in report_rows)
    artifact_finding_failures = sum(int(row.get("finding_failure_count") or 0) for row in report_rows)
    artifact_execution_errors = sum(int(row.get("execution_error_count") or 0) for row in report_rows)
    total_detector_duration = sum(float(row.get("total_duration_sec") or 0.0) for row in detector_rows)
    split_artifact_count = sum(1 for row in report_rows if bool(row.get("is_split")))
    base_artifact_count = archive_reports - split_artifact_count
    default_parallel_workers = effective_parallel_artifact_worker_count(
        resolved_worker_budget=None,
        artifact_count=max(1, split_artifact_count or archive_reports or 1),
    )
    summary = {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "repo_root": str(_REPO_ROOT),
        "data_root": str(data_dir),
        "session_stamp": session_stamp,
        "harvest_session_label": harvest_session,
        "session_state": session_state,
        "session_complete": session_complete,
        "archive_dir": str(archive_dir),
        "expected_packages_from_harvest": expected_packages,
        "expected_apk_artifacts_from_harvest": expected_artifacts,
        "blocked_packages_from_harvest": _safe_int(harvest_expectations.get("blocked_count")),
        "archive_report_count": archive_reports,
        "archive_package_count": archive_packages,
        "archive_base_artifact_count": base_artifact_count,
        "archive_split_artifact_count": split_artifact_count,
        "artifact_timing_available_count": artifact_timing_available,
        "artifact_timing_available_pct": round(100.0 * _timing_coverage(report_rows), 2),
        "artifact_wall_clock_available_count": artifact_wall_timing_available,
        "artifact_wall_clock_available_pct": round(
            100.0 * (artifact_wall_timing_available / max(1, archive_reports)),
            2,
        ),
        "archive_generated_first": archive_started.isoformat().replace("+00:00", "Z") if archive_started else None,
        "archive_generated_last": archive_finished.isoformat().replace("+00:00", "Z") if archive_finished else None,
        "archive_generated_span_sec": round((archive_finished - archive_started).total_seconds(), 3)
        if archive_started and archive_finished
        else None,
        "db_name": db_counts.get("db_name"),
        "db_static_run_rows": db_counts.get("static_run_rows"),
        "db_completed_run_rows": db_counts.get("completed_run_rows"),
        "db_started_run_rows": db_counts.get("started_run_rows"),
        "db_failed_run_rows": db_counts.get("failed_run_rows"),
        "db_status_breakdown": db_counts.get("status_breakdown"),
        "db_findings_rows": db_counts.get("finding_rows"),
        "db_permission_matrix_rows": db_counts.get("permission_matrix_rows"),
        "db_string_summary_rows": db_counts.get("string_summary_rows"),
        "db_string_sample_rows": db_counts.get("string_sample_rows"),
        "db_session_rollup_rows": db_counts.get("session_rollup_rows"),
        "logged_persisted_package_count": persistence_log.get("persisted_package_count"),
        "logged_persistence_max_app_index": persistence_log.get("max_app_index"),
        "logged_persistence_last_at": persistence_log.get("last_logged_at"),
        "artifact_policy_failure_events": artifact_policy_failures,
        "artifact_finding_failure_events": artifact_finding_failures,
        "artifact_execution_error_events": artifact_execution_errors,
        "parse_signal_events_est": sum(int(row.get("parse_signal_events_est") or 0) for row in parse_rows),
        "resource_parse_partial_artifacts": sum(
            int(row.get("resource_parse_partial_artifacts") or 0) for row in parse_rows
        ),
        "resource_reparse_candidate_artifacts": sum(
            int(row.get("resource_reparse_candidate_artifacts") or 0) for row in parse_rows
        ),
        "top_parse_signal_packages": top_parse_packages,
        "top_split_heavy_packages": top_split_heavy,
        "top_detector_stages_by_duration": [
            {
                "detector_id": row["detector_id"],
                "total_duration_sec": row["total_duration_sec"],
                "split_duration_sec": row["split_duration_sec"],
                "base_duration_sec": row["base_duration_sec"],
            }
            for row in detector_rows[:10]
        ],
        "timing_breakdown": {
            "artifact_wall_clock_total_sec": round(total_artifact_wall_clock, 3),
            "hash_total_sec": round(total_hash_seconds, 3),
            "string_index_total_sec": round(total_string_index_seconds, 3),
        },
        "correlation_runtime_cache": {
            "total_hits": total_correlation_cache_hits,
            "total_misses": total_correlation_cache_misses,
            "hit_ratio_pct": round(
                100.0 * total_correlation_cache_hits / max(1, total_correlation_cache_hits + total_correlation_cache_misses),
                2,
            ),
        },
        "worker_model": {
            "package_loop_serial": True,
            "artifact_process_pool_optional": True,
            "artifact_parallel_worker_env": os.getenv("SCYTALEDROID_STATIC_ARTIFACT_WORKERS", "1"),
            "artifact_parallel_worker_default_effective": default_parallel_workers,
            "note": "workers=auto does not by itself enable per-package artifact process parallelism; split artifacts stay inside a serial package loop unless SCYTALEDROID_STATIC_ARTIFACT_WORKERS > 1.",
        },
        "timing_contract": {
            "artifact_duration_field": "metadata.pipeline_summary.total_duration_sec",
            "artifact_duration_semantics": "detector-stage duration sum proxy, not end-to-end wall-clock per artifact",
            "artifact_wall_clock_field": "metadata.artifact_total_wall_s",
            "artifact_wall_clock_available": bool(artifact_wall_timing_available),
        },
        "total_detector_stage_duration_sec": round(total_detector_duration, 3),
        "finding_failure_semantics": {
            "meaning": "Detector stage returned FAIL without policy_gate and without execution exception.",
            "source": "scytaledroid/StaticAnalysis/core/pipeline_artifacts.py:build_pipeline_summary",
            "ui_rewording_candidate": "detector finding gate failures",
        },
        "output_files": list(OUTPUT_FILES),
        "warnings": sorted(set(warnings)),
        "assumptions": [
            "Artifact duration uses pipeline summary or detector-duration fallback when available.",
            "Split evidence uniqueness is measured with conservative proxies such as finding_id/title overlap and split-side detector metric activity.",
            "Static report archive is treated as primary evidence; DB rows and logs are corroboration.",
        ],
        "no_db_writes": True,
        "experimental_audit": True,
    }

    _write_csv(out_dir / "apk_artifact_runtime_summary.csv", [
        {key: value for key, value in row.items() if not str(key).startswith("_")}
        for row in sorted(
            report_rows,
            key=lambda item: (
                -float(item.get("duration_seconds") or 0.0),
                item["package_name"],
                int(item.get("is_split") or 0),
                item["artifact_name"],
            ),
        )
    ])
    _write_csv(out_dir / "package_runtime_summary.csv", package_rows)
    _write_csv(out_dir / "split_heavy_packages.csv", split_rows)
    _write_csv(out_dir / "detector_stage_summary.csv", detector_rows)
    _write_csv(out_dir / "base_vs_split_evidence_summary.csv", [
        {
            "package_name": row["package_name"],
            "display_name": row.get("display_name"),
            "base_artifacts": row["base_artifacts"],
            "split_artifacts": row["split_artifacts"],
            "base_finding_ids_count": row["base_finding_ids_count"],
            "split_finding_ids_count": row["split_finding_ids_count"],
            "shared_finding_ids_count": row["shared_finding_ids_count"],
            "split_only_finding_ids_count": row["split_only_finding_ids_count"],
            "base_only_finding_ids_count": row["base_only_finding_ids_count"],
            "shared_finding_titles_count": row["shared_finding_titles_count"],
            "split_only_finding_titles_count": row["split_only_finding_titles_count"],
            "split_artifacts_with_findings": row["split_artifacts_with_findings"],
            "split_component_metric_artifacts": row["split_component_metric_artifacts"],
            "split_permission_metric_artifacts": row["split_permission_metric_artifacts"],
            "split_provider_metric_artifacts": row["split_provider_metric_artifacts"],
            "split_string_or_secret_metric_artifacts": row["split_string_or_secret_metric_artifacts"],
            "split_network_metric_artifacts": row["split_network_metric_artifacts"],
        }
        for row in package_rows
    ])
    _write_csv(out_dir / "finding_failure_summary.csv", failure_rows)
    _write_csv(out_dir / "parse_signal_summary.csv", parse_rows)
    _write_json(out_dir / "static_performance_recommendations.json", recommendation)
    _write_json(out_dir / "summary.json", summary)

    _log(args.verbose, f"Wrote audit bundle: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
