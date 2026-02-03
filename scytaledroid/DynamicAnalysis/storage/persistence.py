"""Dynamic analysis persistence scaffolding."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_queries.dynamic import schema as dynamic_schema
from scytaledroid.DynamicAnalysis.plans.loader import extract_plan_identity
from scytaledroid.Utils.network_quality import evaluate_network_signal_quality

from ..core.session import DynamicSessionConfig, DynamicSessionResult


def persist_dynamic_summary(
    config: DynamicSessionConfig, result: DynamicSessionResult, payload: Dict[str, Any]
) -> None:
    _require_dynamic_schema()
    dynamic_run_id = result.dynamic_run_id or payload.get("dynamic_run_id")
    if not dynamic_run_id:
        raise RuntimeError("dynamic_run_id missing; cannot persist dynamic session")

    plan_payload = payload.get("plan") or {}
    plan_identity = _extract_plan_identity(plan_payload)
    sampling_rate_s = _safe_int(payload.get("sampling_rate_s"))
    qa_stats = _extract_qa_stats(payload)
    netstats_available = _extract_netstats_available(payload)
    network_signal_quality = _extract_network_signal_quality(payload)
    netstats_rows = _extract_netstats_rows(payload)
    netstats_missing_rows = _extract_netstats_missing_rows(payload)
    pcap_meta = _extract_pcap_meta(payload, result.evidence_path)

    duration_seconds = config.duration_seconds
    if (not duration_seconds or int(duration_seconds) == 0) and result.started_at and result.ended_at:
        duration_seconds = int((result.ended_at - result.started_at).total_seconds())
    session_row = {
        "dynamic_run_id": dynamic_run_id,
        "package_name": config.package_name,
        "device_serial": config.device_serial,
        "scenario_id": config.scenario_id,
        "tier": config.tier,
        "duration_seconds": duration_seconds,
        "sampling_rate_s": sampling_rate_s,
        "started_at_utc": _fmt_dt(result.started_at),
        "ended_at_utc": _fmt_dt(result.ended_at),
        "status": result.status,
        "evidence_path": result.evidence_path,
        "static_run_id": _safe_int(plan_identity.get("static_run_id") or config.static_run_id),
        "run_signature": plan_identity.get("run_signature"),
        "run_signature_version": plan_identity.get("run_signature_version"),
        "base_apk_sha256": plan_identity.get("base_apk_sha256"),
        "artifact_set_hash": plan_identity.get("artifact_set_hash"),
        "version_name": plan_identity.get("version_name"),
        "version_code": _safe_int(plan_identity.get("version_code")),
        "expected_samples": qa_stats.get("expected_samples"),
        "captured_samples": qa_stats.get("captured_samples"),
        "sample_min_delta_s": qa_stats.get("sample_min_delta_s"),
        "sample_avg_delta_s": qa_stats.get("sample_avg_delta_s"),
        "sample_max_delta_s": qa_stats.get("sample_max_delta_s"),
        "sample_max_gap_s": qa_stats.get("sample_max_gap_s"),
        "netstats_available": netstats_available,
        "network_signal_quality": network_signal_quality,
        "netstats_rows": netstats_rows,
        "netstats_missing_rows": netstats_missing_rows,
        "pcap_relpath": pcap_meta.get("pcap_relpath"),
        "pcap_bytes": pcap_meta.get("pcap_bytes"),
        "pcap_sha256": pcap_meta.get("pcap_sha256"),
        "pcap_valid": pcap_meta.get("pcap_valid"),
        "pcap_validated_at_utc": pcap_meta.get("pcap_validated_at_utc"),
    }
    if not _dynamic_sessions_has_column("tier"):
        session_row.pop("tier", None)
    if not _dynamic_sessions_has_column("netstats_available"):
        session_row.pop("netstats_available", None)
    if not _dynamic_sessions_has_column("network_signal_quality"):
        session_row.pop("network_signal_quality", None)
    if not _dynamic_sessions_has_column("netstats_rows"):
        session_row.pop("netstats_rows", None)
    if not _dynamic_sessions_has_column("netstats_missing_rows"):
        session_row.pop("netstats_missing_rows", None)
    if not _dynamic_sessions_has_column("pcap_relpath"):
        session_row.pop("pcap_relpath", None)
    if not _dynamic_sessions_has_column("pcap_bytes"):
        session_row.pop("pcap_bytes", None)
    if not _dynamic_sessions_has_column("pcap_sha256"):
        session_row.pop("pcap_sha256", None)
    if not _dynamic_sessions_has_column("pcap_valid"):
        session_row.pop("pcap_valid", None)
    if not _dynamic_sessions_has_column("pcap_validated_at_utc"):
        session_row.pop("pcap_validated_at_utc", None)

    _insert_dynamic_session(session_row)

    issues = _collect_issue_rows(dynamic_run_id, result, payload, plan_payload)
    if issues:
        _insert_dynamic_issues(issues)

    _persist_telemetry(dynamic_run_id, payload, tier=config.tier)


def _require_dynamic_schema() -> None:
    if not dynamic_schema.ensure_all():
        raise RuntimeError("DB schema is outdated; run migrations to use dynamic schema.")


def _insert_dynamic_session(row: Mapping[str, Any]) -> None:
    columns = list(row.keys())
    placeholders = ", ".join(["%s"] * len(columns))
    updates = ", ".join([f"{col}=VALUES({col})" for col in columns if col != "dynamic_run_id"])
    sql = f"""
        INSERT INTO dynamic_sessions ({', '.join(columns)})
        VALUES ({placeholders})
        ON DUPLICATE KEY UPDATE {updates}
    """
    core_q.run_sql_write(sql, tuple(row[col] for col in columns), query_name="dynamic.sessions.upsert")


def _insert_dynamic_issues(rows: Iterable[Mapping[str, Any]]) -> None:
    columns = ["dynamic_run_id", "issue_code", "details_json"]
    sql = """
        INSERT INTO dynamic_session_issues (dynamic_run_id, issue_code, details_json)
        VALUES (%s, %s, %s)
    """
    data = []
    for row in rows:
        details = row.get("details_json")
        if isinstance(details, (dict, list)):
            details = json.dumps(details)
        data.append((row.get("dynamic_run_id"), row.get("issue_code"), details))
    core_q.run_sql_many(sql, data, query_name="dynamic.issues.insert")


def _persist_telemetry(dynamic_run_id: str, payload: Mapping[str, Any], *, tier: str | None = None) -> None:
    process_rows = payload.get("telemetry_process") or []
    network_rows = payload.get("telemetry_network") or []
    if tier == "dataset":
        network_rows = [
            row
            for row in network_rows
            if row.get("source") in {"netstats", "netstats_missing"}
        ]
    if process_rows:
        _insert_process_rows(dynamic_run_id, process_rows)
    if network_rows:
        _insert_network_rows(dynamic_run_id, network_rows)


def _insert_process_rows(dynamic_run_id: str, rows: Iterable[Mapping[str, Any]]) -> None:
    sql = """
        INSERT INTO dynamic_telemetry_process (
          dynamic_run_id,
          sample_index,
          timestamp_utc,
          uid,
          pid,
          cpu_pct,
          rss_kb,
          pss_kb,
          threads,
          proc_name,
          best_effort,
          collector_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    data = []
    for row in rows:
        data.append(
            (
                dynamic_run_id,
                _safe_int(row.get("sample_index")),
                _fmt_dt(row.get("timestamp_utc")),
                row.get("uid"),
                _safe_int(row.get("pid")),
                _safe_float(row.get("cpu_pct")),
                _safe_float(row.get("rss_kb")),
                _safe_float(row.get("pss_kb")),
                _safe_int(row.get("threads")),
                row.get("proc_name"),
                _safe_int(row.get("best_effort")),
                row.get("collector_status"),
            )
        )
    core_q.run_sql_many(sql, data, query_name="dynamic.telemetry.process")


def _insert_network_rows(dynamic_run_id: str, rows: Iterable[Mapping[str, Any]]) -> None:
    sql = """
        INSERT INTO dynamic_telemetry_network (
          dynamic_run_id,
          sample_index,
          timestamp_utc,
          uid,
          bytes_in,
          bytes_out,
          conn_count,
          source,
          best_effort,
          collector_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    data = []
    for row in rows:
        data.append(
            (
                dynamic_run_id,
                _safe_int(row.get("sample_index")),
                _fmt_dt(row.get("timestamp_utc")),
                row.get("uid"),
                _safe_float(row.get("bytes_in")),
                _safe_float(row.get("bytes_out")),
                _safe_float(row.get("conn_count")),
                row.get("source"),
                _safe_int(row.get("best_effort")),
                row.get("collector_status"),
            )
        )
    core_q.run_sql_many(sql, data, query_name="dynamic.telemetry.network")


def _collect_issue_rows(
    dynamic_run_id: str,
    result: DynamicSessionResult,
    payload: Mapping[str, Any],
    plan_payload: Mapping[str, Any],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if result.status == "blocked":
        validation = payload.get("plan_validation")
        details = validation or {"errors": result.errors}
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "plan_validation_fail",
                "details_json": details,
            }
        )
    manifest_issues = _issues_from_manifest(dynamic_run_id, result.evidence_path)
    issues.extend(manifest_issues)
    telemetry_issue = _issues_from_telemetry(dynamic_run_id, payload)
    issues.extend(telemetry_issue)
    if result.status == "degraded" and not issues:
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "session_degraded",
                "details_json": {"notes": result.notes, "errors": result.errors},
            }
        )
    return issues


def _issues_from_manifest(dynamic_run_id: str, evidence_path: str | None) -> list[dict[str, Any]]:
    if not evidence_path:
        return []
    manifest_path = Path(evidence_path) / "run_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    observers = manifest.get("observers") or []
    issues: list[dict[str, Any]] = []
    for observer in observers:
        if not isinstance(observer, dict):
            continue
        observer_id = observer.get("observer_id")
        status = observer.get("status")
        error = observer.get("error") or ""
        issue_code = _map_observer_issue(observer_id, status, error)
        if issue_code:
            issues.append(
                {
                    "dynamic_run_id": dynamic_run_id,
                    "issue_code": issue_code,
                    "details_json": {"observer_id": observer_id, "status": status, "error": error},
                }
            )
    return issues


def _map_observer_issue(observer_id: object, status: object, error: object) -> str | None:
    if not observer_id or not status:
        return None
    observer_id = str(observer_id)
    status = str(status).lower()
    error_text = str(error or "").lower()
    if observer_id == "proxy_capture" and status == "failed":
        return "proxy_capture_failed"
    if observer_id == "system_log_capture" and status == "failed":
        return "logcat_capture_failed"
    if observer_id == "network_capture":
        if "non-root" in error_text or "not available" in error_text:
            return "tcpdump_unavailable_nonroot"
        if status == "failed":
            return "tcpdump_start_failed"
    if observer_id == "pcapdroid_capture":
        if "not installed" in error_text:
            return "pcapdroid_unavailable"
        if "mismatch" in error_text:
            return "pcapdroid_capture_mismatch"
        if "empty" in error_text:
            return "pcapdroid_capture_empty"
        if status == "failed":
            return "pcapdroid_capture_failed"
    if status == "failed":
        return "observer_failed"
    if status == "skipped" and "tcpdump" in error_text:
        return "tcpdump_unavailable_nonroot"
    return None


def _issues_from_telemetry(dynamic_run_id: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    stats = payload.get("telemetry_stats")
    if not isinstance(stats, dict):
        return []
    issues: list[dict[str, Any]] = []
    error = stats.get("error")
    if error:
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "telemetry_sampler_failed",
                "details_json": {"error": error},
            }
        )
        return issues

    netstats_available = stats.get("netstats_available")
    if netstats_available is False:
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "netstats_unavailable",
                "details_json": {"netstats_available": False},
            }
        )

    expected = stats.get("expected_samples")
    captured = stats.get("captured_samples")
    max_gap = stats.get("sample_max_gap_s")
    rate = payload.get("sampling_rate_s") or 1
    ratio = None
    try:
        if expected and int(expected) > 0:
            ratio = float(captured or 0) / float(expected)
    except Exception:
        ratio = None
    gap_threshold = 2 * int(rate)
    details: dict[str, object] = {}
    if ratio is not None and ratio < 0.90:
        details.update({"captured": captured, "expected": expected, "ratio": ratio})
    try:
        if max_gap is not None and float(max_gap) > gap_threshold:
            details.update({"max_gap_s": max_gap, "threshold_s": gap_threshold})
    except Exception:
        pass
    if details:
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "telemetry_partial_samples",
                "details_json": details,
            }
        )
    return issues


def _extract_plan_identity(plan_payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(plan_payload, dict) or not plan_payload:
        return {}
    identity = extract_plan_identity(dict(plan_payload))
    run_identity = plan_payload.get("run_identity") or {}
    if isinstance(run_identity, dict):
        for key in ("base_apk_sha256", "artifact_set_hash", "run_signature", "run_signature_version"):
            if run_identity.get(key) and not identity.get(key):
                identity[key] = run_identity[key]
    for key in ("version_name", "version_code"):
        if plan_payload.get(key) and not identity.get(key):
            identity[key] = plan_payload.get(key)
    return identity


def _extract_qa_stats(payload: Mapping[str, Any]) -> dict[str, Any]:
    stats = payload.get("telemetry_stats") or {}
    if not isinstance(stats, dict):
        return {
            "expected_samples": None,
            "captured_samples": None,
            "sample_min_delta_s": None,
            "sample_avg_delta_s": None,
            "sample_max_delta_s": None,
            "sample_max_gap_s": None,
        }
    return {
        "expected_samples": _safe_int(stats.get("expected_samples")),
        "captured_samples": _safe_int(stats.get("captured_samples")),
        "sample_min_delta_s": _safe_float(stats.get("sample_min_delta_s")),
        "sample_avg_delta_s": _safe_float(stats.get("sample_avg_delta_s")),
        "sample_max_delta_s": _safe_float(stats.get("sample_max_delta_s")),
        "sample_max_gap_s": _safe_float(stats.get("sample_max_gap_s")),
    }


def _extract_netstats_available(payload: Mapping[str, Any]) -> int | None:
    stats = payload.get("telemetry_stats") or {}
    if not isinstance(stats, dict):
        return None
    value = stats.get("netstats_available")
    if value is None:
        return None
    return 1 if bool(value) else 0


def _extract_network_signal_quality(payload: Mapping[str, Any]) -> str | None:
    stats = payload.get("telemetry_stats") or {}
    if isinstance(stats, dict):
        quality = stats.get("network_signal_quality")
        if isinstance(quality, str) and quality:
            return quality

    rows = payload.get("telemetry_network") or []
    if not isinstance(rows, list):
        return None
    netstats_rows = sum(1 for row in rows if row.get("source") == "netstats")
    netstats_missing_rows = sum(1 for row in rows if row.get("source") == "netstats_missing")
    total_in = 0
    total_out = 0
    for row in rows:
        if row.get("source") != "netstats":
            continue
        try:
            total_in += int(float(row.get("bytes_in") or 0))
            total_out += int(float(row.get("bytes_out") or 0))
        except (TypeError, ValueError):
            continue
    return evaluate_network_signal_quality(
        netstats_rows=netstats_rows,
        netstats_missing_rows=netstats_missing_rows,
        sum_bytes_in=total_in,
        sum_bytes_out=total_out,
    )


def _extract_netstats_rows(payload: Mapping[str, Any]) -> int | None:
    stats = payload.get("telemetry_stats") or {}
    if isinstance(stats, dict):
        value = stats.get("netstats_rows")
        if value is not None:
            return _safe_int(value)
    rows = payload.get("telemetry_network") or []
    if not isinstance(rows, list):
        return None
    return sum(1 for row in rows if row.get("source") == "netstats")


def _extract_netstats_missing_rows(payload: Mapping[str, Any]) -> int | None:
    stats = payload.get("telemetry_stats") or {}
    if isinstance(stats, dict):
        value = stats.get("netstats_missing_rows")
        if value is not None:
            return _safe_int(value)
    rows = payload.get("telemetry_network") or []
    if not isinstance(rows, list):
        return None
    return sum(1 for row in rows if row.get("source") == "netstats_missing")


def _extract_pcap_meta(payload: Mapping[str, Any], evidence_path: str | None) -> dict[str, Any]:
    capture = payload.get("capture") or {}
    evidence = payload.get("evidence") or []
    if not isinstance(capture, dict):
        capture = {}
    if not isinstance(evidence, list):
        evidence = []

    pcap_relpath = None
    pcap_sha256 = None
    pcap_bytes = None
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") in {"pcapdroid_capture", "network_capture", "proxy_capture"}:
            pcap_relpath = entry.get("relative_path")
            pcap_sha256 = entry.get("sha256")
            pcap_bytes = entry.get("size_bytes")
            break

    pcap_valid = capture.get("pcap_valid")
    pcap_size = capture.get("pcap_size_bytes")
    if pcap_bytes is None and isinstance(pcap_size, int):
        pcap_bytes = pcap_size

    pcap_validated_at = None
    if pcap_valid is not None:
        pcap_validated_at = datetime.now(timezone.utc)

    return {
        "pcap_relpath": pcap_relpath,
        "pcap_bytes": _safe_int(pcap_bytes),
        "pcap_sha256": pcap_sha256,
        "pcap_valid": 1 if pcap_valid is True else 0 if pcap_valid is False else None,
        "pcap_validated_at_utc": _fmt_dt(pcap_validated_at),
        "pcap_evidence_path": evidence_path,
    }


_DYN_SESSIONS_COLUMNS: set[str] | None = None


def _dynamic_sessions_has_column(column_name: str) -> bool:
    global _DYN_SESSIONS_COLUMNS
    if _DYN_SESSIONS_COLUMNS is None:
        try:
            rows = core_q.run_sql(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = DATABASE() AND table_name = 'dynamic_sessions'",
                fetch="all",
                dictionary=True,
            )
            _DYN_SESSIONS_COLUMNS = {
                str(row.get("column_name")).lower() for row in rows or [] if row.get("column_name")
            }
        except Exception:
            _DYN_SESSIONS_COLUMNS = set()
    return column_name.lower() in _DYN_SESSIONS_COLUMNS


def _fmt_dt(value: object | None) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, str) and value:
        return value
    return None


def _safe_int(value: object | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: object | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
