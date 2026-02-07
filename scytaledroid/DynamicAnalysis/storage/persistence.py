"""Dynamic analysis persistence scaffolding."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session
from scytaledroid.Database.db_queries.dynamic import schema as dynamic_schema
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Database.db_utils.artifact_registry import record_artifacts
from scytaledroid.DynamicAnalysis.plans.loader import extract_plan_identity
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.network_quality import evaluate_network_signal_quality
from scytaledroid.Utils.version_utils import get_git_commit

from ..core.session import DynamicSessionConfig, DynamicSessionResult

_LOGGER = logging_engine.get_dynamic_logger()


def persist_dynamic_summary(
    config: DynamicSessionConfig, result: DynamicSessionResult, payload: dict[str, Any]
) -> None:
    if not _require_dynamic_schema(require=bool(getattr(config, "require_dynamic_schema", True))):
        return
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
    profile_key = None
    if isinstance(plan_payload, dict):
        profile_key = plan_payload.get("profile_key") or plan_payload.get("profile")
    tool_semver = app_config.APP_VERSION
    tool_git_commit = get_git_commit()
    schema_version = db_diagnostics.get_schema_version() or "<unknown>"

    _LOGGER.info(
        "Dynamic persistence inputs",
        extra={
            "dynamic_run_id": dynamic_run_id,
            "evidence_path": pcap_meta.get("pcap_evidence_path") or result.evidence_path,
            "pcap_relpath": pcap_meta.get("pcap_relpath"),
            "pcap_bytes": pcap_meta.get("pcap_bytes"),
            "pcap_valid": pcap_meta.get("pcap_valid"),
        },
    )

    duration_seconds = config.duration_seconds
    if (not duration_seconds or int(duration_seconds) == 0) and result.started_at and result.ended_at:
        duration_seconds = int((result.ended_at - result.started_at).total_seconds())
    sampling_duration_seconds = qa_stats.get("sampling_duration_seconds")
    clock_alignment_delta_s = None
    try:
        if duration_seconds is not None and sampling_duration_seconds is not None:
            clock_alignment_delta_s = abs(float(duration_seconds) - float(sampling_duration_seconds))
    except (TypeError, ValueError):
        clock_alignment_delta_s = None
    session_row = {
        "dynamic_run_id": dynamic_run_id,
        "package_name": config.package_name,
        "device_serial": config.device_serial,
        "profile_key": profile_key,
        "scenario_id": config.scenario_id,
        "tier": config.tier,
        "duration_seconds": duration_seconds,
        "sampling_duration_seconds": sampling_duration_seconds,
        "clock_alignment_delta_s": clock_alignment_delta_s,
        "sampling_rate_s": sampling_rate_s,
        "started_at_utc": _fmt_dt(result.started_at),
        "ended_at_utc": _fmt_dt(result.ended_at),
        "host_time_utc_start": _fmt_dt(payload.get("host_time_utc_start")),
        "host_time_utc_end": _fmt_dt(payload.get("host_time_utc_end")),
        "device_time_utc_start": _fmt_dt(payload.get("device_time_utc_start")),
        "device_time_utc_end": _fmt_dt(payload.get("device_time_utc_end")),
        "device_uptime_ms_start": _safe_int(payload.get("device_uptime_ms_start")),
        "device_uptime_ms_end": _safe_int(payload.get("device_uptime_ms_end")),
        "drift_ms_start": _safe_int(payload.get("drift_ms_start")),
        "drift_ms_end": _safe_int(payload.get("drift_ms_end")),
        "status": result.status,
        "evidence_path": result.evidence_path,
        "static_run_id": _safe_int(plan_identity.get("static_run_id") or config.static_run_id),
        "run_signature": plan_identity.get("run_signature"),
        "run_signature_version": plan_identity.get("run_signature_version"),
        "base_apk_sha256": plan_identity.get("base_apk_sha256"),
        "apk_sha256": plan_identity.get("base_apk_sha256"),
        "artifact_set_hash": plan_identity.get("artifact_set_hash"),
        "version_name": plan_identity.get("version_name"),
        "version_code": _safe_int(plan_identity.get("version_code")),
        "expected_samples": qa_stats.get("expected_samples"),
        "captured_samples": qa_stats.get("captured_samples"),
        "sample_min_delta_s": qa_stats.get("sample_min_delta_s"),
        "sample_avg_delta_s": qa_stats.get("sample_avg_delta_s"),
        "sample_max_delta_s": qa_stats.get("sample_max_delta_s"),
        "sample_max_gap_s": qa_stats.get("sample_max_gap_s"),
        "sample_first_gap_s": qa_stats.get("sample_first_gap_s"),
        "sample_max_gap_excluding_first_s": qa_stats.get("sample_max_gap_excluding_first_s"),
        "netstats_available": netstats_available,
        "network_signal_quality": network_signal_quality,
        "netstats_rows": netstats_rows,
        "netstats_missing_rows": netstats_missing_rows,
        "pcap_relpath": pcap_meta.get("pcap_relpath"),
        "pcap_bytes": pcap_meta.get("pcap_bytes"),
        "pcap_sha256": pcap_meta.get("pcap_sha256"),
        "pcap_valid": pcap_meta.get("pcap_valid"),
        "pcap_validated_at_utc": pcap_meta.get("pcap_validated_at_utc"),
        "tool_semver": tool_semver,
        "tool_git_commit": tool_git_commit,
        "schema_version": schema_version,
    }

    payload["static_run_id"] = session_row.get("static_run_id")
    payload["dynamic_run_id"] = dynamic_run_id
    try:
        with database_session() as db:
            with db.transaction():
                _register_manifest_artifacts(dynamic_run_id, result.evidence_path)
                grade, reasons = _evaluate_grade(payload, pcap_meta)
                session_row["grade"] = grade
                session_row["grade_reasons_json"] = json.dumps(reasons) if reasons else None

                _insert_dynamic_session(session_row)

                issues = _collect_issue_rows(dynamic_run_id, result, payload, plan_payload)
                if issues:
                    _insert_dynamic_issues(issues)

                _persist_telemetry(dynamic_run_id, payload, tier=config.tier)
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning(
            "Dynamic persistence transaction failed",
            extra={"dynamic_run_id": dynamic_run_id, "error": str(exc)},
        )
        raise


def _require_dynamic_schema(*, require: bool) -> bool:
    if dynamic_schema.ensure_all():
        return True
    # Env vars are entrypoint defaults only. Schema gating must be based on the frozen run config.
    if require:
        raise RuntimeError("DB schema is outdated; run migrations to use dynamic schema.")
    _LOGGER.warning("Dynamic schema missing; persistence skipped (experimental mode).")
    return False


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
    diagnostics = payload.get("diagnostics_warnings")
    if isinstance(diagnostics, list):
        for warning in diagnostics:
            if not warning:
                continue
            issues.append(
                {
                    "dynamic_run_id": dynamic_run_id,
                    "issue_code": f"diagnostic_{warning}",
                    "details_json": {"warning": warning},
                }
            )
    if result.status == "degraded" and not issues:
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "session_degraded",
                "details_json": {"notes": result.notes, "errors": result.errors},
            }
        )
    return issues


def _evaluate_grade(payload: Mapping[str, Any], pcap_meta: Mapping[str, Any]) -> tuple[str, list[object]]:
    reasons: list[object] = []
    status = str(payload.get("status") or "").lower()
    if status == "blocked":
        reasons.append({"code": "run_blocked"})
        return "EXPERIMENTAL", reasons
    process_rows = payload.get("telemetry_process") or []
    network_rows = payload.get("telemetry_network") or []
    if not process_rows:
        reasons.append({"code": "process_telemetry_missing"})
    if not network_rows:
        reasons.append({"code": "network_telemetry_missing"})

    stats = payload.get("telemetry_stats") or {}
    expected = _safe_int(stats.get("expected_samples"))
    captured = _safe_int(stats.get("captured_samples"))
    if expected is None or captured is None:
        reasons.append({"code": "telemetry_stats_missing"})
    elif expected:
        try:
            ratio = float(captured) / float(expected)
            missingness = 1.0 - ratio
            if missingness > 0.10:
                reasons.append(
                    {
                        "code": "telemetry_missingness",
                        "captured": captured,
                        "expected": expected,
                        "missingness": round(missingness, 4),
                    }
                )
        except Exception:
            pass

    manifest_artifacts: list[Mapping[str, Any]] = []
    evidence_path = payload.get("evidence_path")
    manifest_path = None
    if evidence_path:
        manifest_path = resolve_evidence_path(evidence_path) / "run_manifest.json"
        if not manifest_path.exists():
            reasons.append({"code": "manifest_missing"})
        else:
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                manifest = {}
            artifacts = []
            artifacts.extend(manifest.get("artifacts") or [])
            artifacts.extend(manifest.get("outputs") or [])
            for observer in manifest.get("observers") or []:
                artifacts.extend(observer.get("artifacts") or [])
            manifest_artifacts = [a for a in artifacts if isinstance(a, Mapping)]

    if manifest_artifacts:
        required_types = {"system_log_capture"}
        if payload.get("pcap_required"):
            required_types.add("pcapdroid_capture")
        if payload.get("static_run_id"):
            required_types.add("dep_snapshot")
        present_types = {str(a.get("type")) for a in manifest_artifacts if a.get("type")}
        for required in sorted(required_types):
            if required not in present_types:
                reasons.append({"code": "required_artifact_missing", "artifact_type": required})
        for artifact in manifest_artifacts:
            artifact_type = artifact.get("type")
            if artifact_type in required_types and not artifact.get("sha256"):
                reasons.append({"code": "artifact_unhashed", "artifact_type": artifact_type})

    registry_rows = _load_artifact_registry(payload.get("dynamic_run_id"))
    if registry_rows:
        required_types = {"system_log_capture"}
        if payload.get("pcap_required"):
            required_types.add("pcapdroid_capture")
        if payload.get("static_run_id"):
            required_types.add("dep_snapshot")
        present_types = {row["artifact_type"] for row in registry_rows}
        for required in sorted(required_types):
            if required not in present_types:
                reasons.append({"code": "registry_artifact_missing", "artifact_type": required})
        for row in registry_rows:
            if row["artifact_type"] not in required_types:
                continue
            if not row.get("sha256"):
                reasons.append({"code": "registry_artifact_unhashed", "artifact_type": row["artifact_type"]})
            if row.get("origin") == "device" and row.get("pull_status") != "pulled":
                reasons.append({"code": "artifact_not_pulled", "artifact_type": row["artifact_type"]})
            if row.get("origin") in {"unknown", None}:
                reasons.append({"code": "artifact_origin_unknown", "artifact_type": row["artifact_type"]})
            if row.get("pull_status") in {"unknown", None}:
                reasons.append({"code": "artifact_pull_status_unknown", "artifact_type": row["artifact_type"]})

    if payload.get("pcap_required"):
        if not pcap_meta.get("pcap_relpath"):
            reasons.append({"code": "pcap_missing"})
        elif pcap_meta.get("pcap_valid") in (0, False):
            reasons.append({"code": "pcap_invalid"})

    grade = "PAPER_GRADE" if not reasons else "EXPERIMENTAL"
    return grade, reasons


def _register_manifest_artifacts(dynamic_run_id: str, evidence_path: str | None) -> None:
    if not evidence_path:
        return
    resolved = resolve_evidence_path(evidence_path)
    manifest_path = resolved / "run_manifest.json"
    if not manifest_path.exists():
        return
    try:
        manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        manifest_size = manifest_path.stat().st_size
    except Exception:
        manifest_digest = None
        manifest_size = None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return
    artifacts: list[Mapping[str, Any]] = []
    artifacts.append(
        {
            "path": str(manifest_path),
            "type": "dynamic_run_manifest",
            "sha256": manifest_digest,
            "size_bytes": manifest_size,
            "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "origin": "host",
            "pull_status": "n/a",
        }
    )
    artifacts.extend(manifest.get("artifacts") or [])
    artifacts.extend(manifest.get("outputs") or [])
    for observer in manifest.get("observers") or []:
        artifacts.extend(observer.get("artifacts") or [])
    if not artifacts:
        return
    record_artifacts(
        run_id=dynamic_run_id,
        run_type="dynamic",
        artifacts=artifacts,
        base_path=resolved,
    )


def _load_artifact_registry(dynamic_run_id: str | None) -> list[dict[str, Any]]:
    if not dynamic_run_id:
        return []
    try:
        rows = core_q.run_sql(
            """
            SELECT artifact_type, origin, pull_status, sha256, host_path
            FROM artifact_registry
            WHERE run_id=%s AND run_type='dynamic'
            """,
            (dynamic_run_id,),
            fetch="all",
        )
    except Exception:
        return []
    return [
        {
            "artifact_type": str(row[0]),
            "origin": row[1],
            "pull_status": row[2],
            "sha256": row[3],
            "host_path": row[4],
        }
        for row in rows
        if row
    ]


def _issues_from_manifest(dynamic_run_id: str, evidence_path: str | None) -> list[dict[str, Any]]:
    if not evidence_path:
        return []
    resolved = resolve_evidence_path(evidence_path)
    if not resolved:
        _LOGGER.warning(
            "Dynamic manifest lookup failed (missing evidence path)",
            extra={"dynamic_run_id": dynamic_run_id, "evidence_path": evidence_path},
        )
        return []
    manifest_path = resolved / "run_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOGGER.warning(
            "Dynamic manifest read failed while collecting issues",
            extra={
                "dynamic_run_id": dynamic_run_id,
                "evidence_path": str(resolved),
                "error": str(exc),
            },
        )
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

    # Dataset validity is a first-class persisted QA signal for Paper #2.
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    tier = operator.get("tier")
    validity = operator.get("dataset_validity") if isinstance(operator, dict) else None
    if tier and str(tier).lower() == "dataset" and isinstance(validity, dict):
        issues.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "issue_code": "dataset_validity",
                "details_json": validity,
            }
        )
    return issues


def _map_observer_issue(observer_id: object, status: object, error: object) -> str | None:
    if not observer_id or not status:
        return None
    observer_id = str(observer_id)
    status = str(status).lower()
    error_text = str(error or "").lower()
    if observer_id == "system_log_capture" and status == "failed":
        return "logcat_capture_failed"
    if observer_id == "proxy_capture" and status == "failed":
        return "proxy_capture_failed"
    if observer_id == "network_capture":
        if "tcpdump not available" in error_text and "non-root" in error_text:
            return "tcpdump_unavailable_nonroot"
        if status == "failed":
            return "network_capture_failed"
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
    max_gap = stats.get("sample_max_gap_excluding_first_s") or stats.get("sample_max_gap_s")
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
            "sampling_duration_seconds": None,
            "sample_min_delta_s": None,
            "sample_avg_delta_s": None,
            "sample_max_delta_s": None,
            "sample_max_gap_s": None,
            "sample_first_gap_s": None,
            "sample_max_gap_excluding_first_s": None,
        }
    return {
        "expected_samples": _safe_int(stats.get("expected_samples")),
        "captured_samples": _safe_int(stats.get("captured_samples")),
        "sampling_duration_seconds": _safe_float(stats.get("sampling_duration_seconds")),
        "sample_min_delta_s": _safe_float(stats.get("sample_min_delta_s")),
        "sample_avg_delta_s": _safe_float(stats.get("sample_avg_delta_s")),
        "sample_max_delta_s": _safe_float(stats.get("sample_max_delta_s")),
        "sample_max_gap_s": _safe_float(stats.get("sample_max_gap_s")),
        "sample_first_gap_s": _safe_float(stats.get("sample_first_gap_s")),
        "sample_max_gap_excluding_first_s": _safe_float(stats.get("sample_max_gap_excluding_first_s")),
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

    resolved_path = resolve_evidence_path(evidence_path)
    pcap_relpath = None
    meta_relpath = None
    pcap_sha256 = None
    pcap_bytes = None
    pcap_valid = None
    min_pcap_bytes = 30 * 1024
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "pcapdroid_capture":
            pcap_relpath = entry.get("relative_path")
            pcap_sha256 = entry.get("sha256")
            pcap_bytes = entry.get("size_bytes")
            break

    if pcap_relpath is None and resolved_path:
        manifest_path = resolved_path / "run_manifest.json"
        try:
            if not manifest_path.exists():
                _LOGGER.warning(
                    "Dynamic manifest missing while extracting PCAP metadata",
                    extra={"evidence_path": str(resolved_path)},
                )
                manifest = {}
            else:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _LOGGER.warning(
                "Failed to read dynamic manifest while extracting PCAP metadata",
                extra={"evidence_path": str(resolved_path), "error": str(exc)},
            )
            manifest = {}
        capture_types = {"pcapdroid_capture"}
        meta_types = {"pcapdroid_capture_meta"}
        for bucket in ("artifacts", "outputs"):
            for entry in manifest.get(bucket) or []:
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") in capture_types:
                    pcap_relpath = entry.get("relative_path")
                    pcap_sha256 = entry.get("sha256")
                    pcap_bytes = entry.get("size_bytes")
                    break
                if entry.get("type") in meta_types and not meta_relpath:
                    meta_relpath = entry.get("relative_path")
            if pcap_relpath:
                break
        if not pcap_relpath:
            for observer in manifest.get("observers") or []:
                if not isinstance(observer, dict):
                    continue
                for entry in observer.get("artifacts") or []:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("type") in capture_types:
                        pcap_relpath = entry.get("relative_path")
                        pcap_sha256 = entry.get("sha256")
                        pcap_bytes = entry.get("size_bytes")
                        break
                    if entry.get("type") in meta_types and not meta_relpath:
                        meta_relpath = entry.get("relative_path")
                if pcap_relpath:
                    break

        if meta_relpath and resolved_path:
            meta_path = resolved_path / meta_relpath
            try:
                meta_payload = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                meta_payload = {}
            if pcap_bytes is None:
                meta_size = meta_payload.get("pcap_size_bytes")
                if isinstance(meta_size, int):
                    pcap_bytes = meta_size
            if pcap_valid is None:
                meta_valid = meta_payload.get("pcap_valid")
                if isinstance(meta_valid, bool):
                    pcap_valid = meta_valid
            if not pcap_relpath and resolved_path:
                resolved_name = meta_payload.get("resolved_pcap_name") or meta_payload.get("pcap_name")
                if isinstance(resolved_name, str) and resolved_name:
                    candidate = resolved_path / "artifacts" / "pcapdroid_capture" / resolved_name
                    if candidate.exists():
                        pcap_relpath = str(candidate.relative_to(resolved_path))

    capture_valid = capture.get("pcap_valid")
    if capture_valid is not None:
        pcap_valid = capture_valid
    pcap_size = capture.get("pcap_size_bytes")
    if pcap_bytes is None and isinstance(pcap_size, int):
        pcap_bytes = pcap_size

    if pcap_relpath and resolved_path:
        pcap_path = resolved_path / pcap_relpath
        try:
            if pcap_bytes is None and pcap_path.exists():
                pcap_bytes = pcap_path.stat().st_size
            if pcap_valid is None and pcap_path.exists():
                pcap_valid = pcap_path.stat().st_size >= min_pcap_bytes
        except OSError:
            pass

    pcap_validated_at = None
    if pcap_valid is not None:
        pcap_validated_at = datetime.now(UTC)

    return {
        "pcap_relpath": pcap_relpath,
        "pcap_bytes": _safe_int(pcap_bytes),
        "pcap_sha256": pcap_sha256,
        "pcap_valid": 1 if pcap_valid is True else 0 if pcap_valid is False else None,
        "pcap_validated_at_utc": _fmt_dt(pcap_validated_at),
        "pcap_evidence_path": str(resolved_path) if resolved_path else evidence_path,
    }


def _fmt_dt(value: object | None) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
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
