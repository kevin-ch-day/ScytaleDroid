"""Persistence helpers for static analysis results."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...core import StaticAnalysisReport
from ..core.models import RunParameters


def _persist_cohort_rollup(session_stamp: str | None, scope_label: str | None) -> None:
    if not session_stamp:
        return
    scope_label = scope_label or ""
    try:
        row = core_q.run_sql(
            """
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN UPPER(COALESCE(status, ''))='COMPLETED' THEN 1 ELSE 0 END) AS completed,
              SUM(CASE WHEN UPPER(COALESCE(status, ''))='FAILED' THEN 1 ELSE 0 END) AS failed,
              SUM(CASE WHEN UPPER(COALESCE(status, '')) IN ('STARTED','RUNNING') THEN 1 ELSE 0 END) AS running
            FROM static_analysis_runs
            WHERE session_stamp=%s AND scope_label=%s
            """,
            (session_stamp, scope_label),
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:
        log.warning(
            f"Failed to compute cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )
        return

    if not row:
        return

    if isinstance(row, Mapping):
        total = int(row.get("total") or 0)
        completed = int(row.get("completed") or 0)
        failed = int(row.get("failed") or 0)
        running = int(row.get("running") or 0)
    else:
        row_seq = tuple(row) if isinstance(row, (tuple, list)) else ()
        total = int(row_seq[0] or 0) if len(row_seq) > 0 else 0
        completed = int(row_seq[1] or 0) if len(row_seq) > 1 else 0
        failed = int(row_seq[2] or 0) if len(row_seq) > 2 else 0
        running = int(row_seq[3] or 0) if len(row_seq) > 3 else 0
    try:
        core_q.run_sql(
            """
            INSERT INTO static_session_rollups (
              session_stamp, scope_label, apps_total, completed, failed, aborted, running
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              apps_total=VALUES(apps_total),
              completed=VALUES(completed),
              failed=VALUES(failed),
              aborted=VALUES(aborted),
              running=VALUES(running)
            """,
            (
                session_stamp,
                scope_label,
                total,
                completed,
                failed,
                0,
                running,
            ),
        )
    except Exception as exc:
        log.warning(
            f"Failed to persist cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )
        return

    level = "info"
    print(
        status_messages.status(
            f"Session history (attempt rollup): Apps {total} | Completed {completed} | Failed {failed} | Started {running}",
            level=level,
        )
    )


def _build_ingest_payload(
    payload: Mapping[str, object],
    report: StaticAnalysisReport,
    params: RunParameters,
) -> Mapping[str, object]:
    app_section = payload.get("app")
    app_copy: MutableMapping[str, object]
    if isinstance(app_section, Mapping):
        app_copy = dict(app_section)
    else:
        app_copy = {}

    baseline_section = payload.get("baseline")
    baseline_copy: MutableMapping[str, object] = {}
    findings_list: list[Mapping[str, object]] = []
    if isinstance(baseline_section, Mapping):
        baseline_copy.update(baseline_section)
        findings_raw = baseline_section.get("findings")
        if isinstance(findings_raw, list) or isinstance(findings_raw, tuple):
            findings_list = [
                dict(entry)
                for entry in findings_raw
                if isinstance(entry, Mapping)
            ]

    app_copy.setdefault("package", report.manifest.package_name or app_copy.get("package"))
    if report.manifest.version_name and not app_copy.get("version_name"):
        app_copy["version_name"] = report.manifest.version_name
    if report.manifest.version_code and not app_copy.get("version_code"):
        app_copy["version_code"] = report.manifest.version_code
    if report.manifest.min_sdk and not app_copy.get("min_sdk"):
        app_copy["min_sdk"] = report.manifest.min_sdk
    if report.manifest.target_sdk and not app_copy.get("target_sdk"):
        app_copy["target_sdk"] = report.manifest.target_sdk

    metadata_map: MutableMapping[str, object] = {}
    if isinstance(report.metadata, Mapping):
        metadata_map.update(report.metadata)
    if params.session_stamp and not metadata_map.get("session_stamp"):
        metadata_map["session_stamp"] = params.session_stamp
    if params.scope_label and not metadata_map.get("run_scope_label"):
        metadata_map["run_scope_label"] = params.scope_label
    if params.scope and not metadata_map.get("run_scope"):
        metadata_map["run_scope"] = params.scope
    if not metadata_map.get("pipeline_version"):
        metadata_map["pipeline_version"] = getattr(params, "analysis_version", None)
    if not metadata_map.get("catalog_versions"):
        metadata_map["catalog_versions"] = getattr(params, "catalog_versions", None)
    if not metadata_map.get("config_hash"):
        metadata_map["config_hash"] = getattr(params, "config_hash", None)
    if not metadata_map.get("study_tag"):
        metadata_map["study_tag"] = getattr(params, "study_tag", None)
    if payload.get("generated_at") and not metadata_map.get("run_started_utc"):
        metadata_map["run_started_utc"] = payload.get("generated_at")

    ingest_payload: MutableMapping[str, object] = {}
    ingest_payload["generated_at"] = payload.get("generated_at")
    ingest_payload["app"] = app_copy
    ingest_payload["baseline"] = baseline_copy
    ingest_payload["findings"] = findings_list
    ingest_payload["hashes"] = dict(report.hashes)
    ingest_payload["analysis_version"] = report.analysis_version
    ingest_payload["scan_profile"] = params.profile
    ingest_payload["detector_metrics"] = dict(report.detector_metrics)
    ingest_payload["metadata"] = metadata_map
    analytics_section = payload.get("analytics")
    if isinstance(analytics_section, Mapping):
        ingest_payload["analytics"] = dict(analytics_section)

    return ingest_payload


__all__ = ["_build_ingest_payload", "_persist_cohort_rollup"]
