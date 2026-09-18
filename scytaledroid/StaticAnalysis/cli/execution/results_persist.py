"""Persistence helpers for static analysis results."""

from __future__ import annotations

import time
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime

from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
    fetch_static_session_run_rollups,
    materialize_static_session_rollup,
)
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...core import StaticAnalysisReport
from ..core.models import AppRunResult, RunParameters
from ..persistence.run_summary import persist_run_summary
from ..views.renderers.summary_render import render_app_result
from .results_persistence import apply_persistence_outcome, merge_persistence_metadata


def _persist_cohort_rollup(session_stamp: str | None, scope_label: str | None) -> None:
    if not session_stamp:
        return
    scope_label = scope_label or ""
    try:
        rollups = fetch_static_session_run_rollups(session_stamp, scope_label)
        rollup_written = materialize_static_session_rollup(
            session_stamp=session_stamp,
            scope_label=scope_label,
        )
    except Exception as exc:
        log.warning(
            f"Failed to compute cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )
        return

    if not rollups or not rollup_written:
        return

    # Per-run finalization refreshes the session header before the cohort rollup exists.
    # Refresh once more after the rollup upsert so ``static_analysis_sessions.rollup_rows``
    # and related header counters reflect the committed child row.
    try:
        from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
            maybe_refresh_static_analysis_session_summary,
        )

        maybe_refresh_static_analysis_session_summary(
            session_stamp,
            scope_label,
            reason="post_cohort_rollup",
        )
    except Exception as exc:
        log.warning(
            f"Failed to refresh static_analysis_sessions after cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )

    # The persistence audit artifact is emitted before cohort-rollup finalization runs.
    # Refresh the summary once more so operator-facing JSON reflects the committed rollup row.
    try:
        from scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit import (
            refresh_persistence_audit_artifact_for_session,
        )

        refresh_persistence_audit_artifact_for_session(
            session_stamp,
            write=True,
            prefer_reconcile=False,
        )
    except Exception as exc:
        log.warning(
            f"Failed to refresh persistence audit summary after cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )

    level = "info"
    print(
        status_messages.status(
            (
                f"Session history (DB rollup): static_analysis_runs rows matching this session="
                f"{rollups.total_run_count} | COMPLETED={rollups.completed_run_count} | "
                f"FAILED={rollups.failed_run_count} | "
                f"still_STARTED_or_RUNNING={rollups.running_run_count} "
                "(non-terminal status rows only; usually 0 after the cohort finishes cleanly)"
            ),
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


def persist_outcome_is_durable(
    outcome_status: object | None,
    static_run_id: int | None = None,
) -> bool:
    """True when canonical package evidence is already durable in DB.

    ``persist_run_summary`` may return ``success=False`` for non-fatal envelope
    notes or for an idempotent ``immutable_completed_run`` refusal. Those must
    not look like a failed persist that later demotes a COMPLETED parent.
    """

    if outcome_status is None:
        return False
    errors = [str(err) for err in (getattr(outcome_status, "errors", None) or [])]
    if any("immutable_completed_run" in err for err in errors):
        return True
    if bool(getattr(outcome_status, "persistence_failed", False)):
        return False
    if bool(getattr(outcome_status, "success", False)):
        return True
    rid = static_run_id if static_run_id is not None else getattr(outcome_status, "static_run_id", None)
    return _static_run_is_completed(rid)


def _static_run_is_completed(static_run_id: object) -> bool:
    try:
        rid = int(static_run_id)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        row = core_q.run_sql(
            "SELECT status FROM static_analysis_runs WHERE id=%s LIMIT 1",
            (rid,),
            fetch="one",
        )
    except Exception:
        return False
    current = None
    if isinstance(row, dict):
        current = row.get("status")
    elif row:
        current = row[0]
    return str(current or "").strip().upper() == "COMPLETED"


def persist_analyzed_package(
    *,
    app_result: AppRunResult,
    params: RunParameters,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
):
    """Persist one package's canonical evidence before the next package starts.

    Session rollup is derived after commit. A rollup failure must not invalidate
    a package that already committed COMPLETED.
    """

    if getattr(app_result, "canonical_persist_committed", False):
        return None
    if bool(getattr(params, "dry_run", False)):
        return None
    if not bool(getattr(params, "persistence_ready", True)):
        return None
    if not getattr(app_result, "static_run_id", None):
        return None
    base_report = app_result.base_report()
    if base_report is None:
        return None

    string_data = (
        app_result.base_string_data if isinstance(app_result.base_string_data, Mapping) else {}
    )
    total_duration = sum(float(artifact.duration_seconds or 0.0) for artifact in app_result.artifacts)
    _lines, payload, finding_totals = render_app_result(
        base_report,
        signer=app_result.signer,
        split_count=len(app_result.artifacts),
        string_data=string_data,
        duration_seconds=total_duration,
        verbose_output=False,
    )
    merge_persistence_metadata(
        base_report=base_report,
        app_result=app_result,
        params=params,
    )
    if not ended_at_utc:
        ended_at_utc = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    outcome_status = persist_run_summary(
        base_report,
        string_data,
        app_result.package_name,
        session_stamp=params.session_stamp,
        scope_label=params.scope_label or "",
        finding_totals=finding_totals,
        baseline_payload=payload,
        static_run_id=app_result.static_run_id,
        run_status="COMPLETED",
        ended_at_utc=ended_at_utc,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
        paper_grade_requested=params.paper_grade_requested,
        canonical_action=params.canonical_action,
        dry_run=False,
    )
    apply_persistence_outcome(app_result=app_result, outcome_status=outcome_status)
    if persist_outcome_is_durable(outcome_status, getattr(app_result, "static_run_id", None)):
        app_result.canonical_persist_committed = True
        app_result.canonical_persist_committed_at_monotonic = time.monotonic()
        try:
            _persist_cohort_rollup(params.session_stamp, params.scope_label)
        except Exception as exc:
            log.warning(
                (
                    "Session rollup failed after durable package persist "
                    f"for {app_result.package_name}: {exc}"
                ),
                category="static_analysis",
            )
    return outcome_status


__all__ = [
    "_build_ingest_payload",
    "_persist_cohort_rollup",
    "persist_analyzed_package",
    "persist_outcome_is_durable",
]
