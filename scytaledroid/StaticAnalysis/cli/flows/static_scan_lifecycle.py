"""Static scan lifecycle helpers (status derivation, phase / RUN_END logging).

Split from ``static_scan_launch`` so orchestration stays readable and these pieces
can be tested or reused without pulling the full launch function.
"""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome, RunParameters
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext


def effective_static_run_status(
    outcome: RunOutcome | None,
    *,
    current_status: str | None = None,
    summary_render_failed: bool = False,
) -> str | None:
    """Return the final run status after scan and post-processing mutations."""

    status = (current_status or "").strip().upper() or None
    if outcome is None:
        return status
    if summary_render_failed:
        return "FAILED"
    if outcome.aborted:
        return "FAILED"
    if getattr(outcome, "persistence_failed", False):
        return "FAILED"
    if getattr(outcome, "canonical_failed", False):
        return "FAILED"
    failures = {str(item).strip().upper() for item in (outcome.failures or []) if str(item).strip()}
    if failures:
        return "FAILED"
    return status or "COMPLETED"


def emit_static_run_phase_log(
    *,
    run_ctx: RunContext,
    session_stamp: str | None,
    scope_target: str | None,
    scope_label: str | None,
    profile_label: str | None,
    execution_id: str | None,
    phase: str,
    status: str | None = None,
    extra: dict[str, object] | None = None,
) -> None:
    """Structured RUN_PHASE log (prefers ``run_dispatch`` logger, falls back to run_events)."""

    from scytaledroid.StaticAnalysis.cli.flows import run_dispatch as _dispatch_phase
    from scytaledroid.StaticAnalysis.cli.flows.run_events import _emit_phase_log as _run_events_emit_phase_log

    payload: dict[str, object] = {
        "event": log_events.RUN_PHASE,
        "run_id": session_stamp,
        "session_stamp": session_stamp,
        "execution_id": execution_id,
        "target": scope_target,
        "scope_label": scope_label,
        "profile": profile_label,
        "phase": phase,
    }
    if status:
        payload["status"] = status
    if extra:
        payload.update({key: value for key, value in extra.items() if value is not None})

    try:
        logger = _dispatch_phase.get_run_logger("static", run_ctx)
        logger.info("Static RUN_PHASE", extra=payload)
    except Exception:
        _run_events_emit_phase_log(
            run_ctx=run_ctx,
            session_stamp=session_stamp,
            scope_target=scope_target,
            scope_label=scope_label,
            profile_label=profile_label,
            execution_id=execution_id,
            phase=phase,
            status=status,
            extra=extra,
        )


def emit_static_run_end_log(
    *,
    run_ctx: RunContext,
    params: RunParameters,
    outcome: RunOutcome | None,
    modules: list[str],
    scope_target: str | None,
    run_status: str | None,
    abort_reason: str | None,
    abort_signal: str | None,
    summary_render_failed: bool,
) -> None:
    """Emit RUN_END after persistence / postprocess (terminal lifecycle record)."""

    if not params.session_stamp:
        return

    end_payload: dict[str, object] = {
        "event": log_events.RUN_END,
        "run_id": params.session_stamp,
        "execution_id": params.execution_id,
        "target": scope_target,
        "profile": params.profile_label,
        "scope_label": params.scope_label,
        "analysis_version": params.analysis_version,
        "detectors": modules,
        "detectors_count": len(modules),
        "status": (run_status or "UNKNOWN").lower(),
        "dry_run": params.dry_run,
    }
    if outcome is not None:
        end_payload["duration_seconds"] = outcome.duration_seconds
        end_payload["applications"] = len(outcome.results or [])
        end_payload["artifacts"] = outcome.total_artifacts
        end_payload["artifacts_completed"] = outcome.completed_artifacts
        end_payload["dry_run_skipped"] = outcome.dry_run_skipped
        end_payload["warnings_count"] = len(outcome.warnings or [])
        end_payload["failures_count"] = len(outcome.failures or [])
        if outcome.failures:
            end_payload["failure_codes"] = [str(item) for item in outcome.failures[:10]]
        if getattr(outcome, "persistence_failed", False):
            end_payload["persistence_failed"] = True
        if getattr(outcome, "compat_export_failed", False):
            end_payload["compat_export_failed"] = True
        if getattr(outcome, "canonical_failed", False):
            end_payload["canonical_failed"] = True
    if abort_reason:
        end_payload["abort_reason"] = abort_reason
    if abort_signal:
        end_payload["abort_signal"] = abort_signal
    if summary_render_failed:
        end_payload["summary_render_failed"] = True
    if (
        (run_status or "").upper() == "FAILED"
        and "failure_codes" not in end_payload
        and "abort_reason" not in end_payload
        and outcome is not None
        and outcome.completed_artifacts < outcome.total_artifacts
    ):
        end_payload["status_reason"] = "artifacts_incomplete"

    from scytaledroid.StaticAnalysis.cli.flows import run_dispatch as _dispatch

    try:
        static_logger = _dispatch.get_run_logger("static", run_ctx)
        static_logger.info("Static RUN_END", extra=end_payload)
    except Exception:
        try:
            logger = logging_engine.get_static_logger()
            logger.info("Static RUN_END", extra=logging_engine.ensure_trace(end_payload))
        except Exception:
            pass


def emit_static_run_start_log(
    *,
    run_ctx: RunContext,
    frozen_ctx: StaticRunContext,
    params: RunParameters,
    modules: list[str],
    workers_label: str,
    scope_target: str | None,
) -> None:
    """Structured RUN_START log with frozen CLI context payload."""

    from scytaledroid.StaticAnalysis.cli.flows import run_dispatch as _dispatch

    try:
        static_logger = _dispatch.get_run_logger("static", run_ctx)
        run_context_payload = dict(frozen_ctx.__dict__)
        run_context_payload["canonical_grade_requested"] = run_context_payload.pop(
            "paper_grade_requested",
            bool(getattr(params, "paper_grade_requested", True)),
        )
        run_context_payload["execution_id"] = params.execution_id
        static_logger.info(
            "Static RUN_START",
            extra={
                "event": log_events.RUN_START,
                "run_id": params.session_stamp,
                "execution_id": params.execution_id,
                "target": scope_target,
                "profile": params.profile_label,
                "scope_label": params.scope_label,
                "analysis_version": params.analysis_version,
                "modules": modules,
                "workers": workers_label,
                "cache": "purge" if not params.reuse_cache else "reuse",
                "perm_cache": "refresh" if params.permission_snapshot_refresh else "skip",
                "dry_run": params.dry_run,
                "run_context": run_context_payload,
            },
        )
    except Exception:
        pass


def emit_static_dry_run_banner(params: RunParameters) -> None:
    """Operator-facing dry-run diagnostic header (matches launch output)."""

    pipeline_version = getattr(params, "analysis_version", None)
    run_sig_version = getattr(params, "run_signature_version", "v1")
    print("DIAGNOSTIC MODE (dry run)")
    print("────────────────────────────────")
    print("persist=no  evidence_pack=no  plan_generation=no")
    print("identity_required=yes  linkage_required=yes")
    print("metadata=partial  linkage_sources=run_map,db_link")
    print(f"pipeline_version={pipeline_version or '—'}  run_signature_version={run_sig_version}")
    if params.session_stamp:
        print(
            f"Session: {params.session_stamp}  Preset: {params.profile_label}  "
            f"Scope: {params.scope_label or params.scope}"
        )
    print()


def collect_static_run_ids_for_finalize(
    outcome: RunOutcome,
    session_stamp: str | None,
) -> list[int]:
    """Merge result static_run_ids with lingering STARTED DB rows for this session."""

    static_run_ids: list[int] = [
        int(result.static_run_id)
        for result in outcome.results
        if result.static_run_id
    ]
    if session_stamp:
        try:
            from scytaledroid.Database.db_core import db_queries as core_q

            rows = core_q.run_sql(
                """
                SELECT id
                FROM static_analysis_runs
                WHERE session_stamp=%s
                  AND status='STARTED'
                  AND ended_at_utc IS NULL
                """,
                (session_stamp,),
                fetch="all",
            )
            for row in rows or []:
                try:
                    sid = int(row[0])
                except Exception:
                    continue
                static_run_ids.append(sid)
        except Exception:
            pass
    if not static_run_ids:
        return []
    return sorted({int(sid) for sid in static_run_ids if sid})


__all__ = [
    "collect_static_run_ids_for_finalize",
    "effective_static_run_status",
    "emit_static_dry_run_banner",
    "emit_static_run_end_log",
    "emit_static_run_phase_log",
    "emit_static_run_start_log",
]
