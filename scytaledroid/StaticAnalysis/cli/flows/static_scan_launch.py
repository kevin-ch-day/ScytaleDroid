"""Static scan execution path after parameters are resolved (scan → render → postprocess).

Extracted from ``run_dispatch`` so the orchestration module stays a thin compatibility surface
and this lifecycle is easier to navigate and test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

from scytaledroid.Database.summary_surfaces import refresh_static_dynamic_summary_cache
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext
from scytaledroid.Utils.System import output_prefs

from ..core.abort_reasons import classify_exception, normalize_abort_reason
from ..core.models import RunOutcome, RunParameters, ScopeSelection
from ..core.run_context import StaticRunContext
from ..execution import request_abort
from ..execution.static_run_map import REQUIRED_FIELDS
from ..views.view_layouts import render_run_start
from .postprocessing import PostSummaryResult
from .run_events import _emit_phase_log as _run_events_emit_phase_log
from .selection import format_scope_target
from .session_finalizer import refresh_static_session_cache
from .static_run_helpers import (
    modules_for_run as _modules_for_run,
)
from .static_run_helpers import (
    purge_run_cache as _purge_run_cache,
)
from .static_run_helpers import (
    resolve_workers as _resolve_workers,
)


def _effective_run_status(
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


def _emit_phase_log(
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
    """Compatibility facade for phase logging from run_dispatch."""

    from scytaledroid.StaticAnalysis.cli.flows import run_dispatch as _dispatch_phase

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


def launch_scan_flow_resolved(
    selection: ScopeSelection,
    params: RunParameters,
    base_dir: Path,
    *,
    emit_missing_run_ids_artifact: Callable[..., None],
    session_finalization_issues: Callable[..., list[str]],
) -> RunOutcome | None:
    """Execute the static scan using already-resolved parameters."""

    from scytaledroid.StaticAnalysis.cli.flows import run_dispatch as _dispatch

    # Freeze run context once. Deep execution/render paths must not read env vars or
    # mutable output prefs after this point.
    frozen_ctx = StaticRunContext(
        run_mode=output_prefs.effective_run_mode(),
        quiet=output_prefs.effective_quiet(),
        batch=output_prefs.effective_batch(),
        noninteractive=output_prefs.effective_noninteractive(),
        show_splits=output_prefs.effective_show_splits(),
        session_stamp=params.session_stamp,
        persistence_ready=bool(getattr(params, "persistence_ready", True)),
        paper_grade_requested=bool(getattr(params, "paper_grade_requested", True)),
    )
    run_persistence_enabled = _dispatch.persistence_runtime.persistence_enabled(
        dry_run=params.dry_run,
        persistence_ready=bool(params.persistence_ready),
    )

    if run_persistence_enabled:
        _dispatch.persistence_runtime.bootstrap_runtime_persistence(
            session_stamp=params.session_stamp,
            dry_run=params.dry_run,
            persistence_ready=bool(params.persistence_ready),
            strict_persistence=bool(params.strict_persistence),
        )

    workers = _resolve_workers(params.workers)
    if not params.reuse_cache:
        _purge_run_cache()

    modules = _modules_for_run(params)
    scope_target = format_scope_target(selection)
    _dispatch._emit_selection_manifest(selection, params.session_stamp, execution_id=params.execution_id)
    _dispatch._write_execution_marker(params)
    if not (frozen_ctx.quiet and frozen_ctx.batch):
        print()

    workers_label = f"auto ({workers})" if isinstance(params.workers, str) else str(workers)
    if not (frozen_ctx.quiet and frozen_ctx.batch):
        render_run_start(
            profile_label=params.profile_label,
            target=scope_target,
            modules=modules,
            workers_desc=workers_label,
            run_ctx=frozen_ctx,
        )

    # Structured RUN_START log with context
    run_ctx = RunContext(
        subsystem="static",
        device_serial=getattr(selection, "device_serial", None),
        device_model=None,
        run_id=params.session_stamp,
        scope=scope_target,
        profile=params.profile_label,
    )
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
        static_logger = None

    _dispatch.configure_logging_for_cli(params.log_level)

    abort_notified = {"shown": False, "count": 0}

    def _handle_sigint(signum, frame) -> None:  # pragma: no cover - signal path
        abort_notified["count"] += 1
        if not abort_notified["shown"]:
            print(status_messages.status("Interrupt received — stopping safely…", level="warn"))
            print(
                status_messages.status(
                    "Safe stop requested. Current artifact will finish/abort, then partial persistence will run.",
                    level="info",
                )
            )
            abort_notified["shown"] = True
        else:
            print(
                status_messages.status(
                    "Interrupt already requested — waiting for safe stop and partial persistence…",
                    level="warn",
                )
            )
        request_abort(reason="SIGINT", signal="SIGINT")
        try:
            _dispatch._hb_set_phase("aborting", keep_app=True)
        except Exception:
            pass
        _emit_phase_log(
            run_ctx=run_ctx,
            session_stamp=params.session_stamp,
            scope_target=scope_target,
            scope_label=params.scope_label,
            profile_label=params.profile_label,
            execution_id=params.execution_id,
            phase="aborting",
            status="requested",
            extra={
                "abort_reason": "user_abort",
                "abort_signal": "SIGINT",
                "interrupt_count": abort_notified["count"],
                "execution_id": params.execution_id,
            },
        )
        try:
            logger = _dispatch.get_run_logger("static", run_ctx)
            logger.warning(
                "Static RUN_ABORT_REQUESTED",
                extra={
                    "event": log_events.RUN_ABORT_REQUESTED,
                    "run_id": params.session_stamp,
                    "session_stamp": params.session_stamp,
                    "execution_id": params.execution_id,
                    "target": scope_target,
                    "scope_label": params.scope_label,
                    "profile": params.profile_label,
                    "abort_reason": "user_abort",
                    "abort_signal": "SIGINT",
                    "interrupt_count": abort_notified["count"],
                },
            )
        except Exception:
            pass

    previous_handler = None
    sigint_installed = False
    try:
        if threading.current_thread() is threading.main_thread():
            previous_handler = _dispatch.signal.getsignal(_dispatch.signal.SIGINT)
            _dispatch.signal.signal(_dispatch.signal.SIGINT, _handle_sigint)
            sigint_installed = True
    except ValueError as exc:  # pragma: no cover - defensive
        log.warning(f"Skipping SIGINT handler install: {exc}", category="static")

    if params.profile == "permissions":
        print(status_messages.step("Starting permission analysis workflow", label="Static Analysis"))
        try:
            _dispatch.execute_permission_scan(selection, params)
        finally:
            if sigint_installed and previous_handler is not None:
                _dispatch.signal.signal(_dispatch.signal.SIGINT, previous_handler)
        return None

    if params.dry_run:
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
                f"Session: {params.session_stamp}  Profile: {params.profile_label}  "
                f"Scope: {params.scope_label or params.scope}"
            )
        print()
    _dispatch._emit_db_preflight_lock_warning(params=params, run_ctx=frozen_ctx)
    _dispatch._emit_static_run_preflight_summary(params, frozen_ctx=frozen_ctx, base_dir=base_dir)
    outcome: RunOutcome | None = None
    run_status: str | None = None
    abort_reason: str | None = None
    abort_signal: str | None = None
    _dispatch._hb_set_run(params.session_stamp, phase="scan")
    _emit_phase_log(
        run_ctx=run_ctx,
        session_stamp=params.session_stamp,
        scope_target=scope_target,
        scope_label=params.scope_label,
        profile_label=params.profile_label,
        execution_id=params.execution_id,
        phase="scan",
        status="running",
    )
    try:
        outcome = _dispatch.execute_scan(selection, params, base_dir, run_ctx=frozen_ctx)
    finally:
        if sigint_installed and previous_handler is not None:
            _dispatch.signal.signal(_dispatch.signal.SIGINT, previous_handler)
    try:
        if outcome is not None:
            outcome.session_stamp = params.session_stamp
    except Exception:
        pass
    summary_render_failed = False
    post_summary: PostSummaryResult | None = None

    try:
        if outcome is not None:
            run_status = "COMPLETED"
            if outcome.aborted or outcome.failures:
                run_status = "FAILED"
            abort_reason = normalize_abort_reason(outcome.abort_reason or ("SIGINT" if outcome.aborted else None))
            abort_signal = outcome.abort_signal
            if not outcome.aborted:
                _dispatch._hb_set_phase("persist_summary", keep_app=True)
                _emit_phase_log(
                    run_ctx=run_ctx,
                    session_stamp=params.session_stamp,
                    scope_target=scope_target,
                    scope_label=params.scope_label,
                    profile_label=params.profile_label,
                    execution_id=params.execution_id,
                    phase="persist_summary",
                    status="running",
                    extra={
                        "applications": len(outcome.results or []),
                        "artifacts": outcome.total_artifacts,
                        "artifacts_completed": outcome.completed_artifacts,
                    },
                )
                print(
                    status_messages.status(
                        "Scan complete. Persisting findings/risk/session outputs now...",
                        level="info",
                    )
                )
                _dispatch._emit_postprocessing_step("Rendering run summary", run_ctx=frozen_ctx)
            try:
                _dispatch.render_run_results(
                    outcome,
                    params,
                    run_ctx=frozen_ctx,
                    defer_persistence_footer=True,
                    defer_post_run_menu=True,
                )
                run_status = _effective_run_status(
                    outcome,
                    current_status=run_status,
                    summary_render_failed=summary_render_failed,
                )
            except Exception as exc:
                _dispatch._hb_set_phase("failed", keep_app=True)
                _emit_phase_log(
                    run_ctx=run_ctx,
                    session_stamp=params.session_stamp,
                    scope_target=scope_target,
                    scope_label=params.scope_label,
                    profile_label=params.profile_label,
                    execution_id=params.execution_id,
                    phase="persist_summary",
                    status="failed",
                    extra={"abort_reason": "run_summary_render_failed"},
                )
                run_status = "FAILED"
                abort_reason = "run_summary_render_failed"
                summary_render_failed = True
                failure_code = f"run_summary_render_failed:{exc.__class__.__name__}"
                if failure_code not in outcome.failures:
                    outcome.failures.append(failure_code)
                logging_engine.get_error_logger().exception(
                    "Run summary rendering failed",
                    extra=logging_engine.ensure_trace(
                        {
                            "event": "static.run_summary_render_failed",
                            "session_stamp": params.session_stamp,
                            "scope_label": params.scope_label,
                            "profile": params.profile_label,
                        }
                    ),
                )
                print(
                    status_messages.status(
                        (
                            "Run summary finalization failed — static run marked failed. "
                            "Skipping downstream post-processing."
                        ),
                        level="error",
                    )
                )
            if not params.dry_run:
                _dispatch._hb_set_phase("postprocess", keep_app=True)
                _emit_phase_log(
                    run_ctx=run_ctx,
                    session_stamp=params.session_stamp,
                    scope_target=scope_target,
                    scope_label=params.scope_label,
                    profile_label=params.profile_label,
                    execution_id=params.execution_id,
                    phase="postprocess",
                    status="running",
                )
                post_summary = _dispatch.run_post_summary_postprocessing(
                    outcome=outcome,
                    params=params,
                    selection=selection,
                    run_ctx=frozen_ctx,
                    summary_render_failed=summary_render_failed,
                    required_fields=REQUIRED_FIELDS,
                    emit_postprocessing_step=(
                        _dispatch._emit_postprocessing_step
                        if not outcome.aborted
                        else (lambda *args, **kwargs: None)
                    ),
                    build_session_run_map=_dispatch._build_session_run_map,
                    validate_run_map=_dispatch.validate_run_map,
                    persist_session_run_links=_dispatch._persist_session_run_links,
                    emit_missing_run_ids_artifact=emit_missing_run_ids_artifact,
                    execute_permission_scan=_dispatch.execute_permission_scan,
                    emit_phase_transition=lambda phase, status=None, extra=None: _emit_phase_log(
                        run_ctx=run_ctx,
                        session_stamp=params.session_stamp,
                        scope_target=scope_target,
                        scope_label=params.scope_label,
                        profile_label=params.profile_label,
                        execution_id=params.execution_id,
                        phase=phase,
                        status=status,
                        extra=extra,
                    ),
                )
                if post_summary.permission_refresh_error is not None:
                    _dispatch._hb_set_phase("failed", keep_app=True)
                    _emit_phase_log(
                        run_ctx=run_ctx,
                        session_stamp=params.session_stamp,
                        scope_target=scope_target,
                        scope_label=params.scope_label,
                        profile_label=params.profile_label,
                        execution_id=params.execution_id,
                        phase="postprocess",
                        status="failed",
                        extra={"abort_reason": "permission_snapshot_refresh_failed"},
                    )
                    run_status = "FAILED"
                    abort_reason = "permission_snapshot_refresh_failed"
                    logging_engine.get_error_logger().exception(
                        "Permission snapshot refresh failed",
                        extra=logging_engine.ensure_trace(
                            {
                                "event": "static.permission_snapshot_refresh_failed",
                                "session_stamp": params.session_stamp,
                                "scope_label": params.scope_label,
                                "profile": params.profile_label,
                            }
                        ),
                    )
                    print(
                        status_messages.status(
                            (
                                "Permission snapshot refresh failed — static run marked failed. "
                                "See logs for details."
                            ),
                            level="error",
                        )
                    )
            run_status = _effective_run_status(
                outcome,
                current_status=run_status,
                summary_render_failed=summary_render_failed,
            )
    except Exception as exc:
        _dispatch._hb_set_phase("failed", keep_app=True)
        _emit_phase_log(
            run_ctx=run_ctx,
            session_stamp=params.session_stamp,
            scope_target=scope_target,
            scope_label=params.scope_label,
            profile_label=params.profile_label,
            execution_id=params.execution_id,
            phase="runtime_exception",
            status="failed",
            extra={"abort_reason": classify_exception(exc)},
        )
        run_status = "FAILED"
        abort_reason = classify_exception(exc)
        if outcome is not None:
            failure_code = f"postprocess_exception:{exc.__class__.__name__}"
            if failure_code not in outcome.failures:
                outcome.failures.append(failure_code)
        raise
    finally:
        finalization_issues = session_finalization_issues(
            outcome=outcome,
            session_stamp=params.session_stamp,
            post_summary=post_summary,
            summary_render_failed=summary_render_failed,
            persistence_ready=bool(params.persistence_ready),
            dry_run=bool(params.dry_run),
        )
        if outcome is not None and finalization_issues:
            for issue in finalization_issues:
                if issue not in outcome.failures:
                    outcome.failures.append(issue)
            run_status = "FAILED"
            abort_reason = abort_reason or "session_finalization_incomplete"
            print(
                status_messages.status(
                    "Session finalization incomplete — run marked failed. "
                    f"Issues: {', '.join(finalization_issues)}",
                    level="error",
                )
            )

        run_status = _effective_run_status(
            outcome,
            current_status=run_status,
            summary_render_failed=summary_render_failed,
        )
        if outcome is not None and not params.dry_run and run_status:
            static_run_ids = [
                result.static_run_id
                for result in outcome.results
                if result.static_run_id
            ]
            # Recovery: persistence failures may null out static_run_id on app results
            # after a STARTED row was created. Close any lingering STARTED rows for
            # this session stamp so dashboards do not accumulate phantom open runs.
            if params.session_stamp:
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
                        (params.session_stamp,),
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
            if static_run_ids:
                static_run_ids = sorted(set(int(sid) for sid in static_run_ids if sid))
                ended_at = outcome.finished_at.isoformat(timespec="seconds") + "Z"
                _dispatch.finalize_open_runs(
                    static_run_ids,
                    status=run_status,
                    ended_at_utc=ended_at,
                    abort_reason=normalize_abort_reason(abort_reason),
                    abort_signal=abort_signal,
                )

    if run_persistence_enabled and params.session_stamp and outcome is not None:
        if not outcome.aborted:
            _dispatch._hb_set_phase("refresh_views", keep_app=True)
            _emit_phase_log(
                run_ctx=run_ctx,
                session_stamp=params.session_stamp,
                scope_target=scope_target,
                scope_label=params.scope_label,
                profile_label=params.profile_label,
                execution_id=params.execution_id,
                phase="refresh_views",
                status="running",
            )
            _dispatch._emit_postprocessing_step("Refreshing canonical session views", run_ctx=frozen_ctx)
        try:
            _dispatch.persistence_runtime.refresh_session_views(
                session_stamp=params.session_stamp,
                dry_run=params.dry_run,
                persistence_ready=bool(params.persistence_ready),
            )
        except Exception:
            pass
        try:
            refresh_static_session_cache(
                refresh_cache=refresh_static_dynamic_summary_cache,
            )
        except Exception:
            pass
        canonical_failures = [
            str(note.get("message") or "")
            for note in getattr(outcome, "audit_notes", []) or []
            if isinstance(note, dict)
            and str(note.get("code") or "").strip().lower() == "canonical_error"
            and str(note.get("message") or "").strip()
        ]
        if not outcome.aborted:
            _dispatch._render_persistence_footer(
                params.session_stamp,
                had_errors=bool(
                    getattr(outcome, "persistence_failed", False)
                    or getattr(outcome, "compat_export_failed", False)
                ),
                canonical_failures=canonical_failures,
                run_status=run_status,
                abort_reason=abort_reason,
                abort_signal=abort_signal,
            )
            _dispatch._emit_static_persistence_event(
                event=log_events.PERSIST_END,
                message="Static persistence finished",
                params=params,
                extra={
                    "applications": len(outcome.results or []),
                    "findings_persisted_total": None,
                    "string_samples_persisted_total": None,
                    "persistence_error_count": len(list(dict.fromkeys(getattr(outcome, 'failures', []) or []))),
                    "canonical_failure_count": len(canonical_failures),
                    "compat_export_failed": bool(getattr(outcome, "compat_export_failed", False)),
                    "status": "failed" if (run_status or "").upper() != "COMPLETED" else "completed",
                },
            )
        if outcome.results and not summary_render_failed and not outcome.aborted:
            _dispatch._persist_cohort_rollup(params.session_stamp, params.scope_label)

    if outcome is not None and not params.dry_run and not outcome.aborted:
        _dispatch.prompt_deferred_post_run_diagnostics(outcome, params)

    if outcome is not None and run_status:
        _dispatch._hb_set_phase("completed" if run_status == "COMPLETED" else "failed", keep_app=True)
        _emit_phase_log(
            run_ctx=run_ctx,
            session_stamp=params.session_stamp,
            scope_target=scope_target,
            scope_label=params.scope_label,
            profile_label=params.profile_label,
            execution_id=params.execution_id,
            phase="completed" if run_status == "COMPLETED" else "failed",
            status=run_status.lower(),
            extra={
                "abort_reason": abort_reason,
                "abort_signal": abort_signal,
                "applications": len(outcome.results or []) if outcome is not None else None,
                "artifacts": outcome.total_artifacts if outcome is not None else None,
                "artifacts_completed": outcome.completed_artifacts if outcome is not None else None,
            },
        )

    # Emit RUN_END after required persistence/postprocessing/view refresh work so
    # the lifecycle record reflects the actual terminal state of the run.
    if params.session_stamp:
        end_payload = {
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
        try:
            static_logger = _dispatch.get_run_logger("static", run_ctx)
            static_logger.info("Static RUN_END", extra=end_payload)
        except Exception:
            try:
                logger = logging_engine.get_static_logger()
                logger.info("Static RUN_END", extra=logging_engine.ensure_trace(end_payload))
            except Exception:
                pass

    return outcome
