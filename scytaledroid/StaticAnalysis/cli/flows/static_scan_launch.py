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
from ..execution.static_run_map import REQUIRED_FIELDS
from ..views.view_layouts import render_run_start
from .postprocessing import PostSummaryResult
from .static_scan_constants import (
    PHASE_COMPLETED,
    PHASE_FAILED,
    PHASE_PERSIST_SUMMARY,
    PHASE_POSTPROCESS,
    PHASE_REFRESH_VIEWS,
    PHASE_RUNTIME_EXCEPTION,
    PHASE_SCAN,
)
from .static_scan_lifecycle import (
    collect_static_run_ids_for_finalize,
    effective_static_run_status,
    emit_static_dry_run_banner,
    emit_static_run_end_log,
    emit_static_run_phase_log,
    emit_static_run_start_log,
)
from .static_scan_signals import build_static_scan_sigint_handler
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
    workers = _resolve_workers(params.workers)
    frozen_ctx = StaticRunContext(
        run_mode=output_prefs.effective_run_mode(),
        quiet=output_prefs.effective_quiet(),
        batch=output_prefs.effective_batch(),
        noninteractive=output_prefs.effective_noninteractive(),
        show_splits=output_prefs.effective_show_splits(),
        session_stamp=params.session_stamp,
        persistence_ready=bool(getattr(params, "persistence_ready", True)),
        paper_grade_requested=bool(getattr(params, "paper_grade_requested", True)),
        resolved_worker_count=int(workers),
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
    emit_static_run_start_log(
        run_ctx=run_ctx,
        frozen_ctx=frozen_ctx,
        params=params,
        modules=modules,
        workers_label=workers_label,
        scope_target=scope_target,
    )

    _dispatch.configure_logging_for_cli(params.log_level)

    _handle_sigint, _abort_sig_state = build_static_scan_sigint_handler(
        dispatch=_dispatch,
        run_ctx=run_ctx,
        params=params,
        scope_target=scope_target,
    )

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
        emit_static_dry_run_banner(params)
    _dispatch._emit_db_preflight_lock_warning(params=params, run_ctx=frozen_ctx)
    _dispatch._emit_static_run_preflight_summary(
        params,
        frozen_ctx=frozen_ctx,
        base_dir=base_dir,
        selection=selection,
    )
    outcome: RunOutcome | None = None
    run_status: str | None = None
    abort_reason: str | None = None
    abort_signal: str | None = None
    _dispatch._hb_set_run(params.session_stamp, phase=PHASE_SCAN)
    emit_static_run_phase_log(
        run_ctx=run_ctx,
        session_stamp=params.session_stamp,
        scope_target=scope_target,
        scope_label=params.scope_label,
        profile_label=params.profile_label,
        execution_id=params.execution_id,
        phase=PHASE_SCAN,
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
                _dispatch._hb_set_phase(PHASE_PERSIST_SUMMARY, keep_app=True)
                emit_static_run_phase_log(
                    run_ctx=run_ctx,
                    session_stamp=params.session_stamp,
                    scope_target=scope_target,
                    scope_label=params.scope_label,
                    profile_label=params.profile_label,
                    execution_id=params.execution_id,
                    phase=PHASE_PERSIST_SUMMARY,
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
                run_status = effective_static_run_status(
                    outcome,
                    current_status=run_status,
                    summary_render_failed=summary_render_failed,
                )
            except Exception as exc:
                _dispatch._hb_set_phase(PHASE_FAILED, keep_app=True)
                emit_static_run_phase_log(
                    run_ctx=run_ctx,
                    session_stamp=params.session_stamp,
                    scope_target=scope_target,
                    scope_label=params.scope_label,
                    profile_label=params.profile_label,
                    execution_id=params.execution_id,
                    phase=PHASE_PERSIST_SUMMARY,
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
                _dispatch._hb_set_phase(PHASE_POSTPROCESS, keep_app=True)
                emit_static_run_phase_log(
                    run_ctx=run_ctx,
                    session_stamp=params.session_stamp,
                    scope_target=scope_target,
                    scope_label=params.scope_label,
                    profile_label=params.profile_label,
                    execution_id=params.execution_id,
                    phase=PHASE_POSTPROCESS,
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
                    emit_phase_transition=lambda phase, status=None, extra=None: emit_static_run_phase_log(
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
                    _dispatch._hb_set_phase(PHASE_FAILED, keep_app=True)
                    emit_static_run_phase_log(
                        run_ctx=run_ctx,
                        session_stamp=params.session_stamp,
                        scope_target=scope_target,
                        scope_label=params.scope_label,
                        profile_label=params.profile_label,
                        execution_id=params.execution_id,
                        phase=PHASE_POSTPROCESS,
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
            run_status = effective_static_run_status(
                outcome,
                current_status=run_status,
                summary_render_failed=summary_render_failed,
            )
    except Exception as exc:
        _dispatch._hb_set_phase(PHASE_FAILED, keep_app=True)
        emit_static_run_phase_log(
            run_ctx=run_ctx,
            session_stamp=params.session_stamp,
            scope_target=scope_target,
            scope_label=params.scope_label,
            profile_label=params.profile_label,
            execution_id=params.execution_id,
            phase=PHASE_RUNTIME_EXCEPTION,
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

        run_status = effective_static_run_status(
            outcome,
            current_status=run_status,
            summary_render_failed=summary_render_failed,
        )
        if outcome is not None and not params.dry_run and run_status:
            static_run_ids = collect_static_run_ids_for_finalize(outcome, params.session_stamp)
            if static_run_ids:
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
            _dispatch._hb_set_phase(PHASE_REFRESH_VIEWS, keep_app=True)
            emit_static_run_phase_log(
                run_ctx=run_ctx,
                session_stamp=params.session_stamp,
                scope_target=scope_target,
                scope_label=params.scope_label,
                profile_label=params.profile_label,
                execution_id=params.execution_id,
                phase=PHASE_REFRESH_VIEWS,
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

        if (
            run_persistence_enabled
            and outcome is not None
            and not outcome.aborted
            and not params.dry_run
            and params.session_stamp
            and bool(params.persistence_ready)
            and outcome.results
            and not summary_render_failed
            and str(run_status or "").upper() == "COMPLETED"
        ):
            from ..execution.post_run_cohort_quick_check import (
                maybe_emit_post_run_grain_summary,
                merge_post_run_grain_into_run_health_json,
            )

            maybe_emit_post_run_grain_summary(
                params.session_stamp,
                scope_label=params.scope_label,
                run_ctx=frozen_ctx,
                run_aggregate_status=getattr(outcome, "run_aggregate_status", None),
                session_metrics=outcome.session_metrics,
            )
            merge_post_run_grain_into_run_health_json(outcome)

    if outcome is not None and not params.dry_run and not outcome.aborted:
        _dispatch.prompt_deferred_post_run_diagnostics(outcome, params)

    if outcome is not None and run_status:
        _dispatch._hb_set_phase(PHASE_COMPLETED if run_status == "COMPLETED" else PHASE_FAILED, keep_app=True)
        emit_static_run_phase_log(
            run_ctx=run_ctx,
            session_stamp=params.session_stamp,
            scope_target=scope_target,
            scope_label=params.scope_label,
            profile_label=params.profile_label,
            execution_id=params.execution_id,
            phase=PHASE_COMPLETED if run_status == "COMPLETED" else PHASE_FAILED,
            status=run_status.lower(),
            extra={
                "abort_reason": abort_reason,
                "abort_signal": abort_signal,
                "applications": len(outcome.results or []) if outcome is not None else None,
                "artifacts": outcome.total_artifacts if outcome is not None else None,
                "artifacts_completed": outcome.completed_artifacts if outcome is not None else None,
            },
        )

    emit_static_run_end_log(
        run_ctx=run_ctx,
        params=params,
        outcome=outcome,
        modules=modules,
        scope_target=scope_target,
        run_status=run_status,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
        summary_render_failed=summary_render_failed,
    )

    return outcome
