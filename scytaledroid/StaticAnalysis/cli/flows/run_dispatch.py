"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

import json
import os
import shutil
import signal
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.summary_surfaces import refresh_static_dynamic_summary_cache
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger
from scytaledroid.Utils.System import output_prefs

from ..core.abort_reasons import classify_exception, normalize_abort_reason
from ..core.analysis_profiles import run_modules_for_profile
from ..core.models import RunOutcome, RunParameters, ScopeSelection
from ..core.run_context import StaticRunContext
from ..core.run_lifecycle import finalize_open_runs
from ..core.run_specs import StaticRunSpec
from ..execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    render_run_results,
    request_abort,
)
from ..execution.heartbeat_state import set_phase as _hb_set_phase
from ..execution.heartbeat_state import set_run as _hb_set_run
from ..execution.db_verification import _render_persistence_footer
from ..execution.results import _emit_static_persistence_event, prompt_deferred_post_run_diagnostics
from ..execution.results_persist import _persist_cohort_rollup
from ..execution.static_run_map import REQUIRED_FIELDS, validate_run_map
from ..views.view_layouts import render_run_start
from .postprocessing import PostSummaryResult, run_post_summary_postprocessing
from .session_finalizer import emit_persistence_audit_artifact, refresh_static_session_cache
from . import persistence_runtime
from .selection import format_scope_target
from .run_events import (
    _emit_db_preflight_lock_warning,
    _emit_phase_log as _run_events_emit_phase_log,
    _emit_postprocessing_step,
)
from .run_locking import (
    _acquire_static_run_lock,
    _release_static_run_lock,
    _write_execution_marker,
)
from .run_persistence_audit import _build_persistence_audit_summary
from .run_selection_manifest import _emit_selection_manifest
from .run_session_map import (
    _build_session_run_map,
    _detect_duplicate_packages,
    _rebuild_session_run_map_from_db,
    _session_completed_run_count,
    _session_run_link_count,
    _session_run_map_path,
    _persist_session_run_links,
)


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
        logger = get_run_logger("static", run_ctx)
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


def _emit_missing_run_ids_artifact(
    *,
    outcome: RunOutcome,
    session_stamp: str | None,
    linkage_blocked_reason: str | None,
    missing_id_packages: list[str],
) -> None:
    """Compatibility facade so callers can patch run_dispatch.db_diagnostics."""

    emit_persistence_audit_artifact(
        outcome=outcome,
        session_stamp=session_stamp,
        linkage_blocked_reason=linkage_blocked_reason,
        missing_id_packages=missing_id_packages,
        db_schema_version=db_diagnostics.get_schema_version() or "<unknown>",
        build_summary=lambda current_outcome, stamp: _build_persistence_audit_summary(
            outcome=current_outcome,
            session_stamp=stamp,
        ),
        lock_health_snapshot=db_diagnostics.get_lock_health_snapshot,
        output_dir="output",
    )


def _ensure_session_finalization_outputs(session_stamp: str | None) -> list[str]:
    """Compatibility facade for session finalization patch points."""

    stamp = str(session_stamp or "").strip()
    if not stamp:
        return []

    issues: list[str] = []
    run_map_path = _session_run_map_path(stamp)
    expected_count = _session_completed_run_count(stamp)
    link_count = _session_run_link_count(stamp)

    if (run_map_path and run_map_path.exists()) and link_count >= expected_count > 0:
        return issues

    try:
        rebuilt_run_map = _rebuild_session_run_map_from_db(stamp)
        if rebuilt_run_map is not None and _session_run_link_count(stamp) < max(
            expected_count,
            len(rebuilt_run_map.get("apps", [])),
        ):
            _persist_session_run_links(stamp, rebuilt_run_map)

        if run_map_path and not run_map_path.exists():
            issues.append("run_map_missing")

        final_link_count = _session_run_link_count(stamp)
        if expected_count > 0 and final_link_count < expected_count:
            issues.append("session_links_incomplete")
        elif final_link_count == 0:
            issues.append("session_links_missing")
    except Exception:
        if run_map_path and not run_map_path.exists():
            issues.append("run_map_missing")

        final_link_count = _session_run_link_count(stamp)
        if expected_count > 0 and final_link_count < expected_count:
            issues.append("session_links_incomplete")
        elif final_link_count == 0:
            issues.append("session_links_missing")

    return issues


def _session_finalization_issues(
    *,
    outcome: RunOutcome | None,
    session_stamp: str | None,
    post_summary: object | None,
    summary_render_failed: bool,
    persistence_ready: bool,
    dry_run: bool = False,
) -> list[str]:
    """Return session-finalization issues using run_dispatch patch points."""

    if dry_run:
        return []
    if outcome is None or not session_stamp or summary_render_failed or outcome.aborted or not persistence_ready:
        return []
    if not (outcome.results or []):
        return []
    if post_summary is not None and getattr(post_summary, "linkage_blocked_reason", None):
        return ["session_linkage_blocked"]
    return _ensure_session_finalization_outputs(session_stamp)


@dataclass(frozen=True)
class RunExecutionResult:
    """Execution result plus the effective parameters used for the run."""

    outcome: RunOutcome | None
    params: RunParameters
    completed: bool
    detail: str | None = None


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


def _resolve_effective_run_params(
    params: RunParameters,
    *,
    run_mode: str,
    noninteractive: bool,
    quiet: bool,
) -> tuple[RunParameters | None, str | None]:
    """Resolve session identity and persistence readiness before execution."""

    previous_stamp = (params.session_stamp or "").strip()
    session_stamp = make_session_stamp()
    if previous_stamp and session_stamp == previous_stamp:
        session_stamp = make_session_stamp()
    # Enforce unique session per run unless explicitly set by caller.
    if not previous_stamp:
        params = replace(params, session_stamp=session_stamp)
    desired_session_stamp = params.session_stamp or session_stamp
    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            reason = "character safety"
            if len(normalized) != len(params.session_stamp):
                reason = "length safety"
            if not output_prefs.effective_quiet():
                print(
                    status_messages.status(
                        (
                            "Session label normalized for cross-table "
                            f"{reason} ({len(params.session_stamp)}→{len(normalized)} chars): "
                            f"'{params.session_stamp}' → '{normalized}'."
                        ),
                        level="warn",
                    )
                )
            params = replace(params, session_stamp=normalized)
            desired_session_stamp = normalized
    try:
        resolved_stamp, session_label, canonical_action = _resolve_unique_session_stamp(
            desired_session_stamp,
            run_mode=run_mode,
            noninteractive=noninteractive,
            quiet=quiet,
            canonical_action=params.canonical_action,
        )
        params = replace(
            params,
            session_stamp=resolved_stamp,
            session_label=session_label,
            canonical_action=canonical_action,
        )
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return None, str(exc)
    # Honor output prefs when execute_run_spec has already set them.
    output_prefs.set_verbose(bool(params.verbose_output))

    persistence_ready, persistence_note = _check_static_persistence_readiness(params)
    # Freeze persistence readiness into the run parameters for this run. We avoid mutating
    # process env mid-run to keep execution deterministic and auditable.
    params = replace(params, persistence_ready=bool(persistence_ready))
    if not persistence_ready:
        level = "error" if params.strict_persistence or params.paper_grade_requested else "warn"
        print(status_messages.status(persistence_note, level=level))
        if (params.strict_persistence or params.paper_grade_requested) and not params.dry_run:
            print(
                status_messages.status(
                    (
                        "Canonical-grade runs require canonical schema readiness. "
                        "Run schema bootstrap or set SCYTALEDROID_CANONICAL_GRADE=0 "
                        "to allow experimental runs."
                    ),
                    level="error",
                )
            )
            print(
                status_messages.status(
                    "Menu path: Database tools → Apply canonical schema bootstrap",
                    level="info",
                )
            )
            return None, (
                f"{persistence_note} Canonical-grade runs require canonical schema readiness."
            )

    return params, None


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome | None:
    """Primary entry point for running static analysis flows from the CLI."""

    effective_params, _ = _resolve_effective_run_params(
        params,
        run_mode=output_prefs.effective_run_mode(),
        noninteractive=output_prefs.effective_noninteractive(),
        quiet=output_prefs.effective_quiet(),
    )
    if effective_params is None:
        return None
    lock_path: Path | None = None
    try:
        lock_path = _acquire_static_run_lock(effective_params)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return None
    try:
        return _launch_scan_flow_resolved(selection, effective_params, base_dir)
    finally:
        _release_static_run_lock(lock_path)


def _launch_scan_flow_resolved(
    selection: ScopeSelection,
    params: RunParameters,
    base_dir: Path,
) -> RunOutcome | None:
    """Execute the static scan using already-resolved parameters."""

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
    run_persistence_enabled = persistence_runtime.persistence_enabled(
        dry_run=params.dry_run,
        persistence_ready=bool(params.persistence_ready),
    )

    if run_persistence_enabled:
        persistence_runtime.bootstrap_runtime_persistence(
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
    _emit_selection_manifest(selection, params.session_stamp, execution_id=params.execution_id)
    _write_execution_marker(params)
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
        static_logger = get_run_logger("static", run_ctx)
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

    configure_logging_for_cli(params.log_level)

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
            _hb_set_phase("aborting", keep_app=True)
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
            logger = get_run_logger("static", run_ctx)
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
            previous_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, _handle_sigint)
            sigint_installed = True
    except ValueError as exc:  # pragma: no cover - defensive
        log.warning(f"Skipping SIGINT handler install: {exc}", category="static")

    if params.profile == "permissions":
        print(status_messages.step("Starting permission analysis workflow", label="Static Analysis"))
        try:
            execute_permission_scan(selection, params)
        finally:
            if sigint_installed and previous_handler is not None:
                signal.signal(signal.SIGINT, previous_handler)
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
    _emit_db_preflight_lock_warning(params=params, run_ctx=frozen_ctx)
    outcome: RunOutcome | None = None
    run_status: str | None = None
    abort_reason: str | None = None
    abort_signal: str | None = None
    _hb_set_run(params.session_stamp, phase="scan")
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
        outcome = execute_scan(selection, params, base_dir, run_ctx=frozen_ctx)
    finally:
        if sigint_installed and previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)
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
                _hb_set_phase("persist_summary", keep_app=True)
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
                _emit_postprocessing_step("Rendering run summary", run_ctx=frozen_ctx)
            try:
                render_run_results(
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
                _hb_set_phase("failed", keep_app=True)
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
                _hb_set_phase("postprocess", keep_app=True)
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
                post_summary = run_post_summary_postprocessing(
                    outcome=outcome,
                    params=params,
                    selection=selection,
                    run_ctx=frozen_ctx,
                    summary_render_failed=summary_render_failed,
                    required_fields=REQUIRED_FIELDS,
                    emit_postprocessing_step=(
                        _emit_postprocessing_step
                        if not outcome.aborted
                        else (lambda *args, **kwargs: None)
                    ),
                    build_session_run_map=_build_session_run_map,
                    validate_run_map=validate_run_map,
                    persist_session_run_links=_persist_session_run_links,
                    emit_missing_run_ids_artifact=_emit_missing_run_ids_artifact,
                    execute_permission_scan=execute_permission_scan,
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
                    _hb_set_phase("failed", keep_app=True)
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
        _hb_set_phase("failed", keep_app=True)
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
        finalization_issues = _session_finalization_issues(
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
                finalize_open_runs(
                    static_run_ids,
                    status=run_status,
                    ended_at_utc=ended_at,
                    abort_reason=normalize_abort_reason(abort_reason),
                    abort_signal=abort_signal,
                )

    if run_persistence_enabled and params.session_stamp and outcome is not None:
        if not outcome.aborted:
            _hb_set_phase("refresh_views", keep_app=True)
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
            _emit_postprocessing_step("Refreshing canonical session views", run_ctx=frozen_ctx)
        try:
            persistence_runtime.refresh_session_views(
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
            _render_persistence_footer(
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
            _emit_static_persistence_event(
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
            _persist_cohort_rollup(params.session_stamp, params.scope_label)

    if outcome is not None and not params.dry_run and not outcome.aborted:
        prompt_deferred_post_run_diagnostics(outcome, params)

    if outcome is not None and run_status:
        _hb_set_phase("completed" if run_status == "COMPLETED" else "failed", keep_app=True)
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
                "applications": len((outcome.results or [])) if outcome is not None else None,
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
            static_logger = get_run_logger("static", run_ctx)
            static_logger.info("Static RUN_END", extra=end_payload)
        except Exception:
            try:
                logger = logging_engine.get_static_logger()
                logger.info("Static RUN_END", extra=logging_engine.ensure_trace(end_payload))
            except Exception:
                pass

    return outcome


def execute_run_spec_detailed(spec: StaticRunSpec) -> RunExecutionResult:
    """Execute a prepared run spec and return the effective params plus completion state."""

    prev_prefs = output_prefs.snapshot()
    prev_ctx = output_prefs.get_run_context()
    from scytaledroid.StaticAnalysis.engine.strings_runtime import get_config as _get_strings_cfg
    from scytaledroid.StaticAnalysis.engine.strings_runtime import set_config as _set_strings_cfg
    prev_strings_cfg = _get_strings_cfg()
    output_prefs.set_quiet(spec.quiet)
    output_prefs.set_batch(spec.run_mode == "batch" or spec.noninteractive)
    output_prefs.set_run_mode(spec.run_mode)
    output_prefs.set_noninteractive(spec.noninteractive)
    output_prefs.set_show_splits(bool(spec.params.show_split_summaries))
    from ..core.run_context import build_static_run_context
    output_prefs.set_run_context(build_static_run_context(spec))
    _set_strings_cfg(
        _get_strings_cfg().__class__(
            include_https_risk=bool(spec.params.string_include_https_risk),
            debug=bool(spec.params.string_debug),
            skip_resources_on_arsc_warn=bool(spec.params.string_skip_resources_on_warn),
            long_string_length=int(spec.params.string_long_string_length),
            low_entropy_threshold=float(spec.params.string_low_entropy_threshold),
        )
    )
    try:
        effective_params, detail = _resolve_effective_run_params(
            spec.params,
            run_mode=spec.run_mode,
            noninteractive=spec.noninteractive,
            quiet=spec.quiet,
        )
        if effective_params is None:
            return RunExecutionResult(
                outcome=None,
                params=spec.params,
                completed=False,
                detail=detail,
            )
        output_prefs.set_run_context(build_static_run_context(replace(spec, params=effective_params)))
        try:
            lock_path = _acquire_static_run_lock(effective_params)
        except RuntimeError as exc:
            print(status_messages.status(str(exc), level="error"))
            return RunExecutionResult(
                outcome=None,
                params=effective_params,
                completed=False,
                detail=str(exc),
            )
        try:
            outcome = _launch_scan_flow_resolved(spec.selection, effective_params, spec.base_dir)
        finally:
            _release_static_run_lock(lock_path)
        if outcome is not None and not bool(getattr(effective_params, "dry_run", False)):
            try:
                cache_result = refresh_static_session_cache(
                    refresh_cache=refresh_static_dynamic_summary_cache,
                )
                log.info(
                    "Refreshed static/dynamic summary cache "
                    f"(rows={cache_result.cache_rows} materialized_at={cache_result.cache_materialized_at})",
                    category="static_analysis",
                )
            except Exception as exc:
                log.warning(
                    f"Static analysis completed but summary cache refresh failed: {exc}",
                    category="static_analysis",
                )
        return RunExecutionResult(
            outcome=outcome,
            params=effective_params,
            completed=True,
            detail=detail,
        )
    finally:
        output_prefs.restore(prev_prefs)
        output_prefs.set_run_context(prev_ctx)
        _set_strings_cfg(prev_strings_cfg)


def execute_run_spec(spec: StaticRunSpec) -> RunOutcome | None:
    """Execute a prepared run spec without prompting."""

    return execute_run_spec_detailed(spec).outcome


def _modules_for_run(params: RunParameters) -> tuple[str, ...]:
    return run_modules_for_profile(params.profile)


def _resolve_workers(value: str | int) -> int:
    if isinstance(value, int):
        return max(1, value)
    text = (value or "").strip().lower()
    if text.isdigit():
        return max(1, int(text))
    return max(1, os.cpu_count() or 1)


def _purge_run_cache() -> None:
    cache_roots = [
        Path(app_config.DATA_DIR) / "static_analysis" / "cache",
        Path(app_config.DATA_DIR) / "static_analysis" / "tmp",
    ]
    for root in cache_roots:
        try:
            if root.exists():
                shutil.rmtree(root)
        except OSError:
            continue


def _check_static_persistence_readiness(params: RunParameters) -> tuple[bool, str]:
    if params.dry_run:
        return True, "dry-run: persistence gate skipped"
    ok_base, msg_base, detail_base = schema_gate.check_base_schema()
    if not ok_base:
        detail = f" {detail_base}" if detail_base else ""
        return False, f"{msg_base}{detail}"
    ok_static, msg_static, detail_static = schema_gate.static_schema_gate()
    if not ok_static:
        detail = f" {detail_static}" if detail_static else ""
        return False, f"{msg_static}{detail}"
    return True, "OK"


def _resolve_unique_session_stamp(
    session_stamp: str,
    *,
    run_mode: str,
    noninteractive: bool,
    quiet: bool,
    canonical_action: str | None,
) -> tuple[str, str, str]:
    base_stamp = session_stamp
    session_dir = Path(app_config.DATA_DIR) / "sessions"
    final_path = session_dir / base_stamp / "run_map.json"
    attempts = None
    canonical_id = None
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s
            """,
            (base_stamp,),
            fetch="one",
        )
        attempts = int(row[0]) if row and row[0] is not None else 0
        row = core_q.run_sql(
            """
            SELECT id
            FROM static_analysis_runs
            WHERE session_label=%s AND is_canonical=1
            ORDER BY canonical_set_at_utc DESC
            LIMIT 1
            """,
            (base_stamp,),
            fetch="one",
        )
        if row and row[0] is not None:
            canonical_id = int(row[0])
    except Exception:
        attempts = None
        canonical_id = None
    # A local run_map may be missing after reset/cleanup while DB attempts still exist.
    # Treat either source as "session already used".
    has_local_session = final_path.exists()
    has_db_attempts = isinstance(attempts, int) and attempts > 0
    if not has_local_session and not has_db_attempts:
        return base_stamp, base_stamp, "first_run"
    batch_mode = (run_mode == "batch")
    if batch_mode or noninteractive:
        suffix = None
        if attempts is not None and attempts >= 0:
            suffix = f"{attempts + 1}"
        if not suffix:
            suffix = datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        return new_stamp, new_stamp, "auto_suffix"
    # Interactive mode must not prompt inside execution. The menu layer should
    # resolve collisions into a canonical_action and/or a unique session_stamp.
    action = (canonical_action or "").strip().lower()
    if action in {"append", "auto_suffix"}:
        suffix = f"{attempts + 1}" if isinstance(attempts, int) else datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        return new_stamp, new_stamp, "append"
    if action == "":
        suffix = f"{attempts + 1}" if isinstance(attempts, int) else datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        if not quiet:
            print(
                status_messages.status(
                    (
                        f"Session label {base_stamp} already exists; "
                        f"auto-suffixing to {new_stamp}."
                    ),
                    level="warn",
                )
            )
        return new_stamp, new_stamp, "auto_suffix"
    if action in {"replace", "overwrite"}:
        try:
            archive_dir = session_dir / "_archive"
            archive_dir.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
                archive_path = archive_dir / f"{base_stamp}-{timestamp}.run_map.json"
                shutil.copy2(final_path, archive_path)
            if not quiet:
                print(
                    status_messages.status(
                        "Replace mode: deleting local session folder only (DB history preserved).",
                        level="info",
                    )
                )
                if canonical_id:
                    print(
                        status_messages.status(
                            f"Previous canonical attempt: static_run_id={canonical_id}",
                            level="info",
                        )
                    )
            shutil.rmtree(session_dir / base_stamp)
        except Exception as exc:
            raise RuntimeError(f"Failed to replace existing session metadata: {exc}") from exc
        return base_stamp, base_stamp, "replace"
    if action in {"cancel", "abort"}:
        raise RuntimeError(f"Session label already used: {base_stamp}. Cancelled by caller.")
    raise RuntimeError(
        
            f"Session label already used: {base_stamp}. "
            "Resolve this in the menu layer (replace or append) before execution."
        
    )


__all__ = [
    "launch_scan_flow",
    "execute_run_spec",
    "execute_run_spec_detailed",
    "configure_logging_for_cli",
    "execute_scan",
    "execute_permission_scan",
    "generate_report",
    "build_analysis_config",
    "render_run_results",
    "format_duration",
]
