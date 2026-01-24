"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
from dataclasses import replace

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import summary_cards, status_messages
from scytaledroid.Utils.System import output_prefs
from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.ui import formatter
from ..views.view_layouts import render_run_start, render_run_summary
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger
from scytaledroid.Utils.LoggingUtils import logging_events as log_events

from ..execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    request_abort,
    render_run_results,
)
from ..core.models import RunParameters, RunOutcome, ScopeSelection
from ..core.run_lifecycle import finalize_open_runs
from ..core.analysis_profiles import run_modules_for_profile
from .selection import format_scope_target


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome | None:
    """Primary entry point for running static analysis flows from the CLI."""

    previous_stamp = (params.session_stamp or "").strip()
    session_stamp = make_session_stamp()
    if previous_stamp and session_stamp == previous_stamp:
        session_stamp = make_session_stamp()
    # Enforce unique session per run unless explicitly set by caller.
    if not previous_stamp:
        params = replace(params, session_stamp=session_stamp)
    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            reason = "character safety"
            if len(normalized) != len(params.session_stamp):
                reason = "length safety"
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
    output_prefs.set_verbose(bool(params.verbose_output))

    try:
        canonical_ingest.ensure_provider_plumbing()
        if params.session_stamp:
            canonical_ingest.build_session_string_view(params.session_stamp)
    except Exception:
        pass

    workers = _resolve_workers(params.workers)
    if not params.reuse_cache:
        _purge_run_cache()

    modules = _modules_for_run(params)
    scope_target = format_scope_target(selection)

    workers_label = f"auto ({workers})" if isinstance(params.workers, str) else str(workers)
    render_run_start(
        run_id=params.session_stamp,
        profile_label=params.profile_label,
        target=scope_target,
        modules=modules,
        workers_desc=workers_label,
        cache_desc="purge" if not params.reuse_cache else "reuse",
        log_level=params.log_level,
        perm_cache_desc="refresh" if params.permission_snapshot_refresh else "skip",
        trace_ids=params.trace_detectors,
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
        static_logger.info(
            "Static RUN_START",
            extra={
                "event": log_events.RUN_START,
                "run_id": params.session_stamp,
                "target": scope_target,
                "profile": params.profile_label,
                "modules": modules,
                "workers": workers_label,
                "cache": "purge" if not params.reuse_cache else "reuse",
                "perm_cache": "refresh" if params.permission_snapshot_refresh else "skip",
            },
        )
    except Exception:
        static_logger = None

    configure_logging_for_cli(params.log_level)

    abort_notified = {"shown": False}

    def _handle_sigint(signum, frame) -> None:  # pragma: no cover - signal path
        if not abort_notified["shown"]:
            print(status_messages.status("Interrupt received — stopping safely…", level="warn"))
            abort_notified["shown"] = True
        request_abort(reason="SIGINT", signal="SIGINT")

    previous_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _handle_sigint)

    if params.profile == "permissions":
        print(status_messages.step("Starting permission analysis workflow", label="Static Analysis"))
        try:
            execute_permission_scan(selection, params)
        finally:
            signal.signal(signal.SIGINT, previous_handler)
        return None

    print(status_messages.step("Starting detector pipeline", label="Static Analysis"))
    outcome: RunOutcome | None = None
    run_status: str | None = None
    abort_reason: str | None = None
    abort_signal: str | None = None
    try:
        outcome = execute_scan(selection, params, base_dir)
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    try:
        if outcome is not None:
            setattr(outcome, "session_stamp", params.session_stamp)
    except Exception:
        pass
    try:
        if outcome is not None:
            render_run_results(outcome, params)
            run_status = "COMPLETED"
            if outcome.aborted:
                run_status = "ABORTED"
            elif outcome.failures:
                run_status = "FAILED"
            abort_reason = outcome.abort_reason
            abort_signal = outcome.abort_signal
    except Exception as exc:
        run_status = "FAILED"
        abort_reason = exc.__class__.__name__
        raise
    finally:
        if outcome is not None and not params.dry_run and run_status:
            static_run_ids = [
                result.static_run_id
                for result in outcome.results
                if result.static_run_id
            ]
            if static_run_ids:
                ended_at = outcome.finished_at.isoformat(timespec="seconds") + "Z"
                finalize_open_runs(
                    static_run_ids,
                    status=run_status,
                    ended_at_utc=ended_at,
                    abort_reason=abort_reason,
                    abort_signal=abort_signal,
                )

    # Structured RUN SUMMARY (formatter-based) for transcripts/screenshots.
    if outcome and getattr(outcome, "summary", None):
        summary = outcome.summary
        sev_counts = {
            "high": getattr(summary, "high", 0),
            "medium": getattr(summary, "medium", 0),
            "low": getattr(summary, "low", 0),
        }
        perm_stats = {
            "dangerous": getattr(summary, "dangerous_permissions", 0),
            "signature": getattr(summary, "signature_permissions", 0),
            "custom": getattr(summary, "custom_permissions", 0),
        }
        failed_masvs = list(getattr(summary, "failed_masvs", []) or [])
        evidence_root = getattr(summary, "evidence_root", None)

        render_run_summary(
            run_id=params.session_stamp,
            profile_label=params.profile_label,
            target=scope_target,
            detectors_count=len(modules),
            findings_total=getattr(summary, "findings_total", 0),
            sev_counts=sev_counts,
            failed_masvs=failed_masvs,
            perm_stats=perm_stats,
            evidence_root=evidence_root,
        )
        # Structured log for reproducibility (use fresh logger post-configuration)
        try:
            end_payload = {
                "event": log_events.RUN_END,
                "run_id": params.session_stamp,
                "target": scope_target,
                "profile": params.profile_label,
                "detectors": modules,
                "detectors_count": len(modules),
                "findings_total": getattr(summary, "findings_total", 0),
                "severity": sev_counts,
                "failed_masvs": failed_masvs,
                "permissions": perm_stats,
                "evidence_root": evidence_root,
                "status": "ok",
                "duration_seconds": getattr(summary, "duration_seconds", None),
                "applications": getattr(summary, "applications", None),
                "artifacts": getattr(summary, "artifacts", None),
            }
            logger = logging_engine.get_static_logger()
            logger.info("Static RUN_END", extra=logging_engine.ensure_trace(end_payload))
        except Exception:
            pass

    if params.session_stamp:
        try:
            canonical_ingest.upsert_base002_for_session(params.session_stamp)
            canonical_ingest.build_session_string_view(params.session_stamp)
        except Exception:
            pass

    if (
        params.permission_snapshot_refresh
        and params.profile in {"full", "lightweight"}
        and not params.dry_run
    ):
        try:
            print()
            print(
                status_messages.step(
                    "Re-rendering permission snapshot for parity",
                    label="Static Analysis",
                )
            )
            execute_permission_scan(selection, params, persist_detections=False)
        except Exception:
            pass
    elif params.profile in {"full", "lightweight"} and not params.dry_run:
        print()
        print(
            status_messages.status(
                (
                    "Post-run permission refresh skipped. Enable it in Advanced options "
                    "or set SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=1."
                ),
                level="info",
            )
        )

    return outcome


def _modules_for_run(params: RunParameters) -> tuple[str, ...]:
    if params.profile == "custom" and params.selected_tests:
        return params.selected_tests
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


__all__ = [
    "launch_scan_flow",
    "configure_logging_for_cli",
    "execute_scan",
    "execute_permission_scan",
    "generate_report",
    "build_analysis_config",
    "render_run_results",
    "format_duration",
]
