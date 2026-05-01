"""Logging and display event helpers for static analysis run dispatch."""

from __future__ import annotations

from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger

from ..core.models import RunParameters
from ..core.run_context import StaticRunContext


def _emit_postprocessing_step(message: str, *, run_ctx: StaticRunContext) -> None:
    if run_ctx.quiet and run_ctx.batch:
        return

    print()
    print(status_messages.step(message, label="Static Analysis"))


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
        try:
            logging_engine.get_static_logger().info(
                "Static RUN_PHASE",
                extra=logging_engine.ensure_trace(payload),
            )
        except Exception:
            pass


def _emit_db_preflight_lock_warning(
    *,
    params: RunParameters,
    run_ctx: StaticRunContext,
) -> None:
    if run_ctx.quiet and run_ctx.batch:
        return

    if params.dry_run or not params.persistence_ready:
        return

    try:
        snapshot = db_diagnostics.get_lock_health_snapshot(limit=10)
    except Exception:
        return

    if not isinstance(snapshot, dict):
        return

    if snapshot.get("error"):
        return

    active = snapshot.get("active_processes")
    if not isinstance(active, list) or not active:
        return

    long_running = [row for row in active if int(row.get("time_s") or 0) >= 5]
    if not long_running:
        return

    top = long_running[0]
    state = str(top.get("state") or "unknown")
    time_s = int(top.get("time_s") or 0)
    info = str(top.get("info") or "").strip()
    preview = (info[:120] + "…") if len(info) > 120 else info
    wait_timeout = snapshot.get("lock_wait_timeout_s")

    print(
        status_messages.status(
            (
                "DB preflight detected active SQL work that may contend with persistence "
                f"(lock_wait_timeout={wait_timeout}s): state={state} time={time_s}s "
                f"query={preview or '<redacted>'}"
            ),
            level="warn",
        )
    )


__all__ = [
    "_emit_db_preflight_lock_warning",
    "_emit_phase_log",
    "_emit_postprocessing_step",
]