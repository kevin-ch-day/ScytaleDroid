"""SIGINT / safe-abort wiring for static scan launch."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.execution import request_abort
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext

from .static_scan_constants import PHASE_ABORTING
from .static_scan_lifecycle import emit_static_run_phase_log


def build_static_scan_sigint_handler(
    *,
    dispatch: Any,
    run_ctx: RunContext,
    params: RunParameters,
    scope_target: str | None,
) -> tuple[Callable[[int, Any], None], dict[str, bool | int]]:
    """Return ``(handler, abort_notified_state)`` for main-thread SIGINT during static scan."""

    abort_notified: dict[str, bool | int] = {"shown": False, "count": 0}

    def _handle_sigint(signum: int, frame: Any) -> None:  # pragma: no cover - signal path
        abort_notified["count"] = int(abort_notified["count"]) + 1
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
            dispatch._hb_set_phase(PHASE_ABORTING, keep_app=True)
        except Exception:
            pass
        emit_static_run_phase_log(
            run_ctx=run_ctx,
            session_stamp=params.session_stamp,
            scope_target=scope_target,
            scope_label=params.scope_label,
            profile_label=params.profile_label,
            execution_id=params.execution_id,
            phase=PHASE_ABORTING,
            status="requested",
            extra={
                "abort_reason": "user_abort",
                "abort_signal": "SIGINT",
                "interrupt_count": abort_notified["count"],
                "execution_id": params.execution_id,
            },
        )
        try:
            logger = dispatch.get_run_logger("static", run_ctx)
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

    return _handle_sigint, abort_notified


__all__ = ["build_static_scan_sigint_handler"]
