"""Helpers for consistent static-run lifecycle updates."""

from __future__ import annotations

from datetime import UTC, datetime

from ..persistence.run_summary import finalize_open_static_runs, update_static_run_status


def finalize_static_run(
    *,
    static_run_id: int | None,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    if not static_run_id:
        return
    ended_at = ended_at_utc
    if not ended_at:
        ended_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    update_static_run_status(
        static_run_id=static_run_id,
        status=status,
        ended_at_utc=ended_at,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )


def finalize_open_runs(
    static_run_ids: list[int],
    *,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    finalize_open_static_runs(
        static_run_ids,
        status=status,
        ended_at_utc=ended_at_utc,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )


__all__ = ["finalize_open_runs", "finalize_static_run"]