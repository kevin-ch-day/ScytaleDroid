"""Helpers for writing static batch-summary receipts."""

from __future__ import annotations

import json
from pathlib import Path


def _resolve_started_at(rows: list[dict[str, object]]) -> str | None:
    if not rows:
        return None
    first = rows[0]
    started_at = first.get("started_at") or first.get("started_at_utc")
    if started_at:
        return str(started_at)
    for row in rows:
        candidate = row.get("started_at") or row.get("started_at_utc")
        if candidate:
            return str(candidate)
    return None


def write_batch_summary(
    *,
    batch_summary_path: Path,
    batch_id: str,
    batch_rows: list[dict[str, object]],
    apps_total: int,
    apps_completed: int,
    apps_failed: int,
    ended_at: str | None,
) -> None:
    batch_summary_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = _resolve_started_at(batch_rows)
    payload = {
        "batch_id": batch_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "apps_total": apps_total,
        "apps_completed": apps_completed,
        "apps_failed": apps_failed,
        "rows": batch_rows,
    }
    batch_summary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


__all__ = ["write_batch_summary"]
