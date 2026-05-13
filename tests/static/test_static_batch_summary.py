"""Contract tests for static batch summary JSON (see ``scripts/stress_static_postcheck.py``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


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


def _write_batch_summary_receipt(
    *,
    batch_summary_path: Path,
    batch_id: str,
    batch_rows: list[dict[str, object]],
    apps_total: int,
    apps_completed: int,
    apps_failed: int,
    ended_at: str | None,
) -> dict[str, Any]:
    """Build the batch receipt payload written by historical batch runners (shape-only)."""

    batch_summary_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = _resolve_started_at(batch_rows)
    payload: dict[str, Any] = {
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
    return payload


def test_write_batch_summary_accepts_started_at_utc(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "batch.json"
    rows = [
        {
            "package_name": "com.example",
            "display_name": "Example",
            "started_at_utc": "2026-02-28T00:00:00Z",
            "completed": True,
        }
    ]
    _write_batch_summary_receipt(
        batch_summary_path=out,
        batch_id="batch-1",
        batch_rows=rows,
        apps_total=1,
        apps_completed=1,
        apps_failed=0,
        ended_at="2026-02-28T00:01:00Z",
    )
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "started_at_utc" in text
    assert "2026-02-28T00:00:00Z" in text


def test_write_batch_summary_accepts_started_at(tmp_path: Path) -> None:
    out = tmp_path / "batch.json"
    rows = [{"started_at": "2026-02-28T00:00:00Z"}]
    _write_batch_summary_receipt(
        batch_summary_path=out,
        batch_id="batch-2",
        batch_rows=rows,
        apps_total=1,
        apps_completed=1,
        apps_failed=0,
        ended_at=None,
    )
    assert out.exists()
