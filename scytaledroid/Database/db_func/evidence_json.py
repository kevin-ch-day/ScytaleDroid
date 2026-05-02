"""JSON serialization for DB-backed evidence payloads (non-legacy callers)."""

from __future__ import annotations

import json
from typing import Any

from scytaledroid.Utils.LoggingUtils import logging_utils as log


def serialise_evidence_for_db(payload: Any, *, run_id: int | None = None) -> str | None:
    """Serialize evidence for storage; on failure return a JSON sentinel and log."""

    if payload is None:
        return None
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception as exc:
        raw = repr(payload)
        if len(raw) > 220:
            raw = raw[:217] + "..."
        sentinel = {
            "_serialization_error": f"{exc.__class__.__name__}: {exc}",
            "_serialization_type": payload.__class__.__name__,
            "_raw_repr": raw,
        }
        log.warning(
            f"Evidence serialization failed for run_id={run_id}: {exc.__class__.__name__}: {exc}",
            category="db",
            extra={"table": "findings", "column": "evidence", "run_id": run_id},
        )
        return json.dumps(sentinel, ensure_ascii=False)


__all__ = ["serialise_evidence_for_db"]
