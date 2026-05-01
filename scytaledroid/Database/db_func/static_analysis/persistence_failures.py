"""Durable recording for static persistence failures.

We need these records even when the main persistence transaction rolls back.
This module writes failures in a separate best-effort DB transaction.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.session import database_session


def record_static_persistence_failure(
    *,
    static_run_id: int,
    stage: str | None,
    exc_class: str | None,
    exc_message: str | None,
    errors_tail: list[str] | None = None,
) -> None:
    """Insert a failure record for a static_run_id (best-effort).

    This function must not raise: it is invoked from exception paths.
    """

    try:
        stage_val = (stage or "").strip()[:64] or None
        exc_class_val = (exc_class or "").strip()[:128] or None
        exc_msg_val = (exc_message or "").strip()
        if exc_msg_val:
            exc_msg_val = exc_msg_val[:1024]
        else:
            exc_msg_val = None
        tail = None
        if errors_tail:
            # Keep just the last few unique lines to avoid exploding row size.
            seen = set()
            compact: list[str] = []
            for item in reversed(errors_tail):
                text = str(item or "").strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                compact.append(text)
                if len(compact) >= 5:
                    break
            tail = "\n".join(reversed(compact))[:2048] if compact else None

        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        with database_session(reuse_connection=False) as engine:
            with engine.transaction():
                core_q.run_sql(
                    """
                    INSERT INTO static_persistence_failures
                      (static_run_id, stage, exception_class, exception_message, errors_tail, occurred_at_utc)
                    VALUES
                      (%s,%s,%s,%s,%s,%s)
                    """,
                    (int(static_run_id), stage_val, exc_class_val, exc_msg_val, tail, now),
                    fetch="none",
                    query_name="static.persist_failures.insert",
                )
    except Exception:
        return


__all__ = ["record_static_persistence_failure"]

