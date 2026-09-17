"""Session label collision handling before static runs (DB + local run_map alignment).

Extracted from ``run_dispatch`` so parameter resolution stays readable and testable in isolation.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages

from ...session import normalize_session_stamp


def _existing_db_session_labels(base_stamp: str) -> list[str]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        rows = core_q.run_sql(
            """
            SELECT DISTINCT COALESCE(NULLIF(TRIM(session_label), ''), NULLIF(TRIM(session_stamp), ''))
            FROM static_analysis_runs
            WHERE session_label=%s OR session_label LIKE %s OR session_stamp=%s OR session_stamp LIKE %s
            UNION
            SELECT DISTINCT COALESCE(NULLIF(TRIM(session_label), ''), NULLIF(TRIM(session_stamp), ''))
            FROM static_analysis_sessions
            WHERE session_label=%s OR session_label LIKE %s OR session_stamp=%s OR session_stamp LIKE %s
            """,
            (base_stamp, f"{base_stamp}-%", base_stamp, f"{base_stamp}-%") * 2,
            fetch="all",
        ) or []
    except Exception as exc:
        raise RuntimeError(
            "persistent session state cannot be inspected; refusing normal static execution"
        ) from exc

    labels: list[str] = []
    for row in rows:
        value = None
        if isinstance(row, (list, tuple)) and row:
            value = row[0]
        elif isinstance(row, dict) and row:
            value = next(iter(row.values()))
        if isinstance(value, str) and value.strip():
            labels.append(value.strip())
    return labels


def _next_session_suffix(base_stamp: str, labels: list[str]) -> int | None:
    max_suffix = 0
    seen = False
    prefix = f"{base_stamp}-"
    for label in labels:
        candidate = str(label or "").strip()
        if not candidate:
            continue
        if candidate == base_stamp:
            seen = True
            max_suffix = max(max_suffix, 1)
            continue
        if not candidate.startswith(prefix):
            continue
        tail = candidate[len(prefix) :]
        if not re.fullmatch(r"\d+", tail):
            continue
        seen = True
        max_suffix = max(max_suffix, int(tail))
    if not seen:
        return None
    return max_suffix + 1


def resolve_unique_session_stamp(
    session_stamp: str,
    *,
    run_mode: str,
    noninteractive: bool,
    quiet: bool,
    canonical_action: str | None,
) -> tuple[str, str, str]:
    """Return ``(resolved_stamp, session_label, canonical_action_token)`` for a desired label."""

    base_stamp = session_stamp
    session_dir = Path(app_config.DATA_DIR) / "sessions"
    final_path = session_dir / base_stamp / "run_map.json"
    archive_dir = Path(app_config.DATA_DIR) / "static_analysis" / "reports" / "archive" / base_stamp
    attempts = None
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s OR session_stamp=%s
            """,
            (base_stamp, base_stamp),
            fetch="one",
        )
        attempts = int(row[0]) if row and row[0] is not None else 0
        header_row = core_q.run_sql(
            "SELECT COUNT(*) FROM static_analysis_sessions WHERE session_stamp=%s OR session_label=%s",
            (base_stamp, base_stamp),
            fetch="one",
        )
        has_persistent_header = bool(header_row and header_row[0] is not None and int(header_row[0]) > 0)
    except Exception as exc:
        raise RuntimeError(
            "persistent session state cannot be inspected; refusing normal static execution"
        ) from exc
    # A local run_map may be missing after reset/cleanup while DB attempts still exist.
    # Treat either source as "session already used".
    has_local_session = final_path.exists() or any(archive_dir.glob("*.json"))
    has_db_attempts = isinstance(attempts, int) and attempts > 0
    if not has_local_session and not has_db_attempts and not has_persistent_header:
        return base_stamp, base_stamp, "first_run"
    # Only query the historical label set after the authoritative exact-label
    # check establishes that the session already exists.  A failure here must
    # still block reuse because a collision-safe append cannot be computed.
    existing_labels = _existing_db_session_labels(base_stamp)
    next_suffix = _next_session_suffix(base_stamp, existing_labels)
    batch_mode = run_mode == "batch"
    if batch_mode or noninteractive:
        suffix = None
        if next_suffix is not None:
            suffix = str(next_suffix)
        if not suffix:
            suffix = datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        return new_stamp, new_stamp, "auto_suffix"
    # Interactive mode must not prompt inside execution. The menu layer should
    # resolve collisions into a canonical_action and/or a unique session_stamp.
    action = (canonical_action or "").strip().lower()
    if action in {"append", "auto_suffix"}:
        suffix = str(next_suffix) if next_suffix is not None else datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        return new_stamp, new_stamp, "append"
    if action == "":
        suffix = str(next_suffix) if next_suffix is not None else datetime.now(UTC).strftime("%H%M%S")
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
        raise RuntimeError(
            f"Session label already used: {base_stamp}. Normal static execution cannot replace persistent session history; use a new session label."
        )
    if action in {"cancel", "abort"}:
        raise RuntimeError(f"Session label already used: {base_stamp}. Cancelled by caller.")
    raise RuntimeError(
        f"Session label already used: {base_stamp}. "
        "Resolve this in the menu layer by appending a new session label before execution."
    )
