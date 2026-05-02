"""Session label collision handling before static runs (DB + local run_map alignment).

Extracted from ``run_dispatch`` so parameter resolution stays readable and testable in isolation.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import status_messages

from ...session import normalize_session_stamp


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
    batch_mode = run_mode == "batch"
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
