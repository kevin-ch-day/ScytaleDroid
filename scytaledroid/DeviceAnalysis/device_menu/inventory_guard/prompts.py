"""User interaction helpers for inventory guard decisions."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from .utils import humanize_seconds
from .constants import INVENTORY_STALE_SECONDS


def prompt_inventory_decision(
    *,
    timestamp: Optional[datetime],
    age_seconds: Optional[float],
    state_changed: bool,
    stale_level: str,
    default_choice: str = "1",
    quick_hint: Optional[str] = None,
    changes_total: Optional[int] = None,
) -> str:
    """Return the preferred inventory handling strategy.

    Returns one of ``"sync"``, ``"use_snapshot"``, or ``"cancel"``.
    """

    last_synced = humanize_seconds(age_seconds) if timestamp and age_seconds is not None else None
    age_stale = bool(age_seconds is not None and age_seconds >= INVENTORY_STALE_SECONDS)

    # Title/body (centralized copy by state)
    if not timestamp:
        print(status_messages.status("No inventory snapshot exists; run a full sync before pulling APKs.", level="warn"))
    elif age_stale and last_synced:
        print(
            status_messages.status(
                f"Inventory is stale by age (last: {last_synced}; threshold: {INVENTORY_STALE_SECONDS // 3600}h).",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "A fresh inventory is recommended to avoid missing newly installed or updated apps.",
                level="info",
            )
        )
    elif state_changed:
        changes_text = f" ({changes_total} changes)" if changes_total else ""
        freshness = f"(last: {last_synced})" if last_synced else ""
        print(
            status_messages.status(
                f"Inventory is fresh by age {freshness} but packages changed since the last snapshot{changes_text}.",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "Sync now is recommended before pulling APKs; using the existing snapshot may miss updates.",
                level="info",
            )
        )
    else:
        print(
            status_messages.status(
                "Inventory snapshot is within the freshness window; proceed as needed.",
                level="info",
            )
        )

    print("How would you like to proceed?")
    print("  1) Sync now (recommended)")
    print("  2) Use last snapshot")
    print("  0) Cancel")

    if default_choice not in {"0", "1", "2"}:
        default_choice = "1"

    prompt_text = f"Select option [{default_choice}]: "
    choice = prompt_utils.get_choice(["1", "2", "0"], default=default_choice, prompt=prompt_text)

    if choice == "2":
        return "use_snapshot"
    if choice == "0":
        return "cancel"
    return "sync"
