"""User interaction helpers for inventory guard decisions."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from .utils import humanize_seconds


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

    last_synced = None
    if timestamp and age_seconds is not None:
        last_synced = humanize_seconds(age_seconds)

    # Title
    if last_synced:
        print(status_messages.status(f"Inventory is stale (last: {last_synced}).", level="warn"))
    else:
        print(status_messages.status("Inventory may be stale.", level="warn"))

    # Body
    if changes_total and changes_total > 0:
        print(
            status_messages.status(
                f"Proceeding without sync may miss updated packages ({changes_total} changes).",
                level="info",
            )
        )
    elif state_changed:
        print(status_messages.status("Proceeding without sync may miss updates.", level="info"))

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
