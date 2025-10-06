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
) -> str:
    """Return the preferred inventory handling strategy.

    Returns one of ``"sync"``, ``"use_snapshot"``, or ``"cancel"``.
    """

    last_synced = None
    if timestamp and age_seconds is not None:
        last_synced = humanize_seconds(age_seconds)

    if last_synced:
        print(
            status_messages.status(
                f"Last snapshot captured {last_synced} ago.", level="info"
            )
        )

    if state_changed:
        print(
            status_messages.status(
                "Device state differs from the last snapshot.", level="warn"
            )
        )

    if stale_level == "soft":
        print(
            status_messages.status(
                "Guard marked inventory as soft-stale (packages unchanged).", level="info"
            )
        )
    elif stale_level == "hard":
        print(
            status_messages.status(
                "Guard marked inventory as stale; consider refreshing before pull.",
                level="warn",
            )
        )

    if quick_hint:
        print(status_messages.status(quick_hint, level="info"))

    print("How would you like to proceed?")
    print("  1) Run inventory sync now (recommended)")
    print("  2) Use existing snapshot (may be outdated)")
    print("  0) Cancel APK pull")

    if default_choice not in {"0", "1", "2"}:
        default_choice = "1"

    prompt_text = f"Select option [{default_choice}]: "
    choice = prompt_utils.get_choice(["1", "2", "0"], default=default_choice, prompt=prompt_text)

    if choice == "2":
        return "use_snapshot"
    if choice == "0":
        return "cancel"
    return "sync"
