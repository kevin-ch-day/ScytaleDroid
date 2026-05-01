"""User interaction helpers for inventory guard decisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from .constants import INVENTORY_STALE_SECONDS
from .utils import humanize_seconds


@dataclass
class InventoryGuardMessage:
    severity: str  # "none" | "info" | "warn"
    short: str
    long: str | None = None


@dataclass
class InventoryDeltaSummary:
    new_count: int
    removed_count: int
    updated_count: int
    changed_packages_count: int


def describe_inventory_state(
    status: str,
    delta: InventoryDeltaSummary | None,
    age: timedelta,
    threshold: timedelta,
) -> InventoryGuardMessage:
    # Normalize delta
    if delta is None:
        delta = InventoryDeltaSummary(0, 0, 0, 0)

    if status == "NONE":
        return InventoryGuardMessage(
            severity="warn",
            short="No inventory snapshot is available.",
            long="Run a full inventory and database refresh before Execute Harvest.",
        )

    if age >= threshold:
        hours = int(age.total_seconds() // 3600)
        return InventoryGuardMessage(
            severity="warn",
            short=f"Inventory snapshot is older than {hours}h; re-sync is recommended.",
            long="Pulling APKs may miss recent updates or installs.",
        )

    if delta.changed_packages_count == 0:
        return InventoryGuardMessage(
            severity="none",
            short="Inventory is fresh and identical to the previous snapshot.",
            long=None,
        )

    return InventoryGuardMessage(
        severity="info",
        short=f"Inventory package metadata changed since the previous snapshot ({delta.changed_packages_count} total).",
        long=None,
    )


def prompt_inventory_decision(
    *,
    timestamp: datetime | None,
    age_seconds: float | None,
    state_changed: bool,
    stale_level: str,
    default_choice: str = "1",
    quick_hint: str | None = None,
    changes_total: int | None = None,
) -> str:
    """Return the preferred inventory handling strategy.

    Returns one of ``"sync"``, ``"use_snapshot"``, or ``"cancel"``.
    """

    last_synced = humanize_seconds(age_seconds) if timestamp and age_seconds is not None else None
    age_stale = bool(age_seconds is not None and age_seconds >= INVENTORY_STALE_SECONDS)

    # Title/body (centralized copy by state)
    if not timestamp:
        print(status_messages.status("No inventory snapshot exists; run a full refresh before Execute Harvest.", level="warn"))
    elif age_stale and last_synced:
        print(
            status_messages.status(
                f"Inventory is stale by age (last: {last_synced}; threshold: {INVENTORY_STALE_SECONDS // 3600}h).",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "A fresh inventory is recommended to avoid missing newly installed or metadata-changed apps.",
                level="info",
            )
        )
    elif state_changed:
        changes_text = f" ({changes_total} changes)" if changes_total else ""
        freshness = f"(last: {last_synced})" if last_synced else ""
        print(
            status_messages.status(
                f"Inventory is fresh by age {freshness} but packages changed since the selected snapshot{changes_text}.",
                level="warn",
            )
        )
        print(
            status_messages.status(
                "Refresh Inventory is recommended before Execute Harvest; using the existing snapshot may miss changes.",
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
