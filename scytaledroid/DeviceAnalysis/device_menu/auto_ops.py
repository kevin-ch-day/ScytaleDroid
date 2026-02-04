"""Automatic device connect/survey utilities for the Device Analysis menu."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .. import device_manager, inventory, inventory_meta
from .dashboard import resolve_active_device
from .inventory_guard.constants import INVENTORY_STALE_SECONDS
from .inventory_guard.utils import humanize_seconds


def ensure_active_device(
    devices: Sequence[Dict[str, Optional[str]]],
    active_device: Optional[Dict[str, Optional[str]]],
) -> Tuple[Optional[Dict[str, Optional[str]]], List[str]]:
    """Auto-select a single connected device when no active device is set."""

    messages: List[str] = []
    if active_device or len(devices) != 1:
        return active_device, messages

    candidate_serial = devices[0].get("serial")
    if not candidate_serial:
        return active_device, messages

    if device_manager.set_active_device(candidate_serial):
        updated = resolve_active_device(devices)
        if updated:
            messages.append(
                status_messages.status(
                    f"Auto-connected to {candidate_serial}", level="info"
                )
            )
        else:
            log.warning(
                f"Auto-connect to {candidate_serial} did not yield an active device.",
                category="device",
            )
            messages.append(
                status_messages.status(
                    "Automatically selected device disappeared before confirmation. Please select a device manually.",
                    level="warn",
                )
            )
        return updated, messages

    return active_device, messages


def ensure_inventory_survey(
    serial: Optional[str],
    *,
    metadata: Optional[Dict[str, object]],
    surveyed_serials: set[str],
    emit: Optional[Callable[[str], None]] = None,
) -> None:
    """Run a silent inventory survey once per session when the snapshot is fresh."""

    if not serial or serial in surveyed_serials:
        return

    snapshot_meta = inventory_meta.load_latest(serial)
    snapshot_present = metadata is not None or snapshot_meta is not None
    if not snapshot_present:
        surveyed_serials.add(serial)
        message = status_messages.status(
            "No inventory snapshot found yet; run Sync + Pull (option 1).",
            level="warn",
        )
        if emit:
            emit(message)
        return

    # Normalise metadata into primitives we can reason about (support dict or InventoryStatus).
    metadata = metadata or {}
    timestamp: Optional[datetime] = None
    packages_changed = False
    scope_changed = False
    state_changed = False
    fingerprint_changed = False

    if isinstance(metadata, dict):
        timestamp = metadata.get("timestamp") if isinstance(metadata.get("timestamp"), datetime) else None
        packages_changed = bool(metadata.get("packages_changed"))
        scope_changed = bool(metadata.get("scope_changed"))
        state_changed = bool(metadata.get("state_changed"))
        fingerprint_changed = bool(metadata.get("build_fingerprint_changed"))
    else:
        # InventoryStatus dataclass case
        timestamp = getattr(metadata, "last_run_ts", None)
        # These flags may not exist on InventoryStatus; default to False
        packages_changed = bool(getattr(metadata, "packages_changed", False))
        scope_changed = bool(getattr(metadata, "scope_changed", False))
        state_changed = bool(getattr(metadata, "state_changed", False))
        fingerprint_changed = bool(getattr(metadata, "build_fingerprint_changed", False))

    if timestamp is None and snapshot_meta is not None:
        timestamp = snapshot_meta.captured_at

    age_seconds: Optional[float] = None
    if timestamp is not None:
        age_seconds = max((datetime.now(timezone.utc) - timestamp).total_seconds(), 0.0)

    too_old = age_seconds is None or age_seconds > INVENTORY_STALE_SECONDS
    # Only flag changes when current-state deltas are actually reported.
    has_changes = packages_changed or scope_changed or fingerprint_changed

    surveyed_serials.add(serial)

    if too_old or has_changes:
        reason: Optional[str] = None
        if age_seconds is None:
            reason = "Inventory snapshot age unknown; run Sync + Pull (option 1)."
        elif too_old:
            reason = (
                "Inventory snapshot exceeds the freshness threshold—run Sync + Pull (option 1) before pulling APKs."
            )
        else:
            # Fresh by age but changed: do not emit a footer warning; gating will handle this.
            reason = None
        if reason and emit:
            emit(status_messages.status(reason, level="warn"))
        return

    # If we reach here, inventory is fresh and unchanged. Do not auto-refresh;
    # the operator can trigger a manual sync if desired.


__all__ = ["ensure_active_device", "ensure_inventory_survey"]
