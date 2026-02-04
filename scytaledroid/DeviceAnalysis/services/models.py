"""Typed service models for device inventory status."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class InventoryStatus:
    last_run_ts: datetime | None
    package_count: int | None
    age_seconds: int | None
    is_stale: bool
    status_label: str
    age_display: str
    packages_changed: bool = False
    scope_changed: bool = False
    state_changed: bool = False
    fingerprint_changed: bool = False