"""Data models for APK pull workflows."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass
class SnapshotContext:
    snapshot: Mapping[str, object]
    rows: list[Any]
    snapshot_id: int | None
    snapshot_captured_at: str | None


@dataclass
class PlanResolution:
    plan: Any
    selection: Any
    stats: Mapping[str, int | str]
    pull_mode: str
    verbose: bool
    guard_metadata: Mapping[str, object] | None


@dataclass
class PlanStats:
    scheduled_packages: int
    blocked_packages: int
    scheduled_files: int
    policy_blocked: int
    policy: str
