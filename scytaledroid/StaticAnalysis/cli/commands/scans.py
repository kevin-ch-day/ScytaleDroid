"""Scan-oriented command definitions."""

from __future__ import annotations

from .models import Command

SCAN_COMMANDS: tuple[Command, ...] = (
    Command(
        id="1",
        title="Full analysis (persist + verification)",
        description="Run all detectors, reset caches/persistence, and emit verification digest",
        kind="scan",
        profile="full",
        section="workflow",
        auto_verify=True,
        prompt_reset=True,
    ),
    Command(
        id="2",
        title="Accelerated analysis (persist essentials)",
        description="Run core detectors for MASVS/risk tracking and persist results",
        kind="scan",
        profile="lightweight",
        section="workflow",
        auto_verify=True,
    ),
    Command(
        id="3",
        title="Single APK drilldown (read-only)",
        description="Inspect a single APK without writing to the database",
        kind="scan",
        profile="full",
        section="tools",
        persist=False,
        dry_run=True,
        force_app_scope=True,
    ),
)

__all__ = ["SCAN_COMMANDS"]
