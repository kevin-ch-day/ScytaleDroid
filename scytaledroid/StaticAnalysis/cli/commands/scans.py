"""Scan-oriented command definitions."""

from __future__ import annotations

from .models import Command

SCAN_COMMANDS: tuple[Command, ...] = (
    Command(
        id="1",
        title="Full analysis [FULL] (recommended)",
        description="Run complete static analysis with full detector coverage",
        kind="scan",
        profile="full",
        section="workflow",
        auto_verify=True,
        prompt_reset=True,
    ),
    Command(
        id="2",
        title="Lightweight analysis [FAST]",
        description="Run core detectors for quick MASVS/risk coverage",
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
    # Developer shortcuts (only shown when SCYTALEDROID_DEV_SHORTCUTS=1)
    Command(
        id="C",
        title="CNN — baseline regression",
        description="Stable app used to verify detector outputs",
        kind="scan",
        profile="full",
        section="dev",
        auto_verify=True,
        force_app_scope=True,
        prompt_reset=False,
    ),
    Command(
        id="T",
        title="TikTok — stress / edge-case",
        description="Complex app to stress components, strings, and permissions",
        kind="scan",
        profile="full",
        section="dev",
        auto_verify=True,
        force_app_scope=True,
        prompt_reset=False,
    ),
)

__all__ = ["SCAN_COMMANDS"]
