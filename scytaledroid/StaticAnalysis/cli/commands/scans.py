"""Scan-oriented command definitions."""

from __future__ import annotations

from .models import Command, SelectionMode

SCAN_COMMANDS: tuple[Command, ...] = (
    Command(
        id="1",
        title="Run Static Pipeline (Full)",
        description="Run complete static analysis with full detector coverage",
        kind="scan",
        profile="full",
        section="workflow",
        auto_verify=True,
        prompt_reset=True,
    ),
    Command(
        id="2",
        title="Run Static Pipeline (Fast)",
        description="Run core detectors for quick MASVS/risk coverage",
        kind="scan",
        profile="lightweight",
        section="workflow",
        auto_verify=True,
    ),
    Command(
        id="3",
        title="Re-analyze last APK",
        description="Re-run analysis for the most recent static run (fallback to latest harvest)",
        kind="scan",
        profile="full",
        section="workflow",
        auto_verify=True,
        selection_mode=SelectionMode.LAST,
    ),
    Command(
        id="4",
        title="Diff two versions",
        description="Compare the latest two versions for the most recent package",
        kind="scan",
        profile="full",
        section="history",
        selection_mode=SelectionMode.DIFF_LAST,
    ),
    Command(
        id="D",
        title="Single APK drilldown (read-only)",
        description="Inspect a single APK without writing to the database",
        kind="scan",
        profile="full",
        section="tools",
        persist=False,
        dry_run=True,
        force_app_scope=True,
        force_verbose=True,
    ),
)

__all__ = ["SCAN_COMMANDS"]
