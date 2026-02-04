"""Quick APK harvest wrapper.

Quick mode now delegates to the shared harvest executor to avoid drift.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from scytaledroid.Utils.LoggingUtils import logging_engine

from .models import PackagePlan, PullResult
from .runner import execute_harvest


def quick_harvest(
    packages: Sequence[PackagePlan],
    *,
    adb_path: str,
    dest_root: Path,
    session_stamp: str,
    config: object,
    serial: str | None = None,
    verbose: bool = False,
    run_id: str | None = None,
    harvest_logger: logging_engine.ContextAdapter | None = None,
    snapshot_id: int | None = None,
    snapshot_captured_at: str | None = None,
) -> list[PullResult]:
    """Execute quick harvest using the shared executor."""

    resolved_serial = serial or dest_root.name
    return execute_harvest(
        serial=resolved_serial,
        adb_path=adb_path,
        dest_root=dest_root,
        session_stamp=session_stamp,
        plans=packages,
        config=config,
        verbose=verbose,
        pull_mode="quick",
        run_id=run_id,
        harvest_logger=harvest_logger,
        scope_label="Quick pull",
        snapshot_id=snapshot_id,
        snapshot_captured_at=snapshot_captured_at,
    )