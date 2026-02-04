"""Legacy entrypoint for APK pulls."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.workflows.apk_pull_workflow import run_apk_pull
from scytaledroid.Utils.ops.operation_result import OperationResult

__all__ = ["pull_apks"]


def pull_apks(serial: str | None, *, auto_scope: bool = False) -> OperationResult:
    return run_apk_pull(serial, auto_scope=auto_scope)
