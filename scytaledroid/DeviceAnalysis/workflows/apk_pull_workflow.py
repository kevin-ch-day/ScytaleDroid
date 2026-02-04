"""Workflow wrapper for APK pull orchestration."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.apk.workflow import run_apk_pull as _run_apk_pull


def run_apk_pull(
    serial: str | None,
    *,
    auto_scope: bool = False,
    noninteractive: bool = False,
):
    """Workflow entrypoint; delegates to DeviceAnalysis.apk.workflow."""
    return _run_apk_pull(serial, auto_scope=auto_scope, noninteractive=noninteractive)


__all__ = ["run_apk_pull"]
