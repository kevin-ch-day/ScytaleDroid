"""Smoke runner for behavior pipeline."""

from __future__ import annotations

import argparse
import subprocess
import re
from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.DeviceAnalysis import adb_devices, adb_shell
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def _package_installed(pkg: str) -> bool:
    devices = adb_devices.list_devices()
    if not devices:
        return False
    serial = devices[0].get("serial")
    if not serial:
        return False
    try:
        output = adb_shell.run_shell(serial, ["pm", "list", "packages", pkg])
    except RuntimeError:
        return False
    return pkg in output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default="com.android.chrome", help="Target package name")
    parser.add_argument("--duration", type=int, default=60, help="Duration seconds")
    args = parser.parse_args()

    if not _package_installed(args.package):
        log.error(f"Package {args.package} not installed.", category="behavior")
        return 1

    bootstrap_database()
    cmd_run = ["./run.sh", "behavior", "run", "--package", args.package, "--duration", str(args.duration)]
    run_proc = subprocess.run(cmd_run, capture_output=True, text=True)
    if run_proc.returncode != 0:
        log.error(f"Behavior run failed: {run_proc.stderr or run_proc.stdout}", category="behavior")
        return run_proc.returncode
    session_match = re.search(r"SESSION_ID=([A-Za-z0-9_-]+)", run_proc.stdout)
    if not session_match:
        log.error("Could not determine session id from behavior run output.", category="behavior")
        return 1
    session_id = session_match.group(1)
    cmd_report = ["./run.sh", "behavior", "report", "--session", session_id]
    rep_proc = subprocess.run(cmd_report, capture_output=True, text=True)
    if rep_proc.returncode != 0:
        log.error(f"Behavior report failed: {rep_proc.stderr or rep_proc.stdout}", category="behavior")
        return rep_proc.returncode
    log.info(f"Smoke behavior run+report complete for session {session_id}", category="behavior")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
