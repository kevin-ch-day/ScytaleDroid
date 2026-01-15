"""Smoke runner for behavior pipeline."""

from __future__ import annotations

import argparse
import subprocess

from scytaledroid.Database.tools.bootstrap import bootstrap_database
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True, help="Target package name")
    parser.add_argument("--duration", type=int, default=60, help="Duration seconds")
    args = parser.parse_args()

    bootstrap_database()
    cmd_run = ["./run.sh", "behavior", "run", "--package", args.package, "--duration", str(args.duration)]
    cmd_report = ["./run.sh", "behavior", "report", "--session", ""]
    try:
        subprocess.run(cmd_run, check=True)
        log.info("Behavior run completed (smoke).", category="behavior")
    except subprocess.CalledProcessError as exc:  # pragma: no cover - smoke only
        log.error(f"Smoke behavior run failed: {exc}", category="behavior")
        return
    # Session id printed by behavior run; smoke does not know it. User can rerun report separately.


if __name__ == "__main__":
    main()
