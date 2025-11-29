#!/usr/bin/env python3
"""
log_device_history.py

Summarize inventory/harvest/static runs for a given device_serial from JSON logs.
"""

from __future__ import annotations

import argparse
import json
from glob import glob
from pathlib import Path
from collections import defaultdict


def _collect(logs_dir: Path, device_serial: str):
    runs = defaultdict(list)
    patterns = [
        str(logs_dir / "*.jsonl"),
        str(logs_dir / "harvest_runs" / "*.jsonl"),
    ]
    for pattern in patterns:
        for path in glob(pattern):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        obj = json.loads(line)
                        if str(obj.get("device_serial")) != device_serial:
                            continue
                        subsystem = obj.get("subsystem") or obj.get("logger") or "unknown"
                        run_id = obj.get("run_id") or "unknown"
                        event = obj.get("event") or ""
                        runs[(subsystem, run_id)].append(obj)
            except Exception:
                continue
    return runs


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize runs for a device from JSON logs.")
    ap.add_argument("device_serial", help="Device serial to summarize.")
    ap.add_argument("--logs-dir", default="logs", help="Path to logs directory (default: ./logs)")
    args = ap.parse_args()

    logs_dir = Path(args.logs_dir).resolve()
    if not logs_dir.exists():
        print(f"Logs directory not found: {logs_dir}")
        return

    runs = _collect(logs_dir, args.device_serial)
    if not runs:
        print(f"No runs found for device {args.device_serial}")
        return

    print(f"Device {args.device_serial} — Activity summary")
    print("------------------------------------------")
    for (subsystem, run_id), events in sorted(runs.items(), key=lambda x: x[0]):
        start = next((e for e in events if e.get("event") == "run.start"), None)
        end = next((e for e in events if e.get("event") == "run.end"), None)
        scope = start.get("scope") if start else None
        profile = start.get("profile") if start else None
        msg = f"{subsystem.upper():10s} {run_id:20s}"
        if scope:
            msg += f" scope={scope}"
        if profile:
            msg += f" profile={profile}"
        print(msg)
        if subsystem == "inventory" and end:
            print(
                f"  packages={end.get('packages')} delta(n/r/u)="
                f"{end.get('delta_new')}/{end.get('delta_removed')}/{end.get('delta_updated')}"
            )
        if subsystem == "harvest" and end:
            print(
                f"  packages={end.get('packages_total')} artifacts={end.get('artifacts_written')}"
                f" pull_mode={end.get('pull_mode')}"
            )
        if subsystem == "static" and end:
            print(
                f"  findings={end.get('findings_total')} severity={end.get('severity')}"
            )
    print()


if __name__ == "__main__":
    main()
