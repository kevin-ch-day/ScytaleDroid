#!/usr/bin/env python3
"""
log_error_summary.py

Aggregate WARNING/ERROR events from error.jsonl (and subsystem logs) grouped by
subsystem and event.
"""

from __future__ import annotations

import argparse
import json
from glob import glob
from pathlib import Path
from collections import defaultdict


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize WARNING/ERROR events from logs.")
    ap.add_argument("--logs-dir", default="logs", help="Path to logs directory (default: ./logs)")
    args = ap.parse_args()

    logs_dir = Path(args.logs_dir).resolve()
    if not logs_dir.exists():
        print(f"Logs directory not found: {logs_dir}")
        return

    buckets = defaultdict(int)
    samples = defaultdict(list)

    patterns = [
        str(logs_dir / "error.jsonl"),
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
                        level = obj.get("level", "").upper()
                        if level not in {"WARNING", "ERROR", "CRITICAL"}:
                            continue
                        subsystem = obj.get("subsystem") or obj.get("logger") or "unknown"
                        event = obj.get("event") or "unknown"
                        key = (subsystem, event, level)
                        buckets[key] += 1
                        if len(samples[key]) < 3:
                            samples[key].append(obj.get("message", "")[:200])
            except Exception:
                continue

    if not buckets:
        print("No warning/error events found.")
        return

    print("Error summary (WARNING/ERROR/CRITICAL)")
    print("--------------------------------------")
    for (subsystem, event, level), count in sorted(buckets.items(), key=lambda x: (-x[1], x[0])):
        print(f"{subsystem:12s} {event:25s} {level:9s} count={count}")
        for sample in samples[(subsystem, event, level)]:
            print(f"  sample: {sample}")
    print()


if __name__ == "__main__":
    main()
