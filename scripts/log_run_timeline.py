#!/usr/bin/env python3
"""
log_run_timeline.py

Given a run_id, print a chronological timeline of relevant log events
from JSONL logs under ./logs (and ./logs/harvest if present).
"""

from __future__ import annotations

import argparse
import json
from glob import glob
from pathlib import Path
from typing import Dict, List


def _collect_records(run_id: str, logs_dir: Path) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    patterns = [
        str(logs_dir / "*.jsonl"),
        str(logs_dir / "harvest_runs" / "*.jsonl"),
        str(logs_dir / "harvest" / "*.jsonl"),
    ]
    for pattern in patterns:
        for path in glob(pattern):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        obj = json.loads(line)
                        if obj.get("run_id") == run_id:
                            records.append(obj)
            except Exception:
                continue
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description="Show timeline for a given run_id from JSON logs.")
    ap.add_argument("run_id", help="Run identifier (e.g., HARVEST-..., INV-..., STATIC-...).")
    ap.add_argument("--logs-dir", default="logs", help="Path to logs directory (default: ./logs)")
    args = ap.parse_args()

    logs_dir = Path(args.logs_dir).resolve()
    if not logs_dir.exists():
        print(f"Logs directory not found: {logs_dir}")
        return

    recs = _collect_records(args.run_id, logs_dir)
    if not recs:
        print(f"No records found for run_id={args.run_id} in {logs_dir}")
        return

    recs.sort(key=lambda r: r.get("ts", ""))

    for rec in recs:
        ts = rec.get("ts", "")
        subsystem = rec.get("subsystem") or rec.get("logger") or "unknown"
        event = rec.get("event", "")
        message = rec.get("message", "")
        extra = {k: v for k, v in rec.items() if k not in {"ts", "level", "logger", "message", "stack"}}
        print(f"[{ts}] [{subsystem}] [{event}] {message} | extra={extra}")


if __name__ == "__main__":
    main()
