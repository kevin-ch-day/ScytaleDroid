#!/usr/bin/env python3
"""Verify static persistence reliability from persistence audit artifacts.

This script validates the latest (or a specified) artifact produced at either:
  output/audit/persistence/<session>_persistence_audit.json
  output/audit/persistence/<session>_missing_run_ids.json

Default systemic-failure gate:
  - FAIL if max consecutive missing_static_run_id streak >= 10
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _latest_artifact(root: Path) -> Path | None:
    if not root.exists():
        return None
    files = sorted(
        list(root.glob("*_persistence_audit.json"))
        + list(root.glob("*_missing_run_ids.json"))
    )
    return files[-1] if files else None


def _as_bool(value: Any) -> bool:
    return bool(value)


def _summarize(payload: dict[str, Any]) -> dict[str, Any]:
    rows = list(payload.get("rows") or [])
    total = len(rows)
    missing_rows = [row for row in rows if _as_bool(row.get("missing_static_run_id"))]
    missing_count = len(missing_rows)
    missing_rate = (missing_count / total) if total else 0.0

    max_streak = 0
    streak = 0
    for row in rows:
        if _as_bool(row.get("missing_static_run_id")):
            streak += 1
            max_streak = max(max_streak, streak)
        else:
            streak = 0

    classification_counts = Counter(str(row.get("classification") or "unknown") for row in missing_rows)
    stage_counts = Counter(str(row.get("stage") or "unknown") for row in missing_rows)
    disconnect_count = sum(1 for row in missing_rows if _as_bool(row.get("db_disconnect")))
    max_retry = max((int(row.get("retry_count") or 0) for row in missing_rows), default=0)

    return {
        "schema_version": payload.get("schema_version"),
        "db_schema_version": payload.get("db_schema_version"),
        "generated_at_utc": payload.get("generated_at_utc"),
        "session_stamp": payload.get("session_stamp"),
        "total_apps": total,
        "missing_static_run_id_count": missing_count,
        "missing_rate": round(missing_rate, 6),
        "max_missing_streak": max_streak,
        "db_disconnect_count": disconnect_count,
        "max_retry_count": max_retry,
        "classification_counts": dict(sorted(classification_counts.items())),
        "stage_counts": dict(sorted(stage_counts.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify static persistence audit artifact for systemic failures.")
    parser.add_argument(
        "--artifact",
        help="Path to a specific persistence audit artifact JSON. If omitted, latest under output/audit/persistence is used.",
    )
    parser.add_argument(
        "--audit-dir",
        default="output/audit/persistence",
        help="Directory containing persistence audit artifacts (default: output/audit/persistence).",
    )
    parser.add_argument(
        "--max-consecutive-missing",
        type=int,
        default=10,
        help="Fail if max consecutive missing_static_run_id reaches this value (default: 10).",
    )
    parser.add_argument(
        "--max-missing-rate",
        type=float,
        default=-1.0,
        help="Optional fail threshold in [0,1]. Disabled when < 0 (default).",
    )
    args = parser.parse_args(argv)

    artifact = Path(args.artifact).resolve() if args.artifact else _latest_artifact(Path(args.audit_dir))
    if artifact is None or not artifact.exists():
        print("FAIL: no persistence audit artifact found")
        return 2

    try:
        payload = json.loads(artifact.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: unable to parse artifact: {artifact} ({exc})")
        return 2

    summary = _summarize(payload)
    summary["artifact_path"] = str(artifact)
    print(json.dumps(summary, indent=2, sort_keys=True))

    failures: list[str] = []
    if int(summary["max_missing_streak"]) >= int(args.max_consecutive_missing):
        failures.append(
            f"max_missing_streak={summary['max_missing_streak']} >= threshold={args.max_consecutive_missing}"
        )
    if args.max_missing_rate >= 0 and float(summary["missing_rate"]) > float(args.max_missing_rate):
        failures.append(
            f"missing_rate={summary['missing_rate']} > threshold={args.max_missing_rate}"
        )

    if failures:
        print("FAIL: systemic missing run-id indicators detected")
        for item in failures:
            print(f" - {item}")
        return 1

    print("PASS: no systemic missing run-id indicators detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
