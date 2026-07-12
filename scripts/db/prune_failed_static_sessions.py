#!/usr/bin/env python3
"""Prune superseded failed static-analysis sessions (dry-run by default).

Policy:
- only ``interrupted_partial_session`` sessions
- only sessions with zero completed runs and one or more failed runs
- only sessions older than the age gate
- only sessions already superseded by a later completed full session

This is intentionally session-scoped, not row-by-row deletion.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class FailedStaticSessionCandidate:
    session_stamp: str
    scope_label: str
    session_disposition: str
    cleanup_status: str
    total_run_count: int
    completed_run_count: int
    failed_run_count: int
    first_created_at: str | None
    last_ended_at: str | None
    superseding_session_stamp: str
    superseding_disposition: str
    superseding_last_ended_at: str | None
    age_days: int


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prune superseded failed static-analysis sessions (dry-run unless --apply).",
    )
    parser.add_argument(
        "--older-than-days",
        type=int,
        default=7,
        help="Minimum age gate for failed sessions (default: 7).",
    )
    parser.add_argument(
        "--session",
        action="append",
        default=[],
        help="Optional exact session_stamp target(s). If omitted, auto-select by policy.",
    )
    parser.add_argument(
        "--receipt-dir",
        default="data/state/static_failed_session_prune",
        help="Directory for dry-run/apply receipts (default: data/state/static_failed_session_prune).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the session-scoped prune. Default is dry-run only.",
    )
    return parser.parse_args()


def _dt_to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    return str(value)


def _parse_db_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _select_candidates(
    rows: list[dict[str, Any]],
    *,
    older_than_days: int,
    now: datetime,
    only_sessions: set[str] | None = None,
) -> list[FailedStaticSessionCandidate]:
    threshold = max(0, int(older_than_days))
    out: list[FailedStaticSessionCandidate] = []
    for row in rows:
        session_stamp = str(row.get("session_stamp") or "").strip()
        if not session_stamp:
            continue
        if only_sessions and session_stamp not in only_sessions:
            continue

        disposition = str(row.get("session_disposition") or "").strip()
        cleanup_status = str(row.get("cleanup_status") or "").strip() or "none"
        total_runs = int(row.get("total_run_count") or 0)
        completed_runs = int(row.get("completed_run_count") or 0)
        failed_runs = int(row.get("failed_run_count") or 0)
        superseding_stamp = str(row.get("superseding_session_stamp") or "").strip()
        superseding_disposition = str(row.get("superseding_disposition") or "").strip()
        ended_at = _parse_db_dt(row.get("last_ended_at"))

        if disposition != "interrupted_partial_session":
            continue
        if completed_runs != 0 or failed_runs <= 0 or total_runs != failed_runs:
            continue
        if not superseding_stamp or superseding_disposition != "completed_full_session":
            continue
        if ended_at is None:
            continue

        age_days = int((now - ended_at).days)
        if age_days < threshold:
            continue

        out.append(
            FailedStaticSessionCandidate(
                session_stamp=session_stamp,
                scope_label=str(row.get("scope_label") or ""),
                session_disposition=disposition,
                cleanup_status=cleanup_status,
                total_run_count=total_runs,
                completed_run_count=completed_runs,
                failed_run_count=failed_runs,
                first_created_at=_dt_to_text(row.get("first_created_at")),
                last_ended_at=_dt_to_text(row.get("last_ended_at")),
                superseding_session_stamp=superseding_stamp,
                superseding_disposition=superseding_disposition,
                superseding_last_ended_at=_dt_to_text(row.get("superseding_last_ended_at")),
                age_days=age_days,
            )
        )
    return sorted(out, key=lambda item: (item.last_ended_at or "", item.session_stamp))


def _write_receipts(receipt_dir: Path, payload: dict[str, Any]) -> tuple[Path, Path]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = receipt_dir / f"static_failed_session_prune_{stamp}.json"
    csv_path = receipt_dir / f"static_failed_session_prune_{stamp}.csv"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    rows = payload.get("candidates") or []
    fieldnames = [
        "session_stamp",
        "scope_label",
        "session_disposition",
        "cleanup_status",
        "total_run_count",
        "completed_run_count",
        "failed_run_count",
        "last_ended_at",
        "superseding_session_stamp",
        "superseding_disposition",
        "superseding_last_ended_at",
        "age_days",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})
    return json_path, csv_path


def main() -> int:
    args = _parse_args()

    try:
        from scytaledroid.Database.db_core import run_sql
        from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    session_targets = {str(item).strip() for item in (args.session or []) if str(item).strip()}
    query = """
    SELECT
      h.session_stamp,
      h.scope_label,
      h.session_disposition,
      h.cleanup_status,
      h.total_run_count,
      h.completed_run_count,
      h.failed_run_count,
      h.first_created_at,
      h.last_ended_at,
      s.superseding_session_stamp,
      s.superseding_disposition,
      s.superseding_last_ended_at
    FROM v_static_session_health_v2 h
    LEFT JOIN (
      SELECT
        ranked.candidate_session_stamp,
        ranked.candidate_scope_label,
        ranked.superseding_session_stamp,
        ranked.superseding_disposition,
        ranked.superseding_last_ended_at
      FROM (
        SELECT
          bad.session_stamp AS candidate_session_stamp,
          bad.scope_label AS candidate_scope_label,
          good.session_stamp AS superseding_session_stamp,
          good.session_disposition AS superseding_disposition,
          good.last_ended_at AS superseding_last_ended_at,
          ROW_NUMBER() OVER (
            PARTITION BY bad.static_session_id
            ORDER BY good.last_ended_at DESC, good.static_session_id DESC
          ) AS rn
        FROM v_static_session_health_v2 bad
        JOIN v_static_session_health_v2 good
          ON good.scope_label = bad.scope_label
         AND good.session_disposition = 'completed_full_session'
         AND good.last_ended_at > bad.last_ended_at
      ) ranked
      WHERE ranked.rn = 1
    ) s
      ON s.candidate_session_stamp = h.session_stamp
     AND s.candidate_scope_label = h.scope_label
    WHERE h.failed_run_count > 0
    ORDER BY h.last_ended_at ASC, h.session_stamp ASC
    """
    rows = run_sql(query, fetch="all_dict") or []
    now = datetime.now(UTC).replace(tzinfo=None)
    candidates = _select_candidates(
        rows,
        older_than_days=args.older_than_days,
        now=now,
        only_sessions=session_targets or None,
    )

    payload: dict[str, Any] = {
        "schema": "scytaledroid.static_failed_session_prune.v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "mode": "apply" if args.apply else "dry_run",
        "older_than_days": int(args.older_than_days),
        "session_targets": sorted(session_targets),
        "candidate_count": len(candidates),
        "candidates": [asdict(item) for item in candidates],
    }

    print(f"Mode              : {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"Age gate          : {int(args.older_than_days)} day(s)")
    print(f"Candidate sessions: {len(candidates)}")
    if not candidates:
        print("No failed static sessions matched the prune policy.")
        return 0

    for item in candidates:
        print(
            f"- {item.session_stamp} | failed {item.failed_run_count}/{item.total_run_count} | "
            f"age {item.age_days}d | superseded by {item.superseding_session_stamp}"
        )

    receipt_dir = Path(args.receipt_dir)
    json_path, csv_path = _write_receipts(receipt_dir, payload)
    print(f"Receipt JSON      : {json_path}")
    print(f"Receipt CSV       : {csv_path}")

    if not args.apply:
        print("Dry-run complete. Re-run with --apply to prune the listed sessions.")
        return 0

    applied: list[dict[str, Any]] = []
    for item in candidates:
        before = run_sql(
            "SELECT COUNT(*) AS c FROM static_analysis_runs WHERE session_stamp=%s",
            (item.session_stamp,),
            fetch="one_dict",
        ) or {"c": 0}
        outcome = reset_static_analysis_data(session_label=item.session_stamp)
        after = run_sql(
            "SELECT COUNT(*) AS c FROM static_analysis_runs WHERE session_stamp=%s",
            (item.session_stamp,),
            fetch="one_dict",
        ) or {"c": 0}
        applied.append(
            {
                "session_stamp": item.session_stamp,
                "before_static_analysis_runs": int(before.get("c") or 0),
                "after_static_analysis_runs": int(after.get("c") or 0),
                "outcome": {
                    "truncated": list(outcome.truncated),
                    "cleared": list(outcome.cleared),
                    "skipped_protected": list(outcome.skipped_protected),
                    "skipped_missing": list(outcome.skipped_missing),
                    "failed": list(outcome.failed),
                    "static_run_ids": list(outcome.static_run_ids),
                },
            }
        )
        print(
            f"Applied           : {item.session_stamp} | "
            f"rows {int(before.get('c') or 0)} -> {int(after.get('c') or 0)}"
        )

    payload["applied"] = applied
    _write_receipts(receipt_dir, payload)
    print("Apply complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
