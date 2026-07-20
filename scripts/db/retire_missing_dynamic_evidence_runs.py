#!/usr/bin/env python3
"""Stage or apply DB-only retirement for missing dynamic evidence runs.

This is for dynamic runs whose evidence pack is missing locally and that have
already been classified by ``audit_dynamic_evidence_path_migration.py`` as
``missing_evidence_db_only_retirement_candidate``.

Dry-run is the default.  Apply mode deletes only DB rows scoped by the exact
run IDs from the audit receipt. It never deletes files and never changes quota
math directly.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

RETIREMENT_CLASS = "missing_evidence_db_only_retirement_candidate"


@dataclass(frozen=True)
class DeleteTarget:
    table_name: str
    columns: tuple[str, ...]
    row_count: int


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-audit",
        type=Path,
        required=True,
        help="Path to dynamic_evidence_path_migration receipt directory containing missing_runs.csv.",
    )
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "output" / "audit" / "missing_dynamic_evidence_retirement",
        help="Directory for timestamped retirement receipts.",
    )
    parser.add_argument("--expected-run-count", type=int, default=142, help="Refuse unless candidate run count matches.")
    parser.add_argument("--skip-cache-refresh", action="store_true", help="Do not rebuild derived static/dynamic summary cache after apply.")
    parser.add_argument("--apply", action="store_true", help="Delete scoped DB rows inside one transaction.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _read_missing_runs(audit_dir: Path) -> list[dict[str, Any]]:
    path = audit_dir / "missing_runs.csv"
    if not path.exists():
        raise FileNotFoundError(f"missing audit CSV: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _candidate_run_ids(rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    out: list[str] = []
    for row in rows:
        run_id = str(row.get("dynamic_run_id") or "").strip()
        classification = str(row.get("classification") or "").strip()
        target_exists = str(row.get("normalized_target_exists") or "").strip().lower() in {"1", "true", "yes"}
        ref_count = int(str(row.get("reference_hit_count") or "0").strip() or 0)
        if not run_id:
            continue
        if classification != RETIREMENT_CLASS:
            continue
        if target_exists or ref_count:
            continue
        out.append(run_id)
    return tuple(sorted(set(out)))


def _table_columns(run_sql: Any) -> dict[str, tuple[str, ...]]:
    rows = run_sql(
        """
        SELECT c.table_name, c.column_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
        WHERE c.table_schema = DATABASE()
          AND t.table_type = 'BASE TABLE'
          AND c.column_name IN ('dynamic_run_id', 'run_id')
          AND c.data_type IN ('char', 'varchar', 'text')
        ORDER BY c.table_name, c.column_name
        """,
        fetch="all_dict",
    ) or []
    by_table: dict[str, list[str]] = {}
    for row in rows:
        by_table.setdefault(str(row["table_name"]), []).append(str(row["column_name"]))
    return {table: tuple(cols) for table, cols in by_table.items()}


def _count_table(run_sql: Any, table: str, columns: Sequence[str], run_ids: Sequence[str]) -> int:
    if not run_ids:
        return 0
    placeholders = ",".join(["%s"] * len(run_ids))
    where = " OR ".join([f"{column} IN ({placeholders})" for column in columns])
    params: list[str] = []
    for _column in columns:
        params.extend(run_ids)
    row = run_sql(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", tuple(params), fetch="one_dict") or {}
    return int(row.get("n") or 0)


def _build_delete_targets(run_sql: Any, run_ids: Sequence[str]) -> tuple[DeleteTarget, ...]:
    targets: list[DeleteTarget] = []
    for table, columns in _table_columns(run_sql).items():
        count = _count_table(run_sql, table, columns, run_ids)
        if count <= 0:
            continue
        targets.append(DeleteTarget(table_name=table, columns=columns, row_count=count))

    def order_key(target: DeleteTarget) -> tuple[int, str]:
        if target.table_name == "dynamic_sessions":
            return (999, target.table_name)
        return (0, target.table_name)

    return tuple(sorted(targets, key=order_key))


def _count_cache_references(run_sql: Any, run_ids: Sequence[str]) -> dict[str, int]:
    if not run_ids:
        return {}
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = 'web_static_dynamic_app_summary_cache'
          AND table_type = 'BASE TABLE'
        """,
        fetch="one_dict",
    ) or {}
    if int(row.get("n") or 0) <= 0:
        return {}
    placeholders = ",".join(["%s"] * len(run_ids))
    out: dict[str, int] = {}
    for column in ("latest_dynamic_run_id", "latest_feature_dynamic_run_id"):
        exists = run_sql(
            """
            SELECT COUNT(*) AS n
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'web_static_dynamic_app_summary_cache'
              AND column_name = %s
            """,
            (column,),
            fetch="one_dict",
        ) or {}
        if int(exists.get("n") or 0) <= 0:
            out[column] = 0
            continue
        count = run_sql(
            f"SELECT COUNT(*) AS n FROM web_static_dynamic_app_summary_cache WHERE {column} IN ({placeholders})",
            tuple(run_ids),
            fetch="one_dict",
        ) or {}
        out[column] = int(count.get("n") or 0)
    return out


def _delete_target(run_sql_rowcount: Any, target: DeleteTarget, run_ids: Sequence[str], *, chunk_size: int = 100) -> int:
    total = 0
    ids = list(run_ids)
    for i in range(0, len(ids), chunk_size):
        batch = ids[i : i + chunk_size]
        placeholders = ",".join(["%s"] * len(batch))
        where = " OR ".join([f"{column} IN ({placeholders})" for column in target.columns])
        params: list[str] = []
        for _column in target.columns:
            params.extend(batch)
        total += int(
            run_sql_rowcount(
                f"DELETE FROM {target.table_name} WHERE {where}",
                tuple(params),
                query_name="missing_dynamic_evidence_retirement.delete",
            )
        )
    return total


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _write_run_ids(path: Path, run_ids: Sequence[str]) -> None:
    path.write_text("".join(f"{run_id}\n" for run_id in run_ids), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    audit_dir = args.from_audit
    missing_rows = _read_missing_runs(audit_dir)
    run_ids = _candidate_run_ids(missing_rows)
    if len(run_ids) != int(args.expected_run_count):
        sys.stderr.write(
            "Refusing retirement: candidate run count mismatch "
            f"got={len(run_ids)} expected={int(args.expected_run_count)}\n"
        )
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    receipt_dir = args.receipt_dir / stamp
    receipt_dir.mkdir(parents=True, exist_ok=True)

    try:
        with database_session(reuse_connection=False) as db:
            targets_before = _build_delete_targets(core_q.run_sql, run_ids)
            cache_refs_before = _count_cache_references(core_q.run_sql, run_ids)
            apply_rows: list[dict[str, Any]] = []
            cache_refresh: dict[str, Any] = {"requested": bool(args.apply and not args.skip_cache_refresh), "inserted": 0, "materialized_at_utc": ""}
            if args.apply:
                with db.transaction():
                    for target in targets_before:
                        deleted = _delete_target(core_q.run_sql_rowcount, target, run_ids)
                        apply_rows.append(
                            {
                                "table_name": target.table_name,
                                "columns": ",".join(target.columns),
                                "rows_before": target.row_count,
                                "rows_deleted": deleted,
                            }
                        )
                    targets_after = _build_delete_targets(core_q.run_sql, run_ids)
                if not args.skip_cache_refresh:
                    from scytaledroid.Database.summary_surfaces import (
                        refresh_static_dynamic_summary_cache,
                    )

                    inserted, materialized_at = refresh_static_dynamic_summary_cache(reuse_connection=True)
                    cache_refresh = {
                        "requested": True,
                        "inserted": int(inserted),
                        "materialized_at_utc": materialized_at.isoformat(),
                    }
                cache_refs_after = _count_cache_references(core_q.run_sql, run_ids)
            else:
                targets_after = targets_before
                cache_refs_after = cache_refs_before
                apply_rows = [
                    {
                        "table_name": target.table_name,
                        "columns": ",".join(target.columns),
                        "rows_before": target.row_count,
                        "rows_deleted": 0,
                    }
                    for target in targets_before
                ]
    except Exception as exc:
        sys.stderr.write(f"Missing dynamic evidence retirement failed: {type(exc).__name__}: {exc}\n")
        return 2

    target_rows = [
        {
            "table_name": target.table_name,
            "columns": ",".join(target.columns),
            "row_count": target.row_count,
        }
        for target in targets_before
    ]
    after_rows = [
        {
            "table_name": target.table_name,
            "columns": ",".join(target.columns),
            "row_count": target.row_count,
        }
        for target in targets_after
    ]
    summary: dict[str, Any] = {
        "mode": "apply" if args.apply else "dry_run",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "source_audit_dir": str(audit_dir),
        "candidate_run_count": len(run_ids),
        "target_table_count": len(targets_before),
        "target_row_count_before": sum(target.row_count for target in targets_before),
        "target_row_count_after": sum(target.row_count for target in targets_after),
        "rows_deleted": sum(int(row["rows_deleted"]) for row in apply_rows),
        "derived_cache_references_before": cache_refs_before,
        "derived_cache_references_after": cache_refs_after,
        "cache_refresh": cache_refresh,
        "receipts": {
            "summary": str(receipt_dir / "summary.json"),
            "run_ids": str(receipt_dir / "run_ids.txt"),
            "targets": str(receipt_dir / "targets.csv"),
            "apply_actions": str(receipt_dir / "apply_actions.csv"),
            "after_targets": str(receipt_dir / "after_targets.csv"),
        },
    }

    _write_json(receipt_dir / "summary.json", summary)
    _write_run_ids(receipt_dir / "run_ids.txt", run_ids)
    _write_csv(receipt_dir / "targets.csv", target_rows, ["table_name", "columns", "row_count"])
    _write_csv(receipt_dir / "apply_actions.csv", apply_rows, ["table_name", "columns", "rows_before", "rows_deleted"])
    _write_csv(receipt_dir / "after_targets.csv", after_rows, ["table_name", "columns", "row_count"])

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    else:
        print(f"mode: {summary['mode']}")
        print(f"candidate_run_count: {summary['candidate_run_count']}")
        print(f"target_table_count: {summary['target_table_count']}")
        print(f"target_row_count_before: {summary['target_row_count_before']}")
        print(f"rows_deleted: {summary['rows_deleted']}")
        print(f"target_row_count_after: {summary['target_row_count_after']}")
        print(f"receipt: {receipt_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
