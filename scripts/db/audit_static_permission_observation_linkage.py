#!/usr/bin/env python3
"""Read-only core-DB check: static_permission_matrix → run → SHA-256 / apk / versions.

Uses ``SCYTALEDROID_DB_*`` (operational catalog). **No DML/DDL.**

Supports future S2 observation transforms: confirms whether joins can supply
``permission_string``, ``static_run_id``, ``base_apk_sha256``, ``apk_id``, package/version.

Run::

  PYTHONPATH=. python scripts/db/audit_static_permission_observation_linkage.py

Exit codes:
  0 — report complete
  1 — import / connection error
"""

from __future__ import annotations

import argparse
import sys
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-limit", type=int, default=5, help="Rows for sample join output.")
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (PYTHONPATH=.): {exc}\n")
        return 1

    run_sql = core_q.run_sql

    print("# Static permission → observation linkage (read-only, core DB)")

    def scalar(sql: str, params: tuple[Any, ...] = ()) -> int | None:
        try:
            row = run_sql(sql, params, fetch="one")
            if row is None:
                return None
            return int(row[0] if not isinstance(row, dict) else next(iter(row.values())) or 0)
        except Exception as exc:  # pragma: no cover
            print(f"  ERROR: {exc}")
            return None

    def has_column(table: str, column: str) -> bool:
        try:
            n = scalar(
                """
                SELECT COUNT(*) FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_NAME = %s
                """,
                (table, column),
            )
            return bool(n)
        except Exception:
            return False

    for tbl, col in (
        ("static_permission_matrix", "run_id"),
        ("static_analysis_runs", "base_apk_sha256"),
        ("static_analysis_runs", "app_version_id"),
        ("app_versions", "version_code"),
        ("app_versions", "version_name"),
        ("android_apk_repository", "sha256"),
    ):
        ok = has_column(tbl, col)
        print(f"  column {tbl}.{col}: {'YES' if ok else 'NO'}")

    total_m = scalar("SELECT COUNT(*) FROM static_permission_matrix")
    print(f"\n## static_permission_matrix rows: {total_m}")

    if not has_column("static_analysis_runs", "base_apk_sha256"):
        print("  Skip join checks: static_analysis_runs.base_apk_sha256 missing.")
        return 0

    missing_sha = scalar(
        """
        SELECT COUNT(*)
        FROM static_permission_matrix spm
        JOIN static_analysis_runs sar ON sar.id = spm.run_id
        WHERE sar.base_apk_sha256 IS NULL OR TRIM(sar.base_apk_sha256) = ''
        """
    )
    print(f"  matrix rows joined to run with NULL/empty base_apk_sha256: {missing_sha}")

    null_apk = scalar(
        """
        SELECT COUNT(*) FROM static_permission_matrix WHERE apk_id IS NULL
        """
    )
    print(f"  matrix rows with apk_id IS NULL: {null_apk}")

    if has_column("android_apk_repository", "sha256") and has_column("static_permission_matrix", "apk_id"):
        mismatch = scalar(
            """
            SELECT COUNT(*)
            FROM static_permission_matrix spm
            JOIN static_analysis_runs sar ON sar.id = spm.run_id
            LEFT JOIN android_apk_repository r ON r.id = spm.apk_id
            WHERE spm.apk_id IS NOT NULL
              AND r.sha256 IS NOT NULL
              AND sar.base_apk_sha256 IS NOT NULL
              AND LOWER(TRIM(r.sha256)) <> LOWER(TRIM(sar.base_apk_sha256))
            """
        )
        print(f"  rows where repository.sha256 differs from run.base_apk_sha256 (when both set): {mismatch}")

    lim = max(1, min(int(args.sample_limit), 50))
    try:
        sample = run_sql(
            f"""
            SELECT spm.run_id, spm.apk_id, spm.package_name, spm.permission_name,
                   sar.base_apk_sha256, sar.session_stamp, sar.status,
                   av.version_code, av.version_name
            FROM static_permission_matrix spm
            JOIN static_analysis_runs sar ON sar.id = spm.run_id
            LEFT JOIN app_versions av ON av.id = sar.app_version_id
            ORDER BY spm.id DESC
            LIMIT {lim}
            """,
            fetch="all",
        )
    except Exception as exc:
        print(f"  sample join failed: {exc}")
        return 0

    print(f"\n## Sample rows (latest {lim} matrix permissions)")
    for row in sample or []:
        if isinstance(row, dict):
            print(f"  {row}")
        else:
            print(f"  {row}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
