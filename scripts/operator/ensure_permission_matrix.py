#!/usr/bin/env python3
"""
Ensure the static_permission_matrix table exists (idempotent helper).

Usage:
    python scripts/ensure_permission_matrix.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ensure the static_permission_matrix table exists and inspect latest run coverage.")
    parser.parse_args(argv)

    from scytaledroid.Database.db_core import run_sql
    from scytaledroid.Database.db_func.static_analysis import static_permission_matrix

    if static_permission_matrix.ensure_table():
        print("static_permission_matrix table is ready.")
    else:
        print("Failed to ensure static_permission_matrix table.", file=sys.stderr)
        return 1

    latest = run_sql(
        """
        SELECT sar.id, sar.session_stamp, apps.package_name
        FROM static_analysis_runs sar
        JOIN app_versions av ON sar.app_version_id = av.id
        JOIN apps ON av.app_id = apps.id
        ORDER BY sar.id DESC
        LIMIT 1
        """,
        fetch="one",
        dictionary=True,
    )

    if not latest:
        print("No static_analysis_runs found.")
        return 0

    run_id = latest["id"]
    package = latest["package_name"]
    session = latest["session_stamp"]
    print(f"Latest run_id={run_id} (package={package}, session={session})")

    try:
        matrix_total = run_sql(
            "SELECT COUNT(*) FROM static_permission_matrix WHERE run_id = %s",
            (run_id,),
            fetch="one",
        )
        count = int(matrix_total[0]) if matrix_total else 0
        print(f"Matrix rows for latest run: {count}")
        if count == 0:
            print(
                "Hint: Enable the 'Post-run permission refresh' option (or set "
                "SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=1) before running static analysis "
                "to populate the permission matrix.",
                file=sys.stderr,
            )
    except Exception as exc:
        print(f"Unable to count matrix rows: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
