#!/usr/bin/env python3
"""Print the latest static-analysis run metadata for convenience."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    from scytaledroid.Database.db_core import run_sql

    row = run_sql(
        """
        SELECT sar.id,
               sar.session_stamp,
               sar.profile,
               sar.scope_label,
               apps.package_name,
               av.version_name
        FROM static_analysis_runs sar
        JOIN app_versions av ON sar.app_version_id = av.id
        JOIN apps ON av.app_id = apps.id
        ORDER BY sar.id DESC
        LIMIT 1
        """,
        fetch="one",
        dictionary=True,
    )
    if not row:
        print("No static_analysis_runs found.")
        return 1

    print(
        "Latest run:\n"
        f"  id           : {row['id']}\n"
        f"  session      : {row['session_stamp']}\n"
        f"  package      : {row['package_name']}\n"
        f"  version      : {row['version_name']}\n"
        f"  profile      : {row['profile']}\n"
        f"  scope label  : {row['scope_label'] or '—'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
