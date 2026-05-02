#!/usr/bin/env python3
"""Validate Permission Intel DB env + connectivity + governance snapshot rows.

Uses the same resolution rules as ``scytaledroid.Database.db_core.permission_intel``:
  - ``SCYTALEDROID_PERMISSION_INTEL_DB_URL`` (mysql/mariadb DSN), or
  - ``SCYTALEDROID_PERMISSION_INTEL_DB_NAME``, ``USER``, ``PASSWD``, ``HOST``, ``PORT``

Password env suffix is **PASSWD** (not ``PASS``), matching ``db_config.resolve_db_config_from_root``.

Example::

  PYTHONPATH=. python scripts/db/check_permission_intel.py
"""

from __future__ import annotations

import argparse
import os
import sys


def _main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Permission Intel DB env + connectivity + governance snapshot rows "
            "(same rules as scytaledroid.Database.db_core.permission_intel)."
        ),
    )
    parser.parse_args()

    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db
        from scytaledroid.StaticAnalysis.cli.execution.pipeline import governance_ready
        from scytaledroid.Database.db_utils import diagnostics as db_diag
    except ImportError as e:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {e}\n")
        return 2

    print("# Operational DB (SCYTALEDROID_DB_*) — optional quick ping")
    try:
        if db_diag.check_connection():
            ver = db_diag.get_schema_version()
            print(f"  main_db: OK (schema_version={ver or 'unknown'})")
        else:
            print("  main_db: connection failed (check SCYTALEDROID_DB_*)")
    except Exception as exc:
        print(f"  main_db: ERROR {exc}")

    print("# Permission Intel configuration")
    url_set = bool((os.environ.get("SCYTALEDROID_PERMISSION_INTEL_DB_URL") or "").strip())
    name_set = bool((os.environ.get("SCYTALEDROID_PERMISSION_INTEL_DB_NAME") or "").strip())
    if url_set and name_set:
        print(
            "  note: both SCYTALEDROID_PERMISSION_INTEL_DB_URL and …_NAME are set; "
            "db_config uses the URL when non-empty (piecemeal HOST/USER/PASSWD are ignored)."
        )

    if not intel_db.is_permission_intel_configured():
        print("  permission_intel_db: NOT CONFIGURED")
        print(
            "  hint: set SCYTALEDROID_PERMISSION_INTEL_DB_URL "
            "or SCYTALEDROID_PERMISSION_INTEL_DB_NAME/USER/PASSWD/HOST/PORT"
        )
        print("  paper_grade_ready: no (CLI cannot resolve intel DSN)")
        return 1

    try:
        summary = intel_db.describe_target()
        print(f"  permission_intel_db: configured ({summary.get('source')})")
        print(
            f"  target: host={summary.get('host')} port={summary.get('port')} "
            f"database={summary.get('database')} user={summary.get('user')}"
        )
    except Exception as exc:
        print(f"  permission_intel_db: describe_target ERROR {exc}")
        return 1

    print("# Managed tables (existence)")
    missing_tables: list[str] = []
    for table in intel_db.MANAGED_TABLES:
        try:
            ok = intel_db.intel_table_exists(table)
            print(f"  {'OK' if ok else 'MISSING':7}  {table}")
            if not ok:
                missing_tables.append(table)
        except Exception as exc:
            print(f"  ERROR   {table} ({exc})")
            missing_tables.append(table)

    print("# Dictionary / governance row counts")
    try:
        aosp = intel_db.run_sql(
            f"SELECT COUNT(*) FROM {intel_db.AOSP_DICT_TABLE}",
            fetch="one",
            query_name="check_permission_intel.aosp_count",
            read_only=True,
        )
        oem = intel_db.run_sql(
            f"SELECT COUNT(*) FROM {intel_db.OEM_DICT_TABLE}",
            fetch="one",
            query_name="check_permission_intel.oem_count",
            read_only=True,
        )
        unk = intel_db.run_sql(
            f"SELECT COUNT(*) FROM {intel_db.UNKNOWN_DICT_TABLE}",
            fetch="one",
            query_name="check_permission_intel.unknown_count",
            read_only=True,
        )
        que = intel_db.run_sql(
            f"SELECT COUNT(*) FROM {intel_db.QUEUE_DICT_TABLE}",
            fetch="one",
            query_name="check_permission_intel.queue_count",
            read_only=True,
        )
        gov_snaps = intel_db.governance_snapshot_count()
        gov_rows = intel_db.governance_row_count()
        print(f"  aosp_dict_rows: {int(aosp[0] or 0) if aosp else 0}")
        print(f"  oem_dict_rows: {int(oem[0] or 0) if oem else 0}")
        print(f"  unknown_dict_rows: {int(unk[0] or 0) if unk else 0}")
        print(f"  queue_rows: {int(que[0] or 0) if que else 0}")
        print(f"  governance_snapshots: {gov_snaps}")
        print(f"  governance_snapshot_rows: {gov_rows}")
    except Exception as exc:
        print(f"  counts: ERROR {exc}")
        print("  paper_grade_ready: no (query failed)")
        return 1

    ok_gov, gov_detail = governance_ready()
    print("# Paper-grade governance gate (same as static CLI)")
    print(f"  governance_ready: {ok_gov} ({gov_detail or 'ok'})")
    print(f"  paper_grade_ready: {'yes' if ok_gov else 'no'}")
    if not ok_gov and gov_detail == "governance_missing":
        print(
            "  note: load governance CSV into permission_governance_snapshots / "
            "permission_governance_snapshot_rows (see Utils/System/governance_inputs.py)."
        )

    if missing_tables:
        print(f"# WARNING: missing tables: {', '.join(missing_tables)}")
        return 1

    # Exit 2 when configured but paper-grade governance rows are absent (operator reminder).
    return 2 if not ok_gov else 0


if __name__ == "__main__":
    raise SystemExit(_main())
