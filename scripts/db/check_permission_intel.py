#!/usr/bin/env python3
"""Validate Permission Intel DB env + connectivity + governance snapshot rows.

Expected catalog (typical): **android_permission_intel**. Uses the same resolution rules as
``scytaledroid.Database.db_core.permission_intel``:
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
        from scytaledroid.Database.db_utils import diagnostics as db_diag
        from scytaledroid.StaticAnalysis.cli.intel_gate import governance_ready
    except ImportError as e:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {e}\n")
        return 2

    print("# OPTIONAL — Core analyst DB quick ping (SCYTALEDROID_DB_*)")
    try:
        if db_diag.check_connection():
            ver = db_diag.get_schema_version()
            print(f"  INFO main_db: OK (schema_version={ver or 'unknown'})")
        else:
            print("  WARN main_db: connection failed (check SCYTALEDROID_DB_*)")
    except Exception as exc:
        print(f"  ERROR main_db: {exc}")

    print("# PERMISSION INTEL — configuration (dictionary catalog; not static scan results)")
    url_set = bool((os.environ.get("SCYTALEDROID_PERMISSION_INTEL_DB_URL") or "").strip())
    name_set = bool((os.environ.get("SCYTALEDROID_PERMISSION_INTEL_DB_NAME") or "").strip())
    if url_set and name_set:
        print(
            "  INFO note: both SCYTALEDROID_PERMISSION_INTEL_DB_URL and …_NAME are set; "
            "db_config uses the URL when non-empty (piecemeal HOST/USER/PASSWD are ignored)."
        )

    if not intel_db.is_permission_intel_configured():
        print("  ERROR permission_intel_db: NOT CONFIGURED")
        print(
            "  INFO hint: set SCYTALEDROID_PERMISSION_INTEL_DB_URL "
            "or SCYTALEDROID_PERMISSION_INTEL_DB_NAME/USER/PASSWD/HOST/PORT"
        )
        print("  INFO paper_grade_ready: no (CLI cannot resolve intel DSN)")
        return 1

    try:
        summary = intel_db.describe_target()
        print(f"  INFO permission_intel_db: configured ({summary.get('source')})")
        print(
            f"  INFO target: host={summary.get('host')} port={summary.get('port')} "
            f"database={summary.get('database')} user={summary.get('user')}"
        )
    except Exception as exc:
        print(f"  ERROR permission_intel_db: describe_target failed: {exc}")
        return 1

    print("# PERMISSION INTEL — managed tables (existence; CANONICAL for this catalog)")
    missing_tables: list[str] = []
    for table in intel_db.MANAGED_TABLES:
        try:
            ok = intel_db.intel_table_exists(table)
            print(f"  {'OK' if ok else 'ERROR MISSING':16}  {table}")
            if not ok:
                missing_tables.append(table)
        except Exception as exc:
            print(f"  ERROR            {table} ({exc})")
            missing_tables.append(table)

    if not missing_tables:
        print("# PERMISSION INTEL — dictionary read probe (DB menu / static readiness use same probe)")
        try:
            probe_ok = intel_db.probe_dictionary_read_access()
            print(f"  INFO dictionary_select: {'OK' if probe_ok else 'FAILED (AOSP dict unreadable)'}")
        except Exception as exc:
            print(f"  ERROR dictionary_select: probe failed ({exc})")

    print("# PERMISSION INTEL — dictionary / governance row counts (DERIVED / operational)")
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
        print(f"  INFO aosp_dict_rows: {int(aosp[0] or 0) if aosp else 0}")
        print(f"  INFO oem_dict_rows: {int(oem[0] or 0) if oem else 0}")
        print(f"  INFO unknown_dict_rows: {int(unk[0] or 0) if unk else 0}")
        print(f"  INFO queue_rows: {int(que[0] or 0) if que else 0}")
        print(f"  INFO governance_snapshots: {gov_snaps}")
        print(f"  INFO governance_snapshot_rows: {gov_rows}")
    except Exception as exc:
        print(f"  ERROR counts: {exc}")
        print("  INFO paper_grade_ready: no (query failed)")
        return 1

    ok_gov, gov_detail = governance_ready()
    print("# OPTIONAL — paper-grade governance gate (same signal as static CLI)")
    print(f"  INFO governance_ready: {ok_gov} ({gov_detail or 'ok'})")
    print(f"  INFO paper_grade_ready: {'yes' if ok_gov else 'no'}")
    if not ok_gov and gov_detail == "governance_missing":
        print(
            "  INFO note: load governance CSV into permission_governance_snapshots / "
            "permission_governance_snapshot_rows (see Utils/System/governance_inputs.py)."
        )

    if missing_tables:
        print(f"# ERROR: managed Permission Intel tables missing: {', '.join(missing_tables)}")
        return 1

    # Exit 2 when configured but paper-grade governance rows are absent (operator reminder).
    return 2 if not ok_gov else 0


if __name__ == "__main__":
    raise SystemExit(_main())
