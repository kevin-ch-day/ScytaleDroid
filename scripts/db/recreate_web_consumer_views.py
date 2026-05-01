#!/usr/bin/env python3
"""Recreate ScytaleDroid web-facing SQL views from repo DDL.

Connection (same env keys as tooling elsewhere):
  SCYTALEDROID_DB_HOST, SCYTALEDROID_DB_PORT, SCYTALEDROID_DB_USER,
  SCYTALEDROID_DB_PASS, SCYTALEDROID_DB_NAME

Usage:
  python scripts/db/recreate_web_consumer_views.py posture          # reports only
  python scripts/db/recreate_web_consumer_views.py counts           # key row counts
  python scripts/db/recreate_web_consumer_views.py recreate --dry-run
  python scripts/db/recreate_web_consumer_views.py recreate \\
      --apply-safe-alters --drop-conflicting-tables --confirm

Destructive paths require --confirm. Take a backup first — see docs/maintenance/database_governance_runbook.md.
"""

from __future__ import annotations

import argparse
import os
import sys


def _connect():
    try:
        import pymysql  # type: ignore[import-untyped]
    except ImportError as e:
        raise RuntimeError(
            "pymysql is required. Install dev/runtime deps or: pip install pymysql"
        ) from e

    host = os.environ.get("SCYTALEDROID_DB_HOST", "localhost")
    port = int(os.environ.get("SCYTALEDROID_DB_PORT", "3306"))
    user = os.environ.get("SCYTALEDROID_DB_USER") or os.environ.get("MYSQL_USER")
    password = os.environ.get("SCYTALEDROID_DB_PASS") or os.environ.get("MYSQL_PASSWORD", "")
    database = os.environ.get("SCYTALEDROID_DB_NAME") or os.environ.get("MYSQL_DATABASE")
    if not user or not database:
        sys.stderr.write(
            "Set SCYTALEDROID_DB_USER and SCYTALEDROID_DB_NAME (and password) in the environment.\n"
        )
        sys.exit(2)
    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        charset="utf8mb4",
    )


CONFLICT_TABLE_CANDIDATES: tuple[str, ...] = (
    "v_web_permission_intel_current",
    "v_web_app_report_summary",
    "v_web_app_component_acl",
    "v_web_app_component_summary",
    "v_web_app_components",
    "v_web_app_string_samples",
    "v_web_app_string_summary",
    "v_web_app_findings",
    "v_web_app_permission_summary",
    "v_web_app_permissions",
    "v_web_app_sessions",
    "v_web_static_session_health",
    "v_web_runtime_run_detail",
    "v_web_runtime_run_index",
    "v_web_static_dynamic_app_summary",
    "v_web_app_directory",
    "vw_static_finding_surfaces_latest",
    "vw_static_risk_surfaces_latest",
    "vw_permission_audit_latest",
)


def _table_type(cur, name: str) -> str | None:
    cur.execute(
        """
        SELECT TABLE_TYPE FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        """,
        (name,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def _col_exists(cur, table: str, col: str) -> bool:
    cur.execute(
        """
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s AND COLUMN_NAME = %s LIMIT 1
        """,
        (table, col),
    )
    return cur.fetchone() is not None


def cmd_posture() -> int:
    conn = _connect()
    conn.autocommit(True)
    with conn.cursor() as cur:
        print("# Tables named v_* / vw_* that are BASE TABLE")
        cur.execute(
            """
            SELECT TABLE_NAME, TABLE_TYPE, TABLE_ROWS
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
              AND (TABLE_NAME LIKE 'v_web\\_%' ESCAPE '\\\\'
                   OR TABLE_NAME LIKE 'vw\\_%' ESCAPE '\\\\')
              AND TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME
            """
        )
        rows = cur.fetchall()
        if not rows:
            print("  (none — OK)")
        for r in rows:
            print(f"  BAD  {r[0]:50} rows~{r[2]}")

        print("# Missing canonical VIEWs")
        wanted = (
            "v_web_app_directory",
            "vw_static_finding_surfaces_latest",
            "vw_static_risk_surfaces_latest",
            "v_web_app_sessions",
            "v_web_app_findings",
            "v_web_permission_intel_current",
        )
        for name in wanted:
            typ = _table_type(cur, name)
            if typ is None:
                print(f"  MISSING {name}")
            elif typ != "VIEW":
                print(f"  WRONG_TYPE {name} -> {typ}")
            else:
                print(f"  OK {name}")

        print("# UTF-8 posture sample (latin1 cols on hotspot tables)")
        cur.execute(
            """
            SELECT TABLE_NAME, COLUMN_NAME, CHARACTER_SET_NAME, COLLATION_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME IN (
                'apps', 'static_fileproviders', 'static_provider_acl',
                'static_analysis_findings'
              )
              AND DATA_TYPE IN ('varchar','char','text','tinytext','mediumtext','longtext')
              AND CHARACTER_SET_NAME IS NOT NULL AND CHARACTER_SET_NAME <> 'utf8mb4'
            ORDER BY TABLE_NAME, COLUMN_NAME
            LIMIT 40
            """
        )
        for r in cur.fetchall():
            print(f"  {r[0]}.{r[1]} -> {r[2]} / {r[3]}")
    conn.close()
    return 0


def cmd_counts() -> int:
    conn = _connect()
    conn.autocommit(True)
    queries = [
        "SELECT COUNT(*) FROM apps",
        "SELECT COUNT(*) FROM static_analysis_runs",
        "SELECT COUNT(*) FROM static_analysis_findings",
        "SELECT COUNT(*) FROM v_web_app_directory",
        "SELECT COUNT(*) FROM vw_static_finding_surfaces_latest",
        "SELECT COUNT(*) FROM v_web_app_findings",
        "SELECT COUNT(*) FROM v_web_permission_intel_current",
        "SELECT COUNT(*) FROM dynamic_sessions",
    ]
    with conn.cursor() as cur:
        for q in queries:
            try:
                cur.execute(q)
                val = cur.fetchone()[0]
                print(f"{val:8d}  {q}")
            except Exception as e:
                print(f"ERROR     {q}  -> {e}")
    conn.close()
    return 0


def _view_ddl_chain() -> list[tuple[str, str]]:
    from scytaledroid.Database.db_queries.views_inventory import CREATE_VW_LATEST_APK_PER_PACKAGE
    from scytaledroid.Database.db_queries.views_permission import (
        CREATE_VW_LATEST_PERMISSION_RISK,
        CREATE_VW_PERMISSION_AUDIT_LATEST,
        CREATE_V_WEB_PERMISSION_INTEL_CURRENT,
    )
    from scytaledroid.Database.db_queries.views_static import (
        CREATE_VW_STATIC_FINDING_SURFACES_LATEST,
        CREATE_VW_STATIC_RISK_SURFACES_LATEST,
    )
    from scytaledroid.Database.db_queries.views_web import (
        CREATE_V_WEB_APP_COMPONENT_ACL,
        CREATE_V_WEB_APP_COMPONENT_SUMMARY,
        CREATE_V_WEB_APP_COMPONENTS,
        CREATE_V_WEB_APP_DIRECTORY,
        CREATE_V_WEB_APP_FINDINGS,
        CREATE_V_WEB_APP_PERMISSION_SUMMARY,
        CREATE_V_WEB_APP_PERMISSIONS,
        CREATE_V_WEB_APP_REPORT_SUMMARY,
        CREATE_V_WEB_APP_SESSIONS,
        CREATE_V_WEB_APP_STRING_SAMPLES,
        CREATE_V_WEB_APP_STRING_SUMMARY,
        CREATE_V_WEB_RUNTIME_RUN_DETAIL,
        CREATE_V_WEB_RUNTIME_RUN_INDEX,
        CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY,
        CREATE_V_WEB_STATIC_SESSION_HEALTH,
    )

    return [
        ("vw_latest_apk_per_package", CREATE_VW_LATEST_APK_PER_PACKAGE),
        ("vw_latest_permission_risk", CREATE_VW_LATEST_PERMISSION_RISK),
        ("vw_permission_audit_latest", CREATE_VW_PERMISSION_AUDIT_LATEST),
        ("vw_static_risk_surfaces_latest", CREATE_VW_STATIC_RISK_SURFACES_LATEST),
        ("vw_static_finding_surfaces_latest", CREATE_VW_STATIC_FINDING_SURFACES_LATEST),
        ("v_web_static_session_health", CREATE_V_WEB_STATIC_SESSION_HEALTH),
        ("v_web_app_sessions", CREATE_V_WEB_APP_SESSIONS),
        ("v_web_app_permissions", CREATE_V_WEB_APP_PERMISSIONS),
        ("v_web_app_permission_summary", CREATE_V_WEB_APP_PERMISSION_SUMMARY),
        ("v_web_app_findings", CREATE_V_WEB_APP_FINDINGS),
        ("v_web_app_string_summary", CREATE_V_WEB_APP_STRING_SUMMARY),
        ("v_web_app_string_samples", CREATE_V_WEB_APP_STRING_SAMPLES),
        ("v_web_app_components", CREATE_V_WEB_APP_COMPONENTS),
        ("v_web_app_component_summary", CREATE_V_WEB_APP_COMPONENT_SUMMARY),
        ("v_web_app_component_acl", CREATE_V_WEB_APP_COMPONENT_ACL),
        ("v_web_permission_intel_current", CREATE_V_WEB_PERMISSION_INTEL_CURRENT),
        ("v_web_app_report_summary", CREATE_V_WEB_APP_REPORT_SUMMARY),
        ("v_web_app_directory", CREATE_V_WEB_APP_DIRECTORY),
        ("v_web_static_dynamic_app_summary", CREATE_V_WEB_STATIC_DYNAMIC_APP_SUMMARY),
        ("v_web_runtime_run_index", CREATE_V_WEB_RUNTIME_RUN_INDEX),
        ("v_web_runtime_run_detail", CREATE_V_WEB_RUNTIME_RUN_DETAIL),
    ]


def cmd_recreate(
    *,
    dry_run: bool,
    apply_safe_alters: bool,
    drop_conflicting_tables: bool,
    confirm: bool,
) -> int:
    if drop_conflicting_tables and not confirm:
        sys.stderr.write("--drop-conflicting-tables requires --confirm\n")
        return 2

    chain = _view_ddl_chain()
    if dry_run:
        print("DDL order (no execution):")
        for label, _ in chain:
            print(f"  {label}")
        return 0

    conn = _connect()
    conn.autocommit(True)
    with conn.cursor() as cur:
        if apply_safe_alters:
            alters = [
                (
                    "static_analysis_runs",
                    "findings_runtime_total",
                    "ALTER TABLE static_analysis_runs ADD COLUMN findings_runtime_total INT UNSIGNED NULL",
                ),
                (
                    "static_analysis_runs",
                    "findings_capped_total",
                    "ALTER TABLE static_analysis_runs ADD COLUMN findings_capped_total INT UNSIGNED NULL",
                ),
                (
                    "static_analysis_runs",
                    "findings_capped_by_detector_json",
                    "ALTER TABLE static_analysis_runs ADD COLUMN findings_capped_by_detector_json JSON DEFAULT NULL",
                ),
                (
                    "static_analysis_findings",
                    "severity_raw",
                    "ALTER TABLE static_analysis_findings ADD COLUMN severity_raw VARCHAR(64) DEFAULT NULL AFTER severity",
                ),
            ]
            for table, col, ddl in alters:
                if not _col_exists(cur, table, col):
                    print("APPLY", ddl)
                    cur.execute(ddl)
                else:
                    print("SKIP (exists)", table, col)

        if drop_conflicting_tables:
            cur.execute("SET FOREIGN_KEY_CHECKS = 0")
            for name in CONFLICT_TABLE_CANDIDATES:
                typ = _table_type(cur, name)
                if typ == "BASE TABLE":
                    print("DROP TABLE", name)
                    cur.execute(f"DROP TABLE IF EXISTS `{name}`")
                elif typ == "VIEW":
                    print("DROP VIEW", name)
                    cur.execute(f"DROP VIEW IF EXISTS `{name}`")
            cur.execute("SET FOREIGN_KEY_CHECKS = 1")

        failures: list[tuple[str, Exception]] = []
        for label, ddl in chain:
            try:
                cur.execute(ddl)
                print("OK", label)
            except Exception as e:
                failures.append((label, e))
                print("FAIL", label, e)
        conn.close()
        if failures:
            return 1
    cmd_counts()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Web consumer view maintenance.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("posture", help="Report naming conflicts, presence of views, charset sample.")

    sub.add_parser("counts", help="Lightweight row-count sanity probe.")

    r = sub.add_parser("recreate", help="Apply ALTERs optionally, drop stubs, recreate views.")
    r.add_argument("--dry-run", action="store_true", help="Print DDL labels only.")
    r.add_argument(
        "--apply-safe-alters",
        action="store_true",
        help="Add nullable columns expected by modern views if absent.",
    )
    r.add_argument(
        "--drop-conflicting-tables",
        action="store_true",
        help="Drop BASE TABLE / VIEW stubs that collide with consumer view names.",
    )
    r.add_argument(
        "--confirm",
        action="store_true",
        help="Acknowledge destructive operations (required with --drop-conflicting-tables).",
    )

    args = ap.parse_args()
    if args.cmd == "posture":
        return cmd_posture()
    if args.cmd == "counts":
        return cmd_counts()
    if args.cmd == "recreate":
        return cmd_recreate(
            dry_run=args.dry_run,
            apply_safe_alters=args.apply_safe_alters,
            drop_conflicting_tables=args.drop_conflicting_tables,
            confirm=args.confirm,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
