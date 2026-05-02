#!/usr/bin/env python3
"""Operational SQL VIEW maintenance (Web + manifest + canonical reporting surfaces).

Connection (see ``scripts/db/README.md``):
  SCYTALEDROID_DB_HOST, SCYTALEDROID_DB_PORT, SCYTALEDROID_DB_USER,
  SCYTALEDROID_DB_PASSWD (canonical; SCYTALEDROID_DB_PASS legacy), SCYTALEDROID_DB_NAME

Commands:
  posture    — all v_/vw_ BASE TABLE violations, expected VIEW types, columns, utf8 sample
  semantic   — row-count coherence (source table vs consumer view)
  counts     — quick scalar counts
  recreate   — optional safe ALTERs, guarded drop of materialized stubs, CREATE OR REPLACE VIEW

Layers (recreate):
  full       — bootstrap manifest views + supplementary + web extensions (default)
  manifest   — views derivable from ``ordered_schema_statements()`` only
  web        — web-consumer extension chain only (legacy)

Destructive operations require ``--confirm``. Non-empty ``v_*``/``vw_*`` BASE TABLE
drops require ``--allow-drop-nonempty-tables`` in addition to ``--confirm``.

See ``docs/maintenance/database_governance_runbook.md``.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.db.view_repair_support import (
    EXPECTED_VIEW_OBJECTS,
    REQUIRED_COLUMNS,
    full_operational_view_repair_sequence,
    manifest_only_sequence,
    web_consumer_only_sequence,
)


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
    password = (
        os.environ.get("SCYTALEDROID_DB_PASSWD")
        or os.environ.get("SCYTALEDROID_DB_PASS")
        or os.environ.get("MYSQL_PASSWORD", "")
    )
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


def _safe_count(cur, sql: str) -> int | None:
    try:
        cur.execute(sql)
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        return None


def _violating_view_named_base_tables(cur) -> list[tuple[str, int]]:
    cur.execute(
        """
        SELECT TABLE_NAME, COALESCE(TABLE_ROWS, 0)
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_TYPE = 'BASE TABLE'
          AND (
            TABLE_NAME REGEXP '^v_.*'
            OR TABLE_NAME REGEXP '^vw_.*'
          )
        ORDER BY TABLE_NAME
        """
    )
    return [(str(r[0]), int(r[1])) for r in cur.fetchall()]


def cmd_posture() -> int:
    conn = _connect()
    conn.autocommit(True)
    with conn.cursor() as cur:
        print("# BASE TABLE rows whose names are reserved view prefixes (^v_* or ^vw_*)")
        bad = _violating_view_named_base_tables(cur)
        if not bad:
            print("  (none)")
        else:
            for nm, rows in bad:
                print(f"  VIOLATION  {nm:55} approx_rows={rows}")

        print("# Expected analytic VIEW objects (must exist as TABLE_TYPE=VIEW)")
        for name in EXPECTED_VIEW_OBJECTS:
            typ = _table_type(cur, name)
            if typ is None:
                print(f"  MISSING     {name}")
            elif typ != "VIEW":
                print(f"  WRONG_TYPE  {name} -> {typ}")
            else:
                print(f"  OK          {name}")

        print("# Missing columns for modern consumer DDL (information_schema)")
        for table, col, _spec in REQUIRED_COLUMNS:
            if not _col_exists(cur, table, col):
                print(f"  MISSING_COL {table}.{col}")
            else:
                print(f"  OK_COL      {table}.{col}")

        print("# UTF-8 posture sample (non-utf8mb4 text on hotspot tables)")
        cur.execute(
            """
            SELECT TABLE_NAME, COLUMN_NAME, CHARACTER_SET_NAME, COLLATION_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME IN (
                'apps', 'static_fileproviders', 'static_provider_acl',
                'static_analysis_findings', 'risk_scores'
              )
              AND DATA_TYPE IN ('varchar','char','text','tinytext','mediumtext','longtext')
              AND CHARACTER_SET_NAME IS NOT NULL AND CHARACTER_SET_NAME <> 'utf8mb4'
            ORDER BY TABLE_NAME, COLUMN_NAME
            LIMIT 50
            """
        )
        rows = cur.fetchall()
        if not rows:
            print("  (none in sample set)")
        for r in rows:
            print(f"  {r[0]}.{r[1]} -> {r[2]} / {r[3]}")
    conn.close()
    return 0


def cmd_semantic() -> int:
    """Fail (exit 1) if source tables have data but dependent views are empty."""

    conn = _connect()
    conn.autocommit(True)

    baseline: list[tuple[str, str]] = [
        ("apps", "SELECT COUNT(*) FROM apps"),
        ("v_web_app_directory", "SELECT COUNT(*) FROM v_web_app_directory"),
        ("static_analysis_runs", "SELECT COUNT(*) FROM static_analysis_runs"),
        ("v_web_app_sessions", "SELECT COUNT(*) FROM v_web_app_sessions"),
        ("static_analysis_findings", "SELECT COUNT(*) FROM static_analysis_findings"),
        ("v_web_app_findings", "SELECT COUNT(*) FROM v_web_app_findings"),
        ("static_permission_matrix", "SELECT COUNT(*) FROM static_permission_matrix"),
        ("v_web_permission_intel_current", "SELECT COUNT(*) FROM v_web_permission_intel_current"),
        ("dynamic_sessions", "SELECT COUNT(*) FROM dynamic_sessions"),
        ("v_web_runtime_run_index", "SELECT COUNT(*) FROM v_web_runtime_run_index"),
    ]

    checks: list[tuple[str, str, str, str]] = [
        ("apps", "SELECT COUNT(*) FROM apps", "v_web_app_directory", "SELECT COUNT(*) FROM v_web_app_directory"),
        (
            "static_analysis_runs",
            "SELECT COUNT(*) FROM static_analysis_runs",
            "v_web_app_sessions",
            "SELECT COUNT(*) FROM v_web_app_sessions",
        ),
        (
            "static_analysis_findings",
            "SELECT COUNT(*) FROM static_analysis_findings",
            "v_web_app_findings",
            "SELECT COUNT(*) FROM v_web_app_findings",
        ),
        (
            "static_permission_matrix",
            "SELECT COUNT(*) FROM static_permission_matrix",
            "v_web_permission_intel_current",
            "SELECT COUNT(*) FROM v_web_permission_intel_current",
        ),
        (
            "dynamic_sessions",
            "SELECT COUNT(*) FROM dynamic_sessions",
            "v_web_runtime_run_index",
            "SELECT COUNT(*) FROM v_web_runtime_run_index",
        ),
    ]
    failed = False
    with conn.cursor() as cur:
        print("# Baseline counts (informative)")
        for label, sql in baseline:
            c = _safe_count(cur, sql)
            print(f"  {label}: {c}")
        print("# Source-vs-consumer coherence (FAIL when source non-empty but view empty)")
        for label, src_sql, dep_name, dep_sql in checks:
            src = _safe_count(cur, src_sql)
            dep = _safe_count(cur, dep_sql)
            if src is None:
                print(f"SKIP  {label}: source query failed")
                continue
            if dep is None:
                print(f"WARN  {label}: dependent {dep_name} query failed (object missing or error?)")
                failed = True
                continue
            if src > 0 and dep == 0:
                print(f"FAIL  {label}: {src} source rows but {dep_name} is empty")
                failed = True
            else:
                print(f"OK    {label}: src={src} {dep_name}={dep}")
    conn.close()
    return 1 if failed else 0


def cmd_counts() -> int:
    conn = _connect()
    conn.autocommit(True)
    queries = [
        "SELECT COUNT(*) FROM apps",
        "SELECT COUNT(*) FROM static_analysis_runs",
        "SELECT COUNT(*) FROM static_analysis_findings",
        "SELECT COUNT(*) FROM static_permission_matrix",
        "SELECT COUNT(*) FROM v_web_app_directory",
        "SELECT COUNT(*) FROM vw_static_finding_surfaces_latest",
        "SELECT COUNT(*) FROM v_web_app_findings",
        "SELECT COUNT(*) FROM v_web_permission_intel_current",
        "SELECT COUNT(*) FROM dynamic_sessions",
        "SELECT COUNT(*) FROM v_web_runtime_run_index",
        "SELECT COUNT(*) FROM v_run_overview",
        "SELECT COUNT(*) FROM v_static_handoff_v1",
        "SELECT COUNT(*) FROM v_static_masvs_findings_v1",
        "SELECT COUNT(*) FROM v_static_masvs_matrix_v1",
        "SELECT COUNT(*) FROM v_static_masvs_session_summary_v1",
        "SELECT COUNT(*) FROM v_static_risk_surfaces_v1",
        "SELECT COUNT(*) FROM v_masvs_matrix",
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


def _resolve_chain(layer: str) -> list[tuple[str, str]]:
    if layer == "full":
        return full_operational_view_repair_sequence()
    if layer == "manifest":
        return manifest_only_sequence()
    if layer == "web":
        return web_consumer_only_sequence()
    raise ValueError(layer)


def cmd_recreate(
    *,
    layer: str,
    dry_run: bool,
    apply_safe_alters: bool,
    drop_conflicting_tables: bool,
    allow_drop_nonempty: bool,
    confirm: bool,
) -> int:
    if drop_conflicting_tables and not confirm:
        sys.stderr.write("--drop-conflicting-tables requires --confirm\n")
        return 2
    if allow_drop_nonempty and not confirm:
        sys.stderr.write("--allow-drop-nonempty-tables requires --confirm\n")
        return 2

    chain = _resolve_chain(layer)
    if dry_run:
        print(f"DDL order ({layer}, {len(chain)} views):")
        for label, _ in chain:
            print(f"  {label}")
        return 0

    conn = _connect()
    conn.autocommit(True)
    failures: list[tuple[str, Exception]] = []
    try:
        with conn.cursor() as cur:
            if apply_safe_alters:
                alters: list[tuple[str, str, str]] = [
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
                viol = _violating_view_named_base_tables(cur)
                cur.execute("SET FOREIGN_KEY_CHECKS = 0")
                for name, approx_rows in viol:
                    if approx_rows > 0 and not allow_drop_nonempty:
                        print(
                            f"REFUSE_DROP {name}: BASE TABLE has approx_rows={approx_rows}; "
                            "use --allow-drop-nonempty-tables --confirm after backup review"
                        )
                        continue
                    if approx_rows > 0:
                        print(f"DROP_NONEMPTY_TABLE {name} approx_rows={approx_rows}")
                    print("DROP TABLE", name)
                    cur.execute(f"DROP TABLE IF EXISTS `{name}`")
                cur.execute("SET FOREIGN_KEY_CHECKS = 1")

            for label, ddl in chain:
                try:
                    cur.execute(ddl)
                    print("OK", label)
                except Exception as e:
                    failures.append((label, e))
                    print("FAIL", label, e)
    finally:
        conn.close()

    if failures:
        return 1
    return cmd_counts()


def main() -> int:
    ap = argparse.ArgumentParser(description="Operational VIEW maintenance (full stack + web).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("posture", help="Violations, expected VIEW types, missing columns, charset sample.")
    sub.add_parser("semantic", help="Source-vs-view row coherence (empty dashboard detector).")
    sub.add_parser("counts", help="Scalar counts for key tables/views.")

    r = sub.add_parser("recreate", help="Optional ALTERs, guarded stub drop, CREATE OR REPLACE VIEW chain.")
    r.add_argument(
        "--layer",
        choices=("full", "manifest", "web"),
        default="full",
        help=(
            "View set: full (manifest VIEWs + reporting extras + web chain gap-fill), "
            "manifest-only (ordered_schema_statements VIEW DDL only), "
            "or web-consumer-only (full web repair chain). Canonical MASVS v1 VIEWs are "
            "defined in the manifest; use recreate --dry-run --layer manifest to list DDL order."
        ),
    )
    r.add_argument("--dry-run", action="store_true", help="Print DDL labels only.")
    r.add_argument(
        "--apply-safe-alters",
        action="store_true",
        help="Add nullable columns expected by modern views if absent.",
    )
    r.add_argument(
        "--drop-conflicting-tables",
        action="store_true",
        help="Drop BASE TABLE objects under v_/vw_ names (discovered dynamically).",
    )
    r.add_argument(
        "--allow-drop-nonempty-tables",
        dest="allow_drop_nonempty",
        action="store_true",
        help="Allow dropping v_/vw_ BASE TABLE rows with TABLE_ROWS>0 (requires --confirm).",
    )
    r.add_argument(
        "--confirm",
        action="store_true",
        help="Acknowledge destructive operations.",
    )

    args = ap.parse_args()
    if args.cmd == "posture":
        return cmd_posture()
    if args.cmd == "semantic":
        return cmd_semantic()
    if args.cmd == "counts":
        return cmd_counts()
    if args.cmd == "recreate":
        return cmd_recreate(
            layer=args.layer,
            dry_run=args.dry_run,
            apply_safe_alters=args.apply_safe_alters,
            drop_conflicting_tables=args.drop_conflicting_tables,
            allow_drop_nonempty=args.allow_drop_nonempty,
            confirm=args.confirm,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
