#!/usr/bin/env python3
"""Backfill static/dynamic ``apk_set_id`` links from receipt-backed install sets.

This is intentionally narrower than dynamic/static link repair.  It does not
write ``dynamic_sessions.static_run_id``.  It only fills nullable ``apk_set_id``
when an existing row's ``artifact_set_hash`` has exactly one matching row in
``apk_sets``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Write apk_set_id links.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument(
        "--package",
        help="Limit preview/apply to one Android package name.",
    )
    parser.add_argument(
        "--receipt-dir",
        help=(
            "Write summary.json to this directory. Defaults to "
            "output/audit/backfill_apk_set_links/<timestamp> for --apply."
        ),
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_queries.canonical import schema as canonical_schema
        from scytaledroid.Database.db_queries.dynamic import schema as dynamic_schema
        from scytaledroid.Database.db_queries.harvest import install_sets
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    payload = {
        "apply": bool(args.apply),
        "package": args.package,
        "preflight": _preflight(core_q, package=args.package),
        "static": _preview_static(core_q, package=args.package),
        "dynamic": _preview_dynamic(core_q, package=args.package),
    }

    if args.apply:
        _ensure_link_schema(core_q, canonical_schema, dynamic_schema, install_sets)
        payload["applied"] = {
            "static_rows_updated": _apply_static(core_q, package=args.package),
            "dynamic_rows_updated": _apply_dynamic(core_q, package=args.package),
        }
        payload["postflight"] = _preflight(core_q, package=args.package)

    receipt_dir = _receipt_dir(args.receipt_dir, apply=args.apply)
    if receipt_dir is not None:
        receipt_dir.mkdir(parents=True, exist_ok=True)
        payload["output_files"] = {
            "summary_json": str((receipt_dir / "summary.json").resolve()),
        }
        _write_json(receipt_dir / "summary.json", payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        _print_text(payload)
    return 0


def _default_receipt_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "backfill_apk_set_links" / stamp


def _receipt_dir(path: str | None, *, apply: bool) -> Path | None:
    if path:
        return Path(path)
    if apply:
        return _default_receipt_dir()
    return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _ensure_link_schema(core_q: Any, canonical_schema: Any, dynamic_schema: Any, install_sets: Any) -> None:
    # Re-run idempotent DDL from repo-owned schema so --apply works on dev DBs
    # that have not gone through a full bootstrap since the column was added.
    for stmt in canonical_schema._DDL_STATEMENTS:
        if "apk_set_id" in stmt or "static_analysis_runs" in stmt:
            core_q.run_sql(stmt, query_name="backfill_apk_set_links.ensure_static_schema")
    for stmt in dynamic_schema._DDL_STATEMENTS:
        if "apk_set_id" in stmt or "dynamic_sessions" in stmt:
            core_q.run_sql(stmt, query_name="backfill_apk_set_links.ensure_dynamic_schema")
    for stmt in install_sets._DDL_STATEMENTS:
        core_q.run_sql(stmt, query_name="backfill_apk_set_links.ensure_apk_set_schema")
    core_q.run_sql(
        install_sets.CREATE_V_APK_SET_COVERAGE_V1,
        query_name="backfill_apk_set_links.ensure_coverage_view",
    )


def _preflight(core_q: Any, *, package: str | None = None) -> dict[str, Any]:
    apk_set_filter, apk_set_params = _package_where("package_name", package)
    static_join, static_filter, static_params = _static_package_scope(package)
    dynamic_filter, dynamic_params = _package_where("package_name", package)
    return {
        "apk_sets": _scalar(core_q, f"SELECT COUNT(*) AS n FROM apk_sets WHERE 1=1 {apk_set_filter}", apk_set_params),
        "static_rows_with_artifact_set_hash": _scalar(
            core_q,
            f"""
            SELECT COUNT(*) AS n
            FROM static_analysis_runs sar
            {static_join}
            WHERE sar.artifact_set_hash IS NOT NULL
              {static_filter}
            """,
            static_params,
        ),
        "static_rows_with_apk_set_id": _scalar(
            core_q,
            f"""
            SELECT COUNT(*) AS n
            FROM static_analysis_runs sar
            {static_join}
            WHERE sar.apk_set_id IS NOT NULL
              {static_filter}
            """,
            static_params,
        )
        if _column_exists(core_q, "static_analysis_runs", "apk_set_id")
        else 0,
        "dynamic_rows_with_artifact_set_hash": _scalar(
            core_q,
            f"""
            SELECT COUNT(*) AS n
            FROM dynamic_sessions
            WHERE artifact_set_hash IS NOT NULL
              {dynamic_filter}
            """,
            dynamic_params,
        ),
        "dynamic_rows_with_apk_set_id": _scalar(
            core_q,
            f"""
            SELECT COUNT(*) AS n
            FROM dynamic_sessions
            WHERE apk_set_id IS NOT NULL
              {dynamic_filter}
            """,
            dynamic_params,
        )
        if _column_exists(core_q, "dynamic_sessions", "apk_set_id")
        else 0,
    }


def _preview_static(core_q: Any, *, package: str | None = None) -> dict[str, int]:
    pending_filter = "AND sar.apk_set_id IS NULL" if _column_exists(core_q, "static_analysis_runs", "apk_set_id") else ""
    static_join, package_filter, params = _static_package_scope(package)
    rows = core_q.run_sql(
        f"""
        SELECT
          COUNT(*) AS candidates,
          SUM(CASE WHEN matches.match_count = 1 THEN 1 ELSE 0 END) AS unique_matches,
          SUM(CASE WHEN matches.match_count > 1 THEN 1 ELSE 0 END) AS ambiguous_matches,
          SUM(CASE WHEN matches.match_count IS NULL THEN 1 ELSE 0 END) AS no_matches
        FROM static_analysis_runs sar
        LEFT JOIN (
          SELECT artifact_set_hash, COUNT(*) AS match_count
          FROM apk_sets
          GROUP BY artifact_set_hash
        ) matches ON matches.artifact_set_hash = sar.artifact_set_hash
        {static_join}
        WHERE sar.artifact_set_hash IS NOT NULL
          {pending_filter}
          {package_filter}
        """,
        params,
        fetch="one_dict",
        query_name="backfill_apk_set_links.preview_static",
    ) or {}
    return _int_dict(rows)


def _preview_dynamic(core_q: Any, *, package: str | None = None) -> dict[str, int]:
    pending_filter = "AND ds.apk_set_id IS NULL" if _column_exists(core_q, "dynamic_sessions", "apk_set_id") else ""
    package_filter, params = _package_where("ds.package_name", package)
    rows = core_q.run_sql(
        f"""
        SELECT
          COUNT(*) AS candidates,
          SUM(CASE WHEN matches.match_count = 1 THEN 1 ELSE 0 END) AS unique_matches,
          SUM(CASE WHEN matches.match_count > 1 THEN 1 ELSE 0 END) AS ambiguous_matches,
          SUM(CASE WHEN matches.match_count IS NULL THEN 1 ELSE 0 END) AS no_matches
        FROM dynamic_sessions ds
        LEFT JOIN (
          SELECT artifact_set_hash, COUNT(*) AS match_count
          FROM apk_sets
          GROUP BY artifact_set_hash
        ) matches ON matches.artifact_set_hash = ds.artifact_set_hash
        WHERE ds.artifact_set_hash IS NOT NULL
          {pending_filter}
          {package_filter}
        """,
        params,
        fetch="one_dict",
        query_name="backfill_apk_set_links.preview_dynamic",
    ) or {}
    return _int_dict(rows)


def _apply_static(core_q: Any, *, package: str | None = None) -> int:
    static_join, package_filter, params = _static_package_scope(package)
    before = _scalar(
        core_q,
        f"""
        SELECT COUNT(*) AS n
        FROM static_analysis_runs sar
        {static_join}
        WHERE sar.apk_set_id IS NOT NULL
          {package_filter}
        """,
        params,
    )
    core_q.run_sql(
        f"""
        UPDATE static_analysis_runs sar
        {static_join}
        JOIN (
          SELECT artifact_set_hash, MIN(apk_set_id) AS apk_set_id, COUNT(*) AS match_count
          FROM apk_sets
          GROUP BY artifact_set_hash
        ) matches ON matches.artifact_set_hash = sar.artifact_set_hash
        SET sar.apk_set_id = matches.apk_set_id
        WHERE sar.apk_set_id IS NULL
          AND sar.artifact_set_hash IS NOT NULL
          AND matches.match_count = 1
          {package_filter}
        """,
        params,
        query_name="backfill_apk_set_links.apply_static",
    )
    after = _scalar(
        core_q,
        f"""
        SELECT COUNT(*) AS n
        FROM static_analysis_runs sar
        {static_join}
        WHERE sar.apk_set_id IS NOT NULL
          {package_filter}
        """,
        params,
    )
    return max(after - before, 0)


def _apply_dynamic(core_q: Any, *, package: str | None = None) -> int:
    package_filter, params = _package_where("ds.package_name", package)
    count_filter, count_params = _package_where("package_name", package)
    before = _scalar(
        core_q,
        f"SELECT COUNT(*) AS n FROM dynamic_sessions WHERE apk_set_id IS NOT NULL {count_filter}",
        count_params,
    )
    core_q.run_sql(
        f"""
        UPDATE dynamic_sessions ds
        JOIN (
          SELECT artifact_set_hash, MIN(apk_set_id) AS apk_set_id, COUNT(*) AS match_count
          FROM apk_sets
          GROUP BY artifact_set_hash
        ) matches ON matches.artifact_set_hash = ds.artifact_set_hash
        SET ds.apk_set_id = matches.apk_set_id
        WHERE ds.apk_set_id IS NULL
          AND ds.artifact_set_hash IS NOT NULL
          AND matches.match_count = 1
          {package_filter}
        """,
        params,
        query_name="backfill_apk_set_links.apply_dynamic",
    )
    after = _scalar(
        core_q,
        f"SELECT COUNT(*) AS n FROM dynamic_sessions WHERE apk_set_id IS NOT NULL {count_filter}",
        count_params,
    )
    return max(after - before, 0)


def _scalar(core_q: Any, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = core_q.run_sql(sql, params, fetch="one_dict", query_name="backfill_apk_set_links.scalar") or {}
    return int(row.get("n") or 0)


def _package_where(column_expr: str, package: str | None) -> tuple[str, tuple[Any, ...]]:
    if not package:
        return "", ()
    return f"AND {column_expr} = %s", (package,)


def _static_package_scope(package: str | None) -> tuple[str, str, tuple[Any, ...]]:
    if not package:
        return "", "", ()
    return (
        "JOIN app_versions av_scope ON av_scope.id = sar.app_version_id "
        "JOIN apps app_scope ON app_scope.id = av_scope.app_id",
        "AND app_scope.package_name = %s",
        (package,),
    )


def _column_exists(core_q: Any, table_name: str, column_name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (table_name, column_name),
        fetch="one_dict",
        query_name="backfill_apk_set_links.column_exists",
    ) or {}
    return int(row.get("n") or 0) > 0


def _int_dict(row: dict[str, Any]) -> dict[str, int]:
    return {str(key): int(value or 0) for key, value in row.items()}


def _print_text(payload: dict[str, Any]) -> None:
    mode = "APPLY" if payload["apply"] else "DRY-RUN"
    print(f"=== APK set link backfill ({mode}) ===")
    if payload.get("package"):
        print(f"Package: {payload['package']}")
    print("Preflight:")
    for key, value in payload["preflight"].items():
        print(f"  {key}: {value}")
    print("Static:")
    for key, value in payload["static"].items():
        print(f"  {key}: {value}")
    print("Dynamic:")
    for key, value in payload["dynamic"].items():
        print(f"  {key}: {value}")
    if "applied" in payload:
        print("Applied:")
        for key, value in payload["applied"].items():
            print(f"  {key}: {value}")
        output_files = payload.get("output_files") or {}
        if output_files.get("summary_json"):
            print(f"Receipt: {output_files['summary_json']}")
    else:
        print("  note: no DB writes were made. Re-run with --apply to fill nullable apk_set_id links.")
        output_files = payload.get("output_files") or {}
        if output_files.get("summary_json"):
            print(f"Receipt: {output_files['summary_json']}")


if __name__ == "__main__":
    raise SystemExit(main())
