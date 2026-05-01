"""Copy Phase 1 permission-intel tables into a dedicated MariaDB schema.

This is the first implementation step for the shared permission-intelligence
split. It assumes the source operational DB and target permission-intel DB live
on the same MariaDB server, which matches the current project plan.
"""

from __future__ import annotations

import argparse
from typing import Any

from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_core.db_engine import DatabaseEngine, DatabaseError

from .permission_intel_phase1_common import (
    DEFAULT_TARGET_DB,
    PHASE1_TABLES,
    write_phase1_artifact,
)


def _qident(name: str) -> str:
    return f"`{str(name).replace('`', '``')}`"


def _source_db_name() -> str:
    name = str(DB_CONFIG.get("database") or "").strip()
    if not name:
        raise RuntimeError("Operational DB name is not configured.")
    return name


def _show_create_table(db: DatabaseEngine, table: str) -> str:
    row = db.fetch_one(f"SHOW CREATE TABLE {_qident(table)}")
    if not row or len(row) < 2:
        raise RuntimeError(f"Unable to read CREATE TABLE for {table}")
    return str(row[1])


def _render_target_create(create_sql: str, target_db: str, table: str) -> str:
    token = f"CREATE TABLE `{table}`"
    replacement = f"CREATE TABLE `{target_db}`.`{table}`"
    if token not in create_sql:
        raise RuntimeError(f"Unexpected CREATE TABLE header for {table}")
    return create_sql.replace(token, replacement, 1)


def copy_phase1_tables(*, target_db: str, truncate: bool = True) -> list[dict[str, Any]]:
    source_db = _source_db_name()
    if source_db == target_db:
        raise RuntimeError("Target DB must differ from the operational source DB.")

    db = DatabaseEngine()
    results: list[dict[str, Any]] = []
    try:
        db.execute(
            f"CREATE DATABASE IF NOT EXISTS {_qident(target_db)} "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
            query_name="permission_intel.phase1.create_database",
        )
        if truncate:
            db.execute("SET FOREIGN_KEY_CHECKS=0", query_name="permission_intel.phase1.disable_fk_checks")
            for table in reversed(PHASE1_TABLES):
                db.execute(
                    f"DROP TABLE IF EXISTS {_qident(target_db)}.{_qident(table)}",
                    query_name="permission_intel.phase1.drop_existing_table",
                )
            db.execute("SET FOREIGN_KEY_CHECKS=1", query_name="permission_intel.phase1.enable_fk_checks")

        for table in PHASE1_TABLES:
            create_sql = _render_target_create(_show_create_table(db, table), target_db, table)
            db.execute(create_sql, query_name="permission_intel.phase1.create_table")
            db.execute(
                f"INSERT INTO {_qident(target_db)}.{_qident(table)} "
                f"SELECT * FROM {_qident(source_db)}.{_qident(table)}",
                query_name="permission_intel.phase1.copy_rows",
            )
            source_count = int(
                db.fetch_one(
                    f"SELECT COUNT(*) FROM {_qident(source_db)}.{_qident(table)}",
                    query_name="permission_intel.phase1.source_count",
                )[0]
            )
            target_count = int(
                db.fetch_one(
                    f"SELECT COUNT(*) FROM {_qident(target_db)}.{_qident(table)}",
                    query_name="permission_intel.phase1.target_count",
                )[0]
            )
            results.append(
                {
                    "table": table,
                    "source_count": source_count,
                    "target_count": target_count,
                    "match": source_count == target_count,
                }
            )
        return results
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-db", default=DEFAULT_TARGET_DB, help="Target permission-intel DB name.")
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append into existing rows instead of truncating target tables first.",
    )
    parser.add_argument(
        "--json-out",
        help="Optional path to write a machine-readable copy artifact.",
    )
    args = parser.parse_args()

    source_db = _source_db_name()
    try:
        results = copy_phase1_tables(target_db=args.target_db, truncate=not args.append)
    except DatabaseError as exc:
        print(f"Phase 1 copy failed: {exc}")
        print(
            "Likely cause: the current DB user lacks CREATE/SELECT/INSERT privileges "
            f"for `{args.target_db}`. Grant access or provision the DB via DBA tooling, then retry."
        )
        return 2
    failed = False
    print(f"Copied Phase 1 permission-intel tables into {args.target_db}")
    for row in results:
        ok = "OK" if row["match"] else "MISMATCH"
        print(
            f"- {row['table']}: source={row['source_count']} "
            f"target={row['target_count']} [{ok}]"
        )
        failed = failed or not bool(row["match"])
    if args.json_out:
        artifact_path = write_phase1_artifact(
            args.json_out,
            command="permission_intel_phase1_copy",
            source_db=source_db,
            target_db=args.target_db,
            status="failed" if failed else "completed",
            failed=failed,
            results=results,
        )
        print(f"Artifact written: {artifact_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
