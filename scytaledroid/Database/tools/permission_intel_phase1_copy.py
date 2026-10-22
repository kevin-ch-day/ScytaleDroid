"""Copy Phase 1 permission-intel tables into a dedicated MariaDB schema.

This is the first implementation step for the shared permission-intelligence
split. It assumes the source operational DB and target permission-intel DB live
on the same MariaDB server, which matches the current project plan.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_core.db_engine import DatabaseEngine
from scytaledroid.Database.db_core.sql_ident import quote_sql_ident

from .permission_intel_phase1_common import PHASE1_TABLES

_FORBIDDEN_TARGET_DBS = frozenset({"mysql", "information_schema", "performance_schema", "sys"})


def _qident(name: str) -> str:
    quoted = quote_sql_ident(name)
    if quoted is None:
        raise ValueError(f"refusing unsafe SQL identifier: {name!r}")
    return quoted


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


def _protected_target(target_db: str) -> bool:
    name = target_db.casefold()
    return name == "android_permission_intel" or name.endswith("_prod")


def _validate_target(
    source_db: str, target_db: str, allow_protected_target: bool, confirmation: str | None
) -> None:
    try:
        _qident(target_db)
        _qident(source_db)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    if source_db.casefold() == target_db.casefold():
        raise RuntimeError("Target DB must differ from the operational source DB.")
    if target_db.casefold() in _FORBIDDEN_TARGET_DBS:
        raise RuntimeError("Copy into a system schema is forbidden.")
    if _protected_target(target_db) and (not allow_protected_target or confirmation != target_db):
        raise RuntimeError(
            "Protected target requires explicit opt-in and exact typed confirmation."
        )


def _now() -> str:
    return datetime.now(UTC).isoformat()


def copy_phase1_tables(
    *,
    target_db: str,
    truncate: bool = False,
    apply: bool = False,
    allow_protected_target: bool = False,
    confirmation: str | None = None,
    receipt_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Plan by default; every applied attempt first reserves a durable receipt.

    Non-replacing mode requires new destination tables. It never drops existing
    tables. DDL is not transactional: a failure can leave a partial copy, recorded
    in the receipt. Counts are observations, not a consistent source snapshot.
    """
    source_db = _source_db_name()
    _validate_target(source_db, target_db, allow_protected_target, confirmation)
    results: list[dict[str, Any]] = [
        {"table": table, "source_count": None, "target_count": None, "match": None}
        for table in PHASE1_TABLES
    ]
    if not apply:
        print(
            json.dumps(
                {
                    "mode": "dry_run",
                    "source_db": source_db,
                    "target_db": target_db,
                    "replace_tables": truncate,
                    "tables": list(PHASE1_TABLES),
                    "row_counts": "UNAVAILABLE (no connection in dry run)",
                },
                indent=2,
            )
        )
        return results

    path = (
        Path(receipt_path)
        if receipt_path is not None
        else (Path("output/audit/permission_intel_copy") / f"{uuid4().hex}.json")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "v2",
        "command": "permission_intel_phase1_copy",
        "source_db": source_db,
        "target_db": target_db,
        "operator": getpass.getuser(),
        "started_at_utc": _now(),
        "finished_at_utc": None,
        "status": "started",
        "replace_tables": truncate,
        "phase1_tables": list(PHASE1_TABLES),
        "results": results,
    }
    # Exclusive creation prevents clobbering an earlier receipt. Persist before DDL.
    with path.open("x", encoding="utf-8") as receipt:

        def save() -> None:
            receipt.seek(0)
            json.dump(payload, receipt, indent=2, sort_keys=True)
            receipt.write("\n")
            receipt.truncate()
            receipt.flush()
            os.fsync(receipt.fileno())

        save()
        print(f"Receipt: {path}")
        db = None
        try:
            db = DatabaseEngine()
            # Validate source definitions and record counts before any target writes.
            definitions = {}
            for row in results:
                table = row["table"]
                definitions[table] = _render_target_create(
                    _show_create_table(db, table), target_db, table
                )
                row["source_count"] = int(
                    db.fetch_one(
                        f"SELECT COUNT(*) FROM {_qident(source_db)}.{_qident(table)}",
                        query_name="permission_intel.phase1.source_count",
                    )[0]
                )
            save()
            db.execute(
                f"CREATE DATABASE IF NOT EXISTS {_qident(target_db)} "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
                query_name="permission_intel.phase1.create_database",
            )
            if truncate:
                db.execute(
                    "SET FOREIGN_KEY_CHECKS=0",
                    query_name="permission_intel.phase1.disable_fk_checks",
                )
                try:
                    for table in reversed(PHASE1_TABLES):
                        db.execute(
                            f"DROP TABLE IF EXISTS {_qident(target_db)}.{_qident(table)}",
                            query_name="permission_intel.phase1.drop_existing_table",
                        )
                finally:
                    db.execute(
                        "SET FOREIGN_KEY_CHECKS=1",
                        query_name="permission_intel.phase1.enable_fk_checks",
                    )
            for row in results:
                table = row["table"]
                db.execute(definitions[table], query_name="permission_intel.phase1.create_table")
                db.execute(
                    f"INSERT INTO {_qident(target_db)}.{_qident(table)} "
                    f"SELECT * FROM {_qident(source_db)}.{_qident(table)}",
                    query_name="permission_intel.phase1.copy_rows",
                )
                row["target_count"] = int(
                    db.fetch_one(
                        f"SELECT COUNT(*) FROM {_qident(target_db)}.{_qident(table)}",
                        query_name="permission_intel.phase1.target_count",
                    )[0]
                )
                row["match"] = row["source_count"] == row["target_count"]
                save()
            payload["status"] = "completed" if all(r["match"] for r in results) else "mismatch"
            return results
        except BaseException as exc:
            payload["status"] = "failed"
            # Exception text can contain connection credentials; record only its type.
            payload["error_type"] = type(exc).__name__
            raise
        finally:
            payload["finished_at_utc"] = _now()
            try:
                save()
            finally:
                if db is not None:
                    db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-db", required=True, help="Explicit destination schema; no default."
    )
    parser.add_argument(
        "--apply", action="store_true", help="Execute the copy; default prints a dry-run plan."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--truncate", action="store_true", help="Explicitly drop and recreate destination tables."
    )
    mode.add_argument(
        "--append",
        dest="truncate",
        action="store_false",
        help="Legacy non-replacing mode; existing tables cause an error.",
    )
    parser.set_defaults(truncate=False)
    parser.add_argument(
        "--allow-protected-target",
        action="store_true",
        help="Permit a protected destination only after exact typed confirmation.",
    )
    parser.add_argument(
        "--json-out",
        help="New receipt path; applied runs always write a receipt, generated under output/audit/permission_intel_copy by default.",
    )
    args = parser.parse_args()
    confirmation = None
    try:
        if _protected_target(args.target_db) and args.allow_protected_target:
            confirmation = input(f"Type the exact destination schema ({args.target_db}): ")
        results = copy_phase1_tables(
            target_db=args.target_db,
            truncate=args.truncate,
            apply=args.apply,
            allow_protected_target=args.allow_protected_target,
            confirmation=confirmation,
            receipt_path=args.json_out,
        )
    except (RuntimeError, OSError, EOFError) as exc:
        print(f"Copy refused or failed ({type(exc).__name__}); no automatic retry.")
        return 2
    if not args.apply:
        return 0
    for row in results:
        print(
            f"- {row['table']}: source={row['source_count']} target={row['target_count']} match={row['match']}"
        )
    return 0 if all(row["match"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
