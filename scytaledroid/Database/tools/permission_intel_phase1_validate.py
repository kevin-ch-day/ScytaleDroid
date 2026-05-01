"""Validate Phase 1 permission-intel copy results.

This compares source and target row counts and basic table checksums on the
same MariaDB server. It is intentionally lightweight and meant for the first
copy-first migration milestone.
"""

from __future__ import annotations

import argparse
from typing import Any

from scytaledroid.Database.db_core import permission_intel
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


def _count(db: DatabaseEngine, db_name: str, table: str) -> int:
    row = db.fetch_one(
        f"SELECT COUNT(*) FROM {_qident(db_name)}.{_qident(table)}",
        query_name="permission_intel.phase1.validate.count",
    )
    return int(row[0] or 0) if row else 0


def _checksum(db: DatabaseEngine, db_name: str, table: str) -> int | None:
    row = db.fetch_one(
        f"CHECKSUM TABLE {_qident(db_name)}.{_qident(table)}",
        query_name="permission_intel.phase1.validate.checksum",
    )
    if not row or len(row) < 2:
        return None
    try:
        return int(row[1])
    except Exception:
        return None


def _latest_governance(db: DatabaseEngine, db_name: str) -> tuple[str | None, str | None, int]:
    row = db.fetch_one(
        f"""
        SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
        FROM {_qident(db_name)}.{_qident(permission_intel.GOVERNANCE_SNAPSHOTS_TABLE)} s
        LEFT JOIN {_qident(db_name)}.{_qident(permission_intel.GOVERNANCE_ROWS_TABLE)} r
          ON r.governance_version = s.governance_version
        GROUP BY s.governance_version, s.snapshot_sha256
        ORDER BY s.loaded_at_utc DESC
        LIMIT 1
        """,
        query_name="permission_intel.phase1.validate.latest_governance",
    )
    if not row:
        return None, None, 0
    return (
        str(row[0]) if row[0] is not None else None,
        str(row[1]) if row[1] is not None else None,
        int(row[2] or 0),
    )


def validate_phase1_copy(*, target_db: str) -> tuple[list[dict[str, Any]], bool]:
    source_db = _source_db_name()
    db = DatabaseEngine().as_reader()
    try:
        results: list[dict[str, Any]] = []
        failed = False
        for table in PHASE1_TABLES:
            source_count = _count(db, source_db, table)
            target_count = _count(db, target_db, table)
            source_checksum = _checksum(db, source_db, table)
            target_checksum = _checksum(db, target_db, table)
            counts_match = source_count == target_count
            checksum_match = source_checksum == target_checksum
            results.append(
                {
                    "table": table,
                    "source_count": source_count,
                    "target_count": target_count,
                    "source_checksum": source_checksum,
                    "target_checksum": target_checksum,
                    "counts_match": counts_match,
                    "checksum_match": checksum_match,
                }
            )
            failed = failed or not counts_match or not checksum_match

        source_gov = _latest_governance(db, source_db)
        target_gov = _latest_governance(db, target_db)
        results.append(
            {
                "table": "permission_governance_latest",
                "source_version": source_gov[0],
                "target_version": target_gov[0],
                "source_sha256": source_gov[1],
                "target_sha256": target_gov[1],
                "source_row_count": source_gov[2],
                "target_row_count": target_gov[2],
                "counts_match": source_gov[2] == target_gov[2],
                "checksum_match": source_gov[:2] == target_gov[:2],
            }
        )
        failed = failed or source_gov != target_gov
        return results, failed
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-db", default=DEFAULT_TARGET_DB, help="Target permission-intel DB name.")
    parser.add_argument(
        "--json-out",
        help="Optional path to write a machine-readable validation artifact.",
    )
    args = parser.parse_args()

    source_db = _source_db_name()
    try:
        results, failed = validate_phase1_copy(target_db=args.target_db)
    except DatabaseError as exc:
        print(f"Phase 1 validation failed: {exc}")
        print(
            "Likely cause: the current DB user lacks SELECT privileges on the "
            f"target `{args.target_db}` schema, or the target DB has not been provisioned yet."
        )
        return 2
    print(f"Validated Phase 1 permission-intel copy in {args.target_db}")
    for row in results:
        if row["table"] == "permission_governance_latest":
            ok = "OK" if row["counts_match"] and row["checksum_match"] else "MISMATCH"
            print(
                f"- {row['table']}: "
                f"source=({row['source_version']}, {row['source_sha256']}, rows={row['source_row_count']}) "
                f"target=({row['target_version']}, {row['target_sha256']}, rows={row['target_row_count']}) "
                f"[{ok}]"
            )
            continue
        ok = "OK" if row["counts_match"] and row["checksum_match"] else "MISMATCH"
        print(
            f"- {row['table']}: source={row['source_count']} target={row['target_count']} "
            f"source_checksum={row['source_checksum']} target_checksum={row['target_checksum']} [{ok}]"
        )
    if args.json_out:
        artifact_path = write_phase1_artifact(
            args.json_out,
            command="permission_intel_phase1_validate",
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
