#!/usr/bin/env python3
"""Safely normalize finding evidence hash columns to ``ascii_bin``.

Dry-run by default. With ``--apply``, this helper only alters the narrow
evidence hash pair used by ``static_analysis_findings`` and
``static_finding_evidence_payloads``.

Run from repo root::

  PYTHONPATH=. python scripts/db/normalize_evidence_hash_collation.py
  PYTHONPATH=. python scripts/db/normalize_evidence_hash_collation.py --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_TARGETS: tuple[dict[str, str], ...] = (
    {
        "table": "static_finding_evidence_payloads",
        "column": "evidence_hash",
        "nullable": "NO",
        "alter_sql": (
            "ALTER TABLE static_finding_evidence_payloads "
            "MODIFY evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL"
        ),
    },
    {
        "table": "static_analysis_findings",
        "column": "evidence_hash",
        "nullable": "YES",
        "alter_sql": (
            "ALTER TABLE static_analysis_findings "
            "MODIFY evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL"
        ),
    },
)


def _column_rows(core_q) -> dict[tuple[str, str], dict[str, object]]:
    rows = core_q.run_sql(
        """
        SELECT table_name, column_name, column_type, is_nullable,
               character_set_name, collation_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            (table_name = 'static_analysis_findings' AND column_name = 'evidence_hash')
            OR (table_name = 'static_finding_evidence_payloads' AND column_name = 'evidence_hash')
          )
        ORDER BY table_name, column_name
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="normalize_evidence_hash_collation.columns",
    )
    return {
        (str(row.get("table_name") or ""), str(row.get("column_name") or "")): row
        for row in rows or []
    }


def _target_ok(row: dict[str, object], *, nullable: str) -> bool:
    return (
        str(row.get("column_type") or "").lower() == "char(64)"
        and str(row.get("character_set_name") or "").lower() == "ascii"
        and str(row.get("collation_name") or "").lower() == "ascii_bin"
        and str(row.get("is_nullable") or "").upper() == nullable
    )


def _invalid_hash_count(core_q, table: str) -> int:
    row = core_q.run_sql(
        f"""
        SELECT COUNT(*) AS c
        FROM {table}
        WHERE evidence_hash IS NOT NULL
          AND evidence_hash NOT REGEXP '^[0-9A-Fa-f]{{64}}$'
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name=f"normalize_evidence_hash_collation.invalid_hash.{table}",
    )
    return int(row.get("c") or 0) if row else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Run the ALTER TABLE statements. Default is read-only dry-run.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        by_column = _column_rows(core_q)
        bad = False
        planned: list[str] = []
        for target in _TARGETS:
            table = target["table"]
            column = target["column"]
            row = by_column.get((table, column))
            if not row:
                sys.stderr.write(f"{table}.{column} is missing; apply canonical schema first.\n")
                return 2
            print(
                f"{table}.{column}: {row.get('column_type')} "
                f"{row.get('character_set_name')}/{row.get('collation_name')} "
                f"nullable={row.get('is_nullable')}"
            )
            invalid = _invalid_hash_count(core_q, table)
            print(f"{table}.invalid_evidence_hash_rows={invalid}")
            if invalid:
                bad = True
            if not _target_ok(row, nullable=target["nullable"]):
                planned.append(target["alter_sql"])

        if bad:
            sys.stderr.write("Refusing migration: evidence_hash contains non-64-hex values.\n")
            return 1

        if not planned:
            print("evidence_hash_collation_ok=1")
            return 0

        print("evidence_hash_collation_ok=0")
        print("planned_alters:")
        for sql in planned:
            print(f"  {sql};")

        if not args.apply:
            print("dry_run=1")
            print("hint: rerun with --apply after reviewing the planned ALTER statements.")
            return 0

        for sql in planned:
            core_q.run_sql(
                sql,
                (),
                fetch="none",
                query_name="normalize_evidence_hash_collation.apply",
            )
        print("applied=1")
        return 0
    except Exception as exc:  # noqa: BLE001 - operator migration helper
        sys.stderr.write(f"Migration helper failed: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
