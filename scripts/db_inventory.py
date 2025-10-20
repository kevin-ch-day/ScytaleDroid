#!/usr/bin/env python3
"""Summarise canonical database contents.

This helper inspects the configured MySQL schema and prints a readable snapshot
of every table/view: row counts, column definitions, and sample rows. Use it to
understand what persistence already stores before pruning legacy ingestion
logic.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from mysql.connector import Error

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine


@dataclass
class TableInfo:
    name: str
    type: str


def _clip(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "\u2026"


def fetch_tables(engine: DatabaseEngine, schema: str) -> List[TableInfo]:
    rows = engine.fetch_all(
        """
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = %s
        ORDER BY table_type, table_name
        """,
        (schema,),
    )
    return [TableInfo(name=row[0], type=row[1]) for row in rows]


def fetch_columns(engine: DatabaseEngine, schema: str, table: str) -> List[Tuple[str, str, str, str, str]]:
    rows = engine.fetch_all(
        """
        SELECT column_name, column_type, column_key, is_nullable, IFNULL(column_default, '—')
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s
        ORDER BY ordinal_position
        """,
        (schema, table),
    )
    return [(str(r[0]), str(r[1]), str(r[2] or ""), str(r[3]), str(r[4])) for r in rows]


def fetch_row_count(engine: DatabaseEngine, schema: str, table: str) -> int:
    ident = table.replace("`", "``")
    query = f"SELECT COUNT(*) FROM `{schema}`.`{ident}`"
    row = engine.fetch_one(query)
    return int(row[0]) if row else 0


def fetch_samples(engine: DatabaseEngine, schema: str, table: str, limit: int) -> Sequence[dict]:
    if limit <= 0:
        return []
    ident = table.replace("`", "``")
    query = f"SELECT * FROM `{schema}`.`{ident}` LIMIT %s"
    try:
        return engine.fetch_all_dict(query, (limit,))
    except Error:
        # Some views may reject LIMIT placeholders – retry with literal.
        query_literal = f"SELECT * FROM `{schema}`.`{ident}` LIMIT {int(limit)}"
        return engine.fetch_all_dict(query_literal)


def render_samples(samples: Sequence[dict], width: int) -> Iterable[str]:
    if not samples:
        yield "  (none)"
        return
    for sample in samples:
        raw = json.dumps(sample, ensure_ascii=False, default=str)
        yield f"  {_clip(raw, width)}"


def render_columns(columns: Sequence[Tuple[str, str, str, str, str]]) -> Iterable[str]:
    if not columns:
        yield "  (no columns)"
        return
    for name, col_type, col_key, is_null, default in columns:
        key = col_key or ""
        nullable = "NULL" if is_null.upper() == "YES" else "NOT NULL"
        pieces = [name, f"{col_type}", nullable]
        if key:
            pieces.append(f"{key}")
        pieces.append(f"default: {default}")
        yield "  " + " | ".join(pieces)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect canonical database tables and views.")
    parser.add_argument(
        "--schema",
        default=db_config.DB_CONFIG.get("database", ""),
        help="Schema/database to inspect (defaults to configured database).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Number of sample rows to display per table/view (default: 3).",
    )
    parser.add_argument(
        "--width",
        type=int,
        default=100,
        help="Clip width for sample JSON strings (default: 100).",
    )
    parser.add_argument(
        "--only",
        nargs="*",
        help="Optional specific table/view names to include (case-sensitive).",
    )
    args = parser.parse_args()

    engine = DatabaseEngine()
    try:
        tables = fetch_tables(engine, args.schema)
        if args.only:
            wanted = set(args.only)
            tables = [t for t in tables if t.name in wanted]
            missing = sorted(wanted - {t.name for t in tables})
            if missing:
                print(f"! Skipped missing objects: {', '.join(missing)}")
        if not tables:
            print(f"No tables or views found in schema `{args.schema}`.")
            return
        for info in tables:
            print()
            print(f"table: {info.name}   [{info.type.lower()}]")
            count = fetch_row_count(engine, args.schema, info.name)
            print(f"rows = {count}")
            print("columns")
            for line in render_columns(fetch_columns(engine, args.schema, info.name)):
                print(line)
            print("sample rows")
            for line in render_samples(fetch_samples(engine, args.schema, info.name, args.limit), args.width):
                print(line)
    finally:
        engine.close()


if __name__ == "__main__":
    main()
