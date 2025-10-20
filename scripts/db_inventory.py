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
import importlib
import importlib.util
import re
from typing import Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from mysql.connector import Error

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine


@dataclass
class TableInfo:
    name: str
    type: str


@dataclass
class SchemaItem:
    kind: str
    name: str
    target: Optional[str] = None
    columns: Tuple[str, ...] = ()


@dataclass
class SchemaMetadata:
    tables: set[str]
    views: set[str]
    columns: Mapping[str, set[str]]
    indexes: Mapping[str, Mapping[str, set[str]]]


@dataclass
class SchemaCheckResult:
    item: SchemaItem
    status: str
    detail: str = ""


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


CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE,
)
ALTER_TABLE_RE = re.compile(
    r"ALTER\s+TABLE\s+`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE,
)
ADD_COLUMN_RE = re.compile(
    r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE,
)
CREATE_INDEX_RE = re.compile(
    r"CREATE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?\s+ON\s+`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE,
)
CREATE_VIEW_RE = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+`?([a-zA-Z0-9_]+)`?",
    re.IGNORECASE,
)


def parse_schema_statements(statements: Sequence[str]) -> List[SchemaItem]:
    items: List[SchemaItem] = []
    for raw in statements:
        stmt = raw.strip()
        if not stmt:
            continue
        table_match = CREATE_TABLE_RE.search(stmt)
        if table_match:
            items.append(SchemaItem(kind="table", name=table_match.group(1)))
            continue
        view_match = CREATE_VIEW_RE.search(stmt)
        if view_match:
            items.append(SchemaItem(kind="view", name=view_match.group(1)))
            continue
        index_match = CREATE_INDEX_RE.search(stmt)
        if index_match:
            items.append(
                SchemaItem(
                    kind="index",
                    name=index_match.group(1),
                    target=index_match.group(2),
                )
            )
            continue
        alter_match = ALTER_TABLE_RE.search(stmt)
        if alter_match:
            columns = tuple(ADD_COLUMN_RE.findall(stmt))
            items.append(
                SchemaItem(
                    kind="alter",
                    name=alter_match.group(1),
                    columns=columns,
                )
            )
            continue
    return items


def _load_schema_module(module_path: str):
    try:
        return importlib.import_module(module_path)
    except ModuleNotFoundError:
        spec = importlib.util.spec_from_file_location("_schema_module", module_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[arg-type]
            return module
        raise


def fetch_schema_metadata(engine: DatabaseEngine, schema: str) -> SchemaMetadata:
    tables: set[str] = set()
    views: set[str] = set()
    columns: MutableMapping[str, set[str]] = {}
    indexes: MutableMapping[str, MutableMapping[str, set[str]]] = {}

    for name, table_type in engine.fetch_all(
        """
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = %s
        """,
        (schema,),
    ):
        key = str(name)
        typ = str(table_type or "")
        if typ.upper() == "VIEW":
            views.add(key)
        else:
            tables.add(key)

    for table_name, column_name in engine.fetch_all(
        """
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = %s
        """,
        (schema,),
    ):
        table = str(table_name)
        column = str(column_name)
        columns.setdefault(table, set()).add(column)

    for table_name, index_name, column_name in engine.fetch_all(
        """
        SELECT table_name, index_name, column_name
        FROM information_schema.statistics
        WHERE table_schema = %s
        """,
        (schema,),
    ):
        table = str(table_name)
        index = str(index_name)
        column = str(column_name)
        index_map = indexes.setdefault(table, {})
        index_map.setdefault(index, set()).add(column)

    return SchemaMetadata(
        tables=tables,
        views=views,
        columns=columns,
        indexes=indexes,
    )


def summarise_schema_usage(
    items: Sequence[SchemaItem], metadata: SchemaMetadata
) -> List[SchemaCheckResult]:
    results: List[SchemaCheckResult] = []
    for item in items:
        if item.kind == "table":
            status = "present" if item.name in metadata.tables else "missing"
            detail = "already exists" if status == "present" else "will be created"
            results.append(SchemaCheckResult(item=item, status=status, detail=detail))
        elif item.kind == "view":
            status = "present" if item.name in metadata.views else "missing"
            detail = "already exists" if status == "present" else "will be created"
            results.append(SchemaCheckResult(item=item, status=status, detail=detail))
        elif item.kind == "index":
            table_indexes = metadata.indexes.get(item.target or "", {})
            status = "present" if item.name in table_indexes else "missing"
            detail = "already exists" if status == "present" else "will be created"
            results.append(SchemaCheckResult(item=item, status=status, detail=detail))
        elif item.kind == "alter":
            existing_columns = metadata.columns.get(item.name, set())
            missing = [col for col in item.columns if col not in existing_columns]
            if missing:
                status = "needs-columns"
                detail = "missing columns: " + ", ".join(sorted(missing))
            else:
                status = "columns-present"
                detail = "all columns already present"
            results.append(SchemaCheckResult(item=item, status=status, detail=detail))
    return results


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
    parser.add_argument(
        "--check-schema",
        action="store_true",
        help="Compare canonical schema DDL with current database objects.",
    )
    parser.add_argument(
        "--schema-module",
        default="scytaledroid.Database.db_queries.canonical.schema",
        help="Module path to load canonical DDL statements from.",
    )
    args = parser.parse_args()

    engine = DatabaseEngine()
    try:
        if args.check_schema:
            module = _load_schema_module(args.schema_module)
            statements = []
            ddl = getattr(module, "_DDL_STATEMENTS", None)
            if isinstance(ddl, Sequence):
                statements = [str(stmt) for stmt in ddl]
            metadata = fetch_schema_metadata(engine, args.schema)
            items = parse_schema_statements(statements)
            checks = summarise_schema_usage(items, metadata)
            print("Schema coverage (" + args.schema + "):")
            for check in checks:
                item = check.item
                if item.kind == "alter" and item.columns:
                    extra = f" columns={','.join(item.columns)}"
                elif item.kind == "index":
                    extra = f" table={item.target}"
                else:
                    extra = ""
                print(f"- {item.kind} {item.name}{extra}: {check.status} ({check.detail})")

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
