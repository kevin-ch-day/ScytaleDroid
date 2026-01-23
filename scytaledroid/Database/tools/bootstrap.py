"""Schema bootstrapper for local (SQLite) and MySQL deployments.

Usage:
    python -m scytaledroid.Database.tools.bootstrap
    or call bootstrap_database() from application setup.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from scytaledroid.Database.db_core import db_engine
from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_core.db_queries import run_sql
from scytaledroid.Database.db_queries.canonical import schema as canonical_schema
from scytaledroid.Utils.LoggingUtils import logging_utils as log


_DDL_PATTERN = re.compile(r'"""(.*?)"""', re.DOTALL)


def _extract_ddl_blocks(path: Path) -> List[str]:
    blocks: List[str] = []
    text = path.read_text(encoding="utf-8")
    for match in _DDL_PATTERN.finditer(text):
        block = match.group(1).strip()
        if not block:
            continue
        upper_block = block.upper()
        if "CREATE TABLE" in upper_block or "ALTER TABLE" in upper_block or "CREATE INDEX" in upper_block:
            blocks.append(block)
    return blocks


def _iter_schema_files() -> Iterable[Path]:
    root = Path(__file__).resolve().parent.parent / "db_queries"
    for path in root.rglob("*.py"):
        yield path


def _normalize_sqlite(sql: str) -> str:
    """Translate MySQL-ish DDL to SQLite-friendly syntax."""
    # Drop ENGINE/CHARSET fragments
    sql = re.sub(r"ENGINE=InnoDB[^;]*", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"DEFAULT CHARSET=\w+", "", sql, flags=re.IGNORECASE)
    sql = sql.replace("AUTO_INCREMENT", "")

    replacements = [
        (r"BIGINT\s+UNSIGNED", "INTEGER"),
        (r"BIGINT", "INTEGER"),
        (r"INT\s+UNSIGNED", "INTEGER"),
        (r"INT\(", "INTEGER("),
        (r"TINYINT\(\d+\)", "INTEGER"),
        (r"SMALLINT\s+UNSIGNED", "INTEGER"),
        (r"SMALLINT", "INTEGER"),
        (r"LONGTEXT", "TEXT"),
        (r"UNSIGNED", ""),
        (r"DOUBLE", "REAL"),
        (r"DECIMAL\([0-9,]+\)", "REAL"),
        (r"JSON", "TEXT"),
        (r"\bDATETIME\b", "TEXT"),
        (r"\bTIMESTAMP\b", "TEXT"),
        (r"ENUM\([^)]*\)", "TEXT"),
    ]
    for pattern, replacement in replacements:
        sql = re.sub(pattern, replacement, sql, flags=re.IGNORECASE)

    # Strip MySQL KEY/CONSTRAINT lines that SQLite won't parse cleanly
    cleaned_lines: list[str] = []
    cleaned_lines: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith("KEY ") or upper.startswith("UNIQUE KEY") or upper.startswith("CONSTRAINT "):
            continue
        if upper.startswith("FOREIGN KEY"):
            continue
        # DROP ON UPDATE fragments (not supported)
        if "ON UPDATE" in upper or "ON DELETE" in upper:
            continue
        if "REFERENCES" in upper:
            continue
        if upper.startswith("PRIMARY KEY") and cleaned_lines and not cleaned_lines[-1].rstrip().endswith(","):
            cleaned_lines[-1] = cleaned_lines[-1].rstrip() + ","
        cleaned_lines.append(line.rstrip())

    sql = "\n".join(line for line in cleaned_lines if line.strip())
    sql = re.sub(r",\s*\)", "\n)", sql)
    return sql.strip().rstrip(";") + ";"


def _execute_statements(statements: Iterable[str], *, dialect: str) -> None:
    for stmt in statements:
        sql = stmt
        if dialect == "sqlite":
            # Skip some MySQL-only ALTERs that SQLite cannot parse even after replacements
            upper = stmt.upper()
            if "ALTER TABLE" in upper:
                continue
            sql = _normalize_sqlite(stmt)
        try:
            run_sql(sql)
        except Exception as exc:  # pragma: no cover - best-effort bootstrap
            log.warning(f"Schema statement failed ({sql[:60]}...): {exc}", category="database")


def bootstrap_database() -> None:
    dialect = str(DB_CONFIG.get("engine", "sqlite")).lower()
    ddl_blocks: List[str] = []

    if dialect == "sqlite":
        log.warning(
            "SQLite bootstrap uses relaxed constraints; MariaDB/MySQL is canonical.",
            category="database",
        )

    # Prefer ordered canonical schema statements first to avoid FK ordering issues.
    try:
        ddl_blocks.extend(list(getattr(canonical_schema, "_DDL_STATEMENTS", [])))
    except Exception:
        pass

    for path in _iter_schema_files():
        ddl_blocks.extend(_extract_ddl_blocks(path))

    # Ensure schema_version exists and is populated
    schema_version_stmt = """
    CREATE TABLE IF NOT EXISTS schema_version (
      version TEXT NOT NULL,
      applied_at_utc TEXT NOT NULL
    );
    """
    ddl_blocks.insert(0, schema_version_stmt)

    if not ddl_blocks:
        log.warning("No schema statements discovered during bootstrap.", category="database")
        return

    log.info(f"Bootstrapping schema for {dialect} with {len(ddl_blocks)} statements.", category="database")
    _execute_statements(ddl_blocks, dialect=dialect)
    # Record schema version after successful bootstrap (append-only, if empty)
    try:
        row = run_sql("SELECT COUNT(*) FROM schema_version", fetch="one")
        if row and int(row[0]) == 0:
            run_sql(
                "INSERT INTO schema_version (version, applied_at_utc) VALUES (%s, %s)",
                (
                    "0.3.0-bootstrap",
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                ),
            )
    except Exception as exc:  # pragma: no cover
        log.warning(f"Failed to record schema_version: {exc}", category="database")
    log.info("Schema bootstrap complete.", category="database")


if __name__ == "__main__":  # pragma: no cover
    bootstrap_database()
