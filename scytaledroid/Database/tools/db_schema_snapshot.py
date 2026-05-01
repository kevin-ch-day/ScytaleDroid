"""Generate a read-only DB schema snapshot report under output/audit/db/.

This is an operator/audit convenience for OSS vNext. The filesystem remains the
canonical source of truth; DB is an optional mirror/query layer.

The report is intentionally best-effort and does not mutate the database.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core.db_engine import DatabaseEngine
from scytaledroid.Persistence import db_writer
from scytaledroid.Utils.IO.atomic_write import atomic_write_text


@dataclass(frozen=True)
class _OptionalColumnCheck:
    table: str
    column: str
    present: bool


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _redacted_config() -> dict[str, Any]:
    cfg = dict(db_config.DB_CONFIG)
    cfg.pop("password", None)
    return {
        "engine": str(cfg.get("engine", "")),
        "host": cfg.get("host"),
        "port": cfg.get("port"),
        "user": cfg.get("user"),
        "database": cfg.get("database"),
        "charset": cfg.get("charset"),
        "readonly": cfg.get("readonly"),
        "connect_timeout": cfg.get("connect_timeout"),
        "read_timeout": cfg.get("read_timeout"),
        "write_timeout": cfg.get("write_timeout"),
        "config_source": getattr(db_config, "DB_CONFIG_SOURCE", "unknown"),
        "db_url_set": bool((os.environ.get("SCYTALEDROID_DB_URL") or "").strip()),
    }


def _write_report(out_dir: Path, *, snapshot: dict[str, Any], markdown: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(out_dir / "snapshot.json", json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    atomic_write_text(out_dir / "snapshot.md", markdown.rstrip() + "\n")


def _render_markdown(snapshot: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# DB schema snapshot")
    lines.append("")
    lines.append(f"- timestamp_utc: `{snapshot.get('timestamp_utc', '')}`")
    lines.append(f"- db_enabled: `{snapshot.get('db_enabled', False)}`")
    cfg = snapshot.get("db_config_redacted") or {}
    lines.append(f"- engine: `{cfg.get('engine', '')}`")
    lines.append(f"- host: `{cfg.get('host', '')}`")
    lines.append(f"- database: `{cfg.get('database', '')}`")
    lines.append(f"- config_source: `{cfg.get('config_source', '')}`")
    lines.append("")

    required = snapshot.get("required_tables") or {}
    missing = [name for name, ok in required.items() if not ok]
    lines.append("## required_tables")
    if missing:
        lines.append(f"- status: **MISSING** ({len(missing)}): {', '.join(missing)}")
    else:
        lines.append("- status: **OK**")
    lines.append("")

    optional_cols = snapshot.get("optional_columns") or []
    if optional_cols:
        lines.append("## optional_columns")
        lines.append("| table | column | present |")
        lines.append("| --- | --- | --- |")
        for entry in optional_cols:
            lines.append(f"| {entry.get('table','')} | {entry.get('column','')} | {entry.get('present', False)} |")
        lines.append("")

    history = snapshot.get("schema_version_history") or []
    lines.append("## schema_version (latest 20)")
    if not history:
        lines.append("- (none)")
    else:
        lines.append("| version | applied_at_utc |")
        lines.append("| --- | --- |")
        for row in history:
            lines.append(f"| {row.get('version','')} | {row.get('applied_at_utc','')} |")
    lines.append("")

    tables = snapshot.get("tables") or []
    lines.append("## tables")
    if not tables:
        lines.append("- (none)")
        return "\n".join(lines)

    lines.append("| table | type | approx_rows |")
    lines.append("| --- | --- | ---: |")
    for table in tables:
        name = table.get("name", "")
        ttype = table.get("type", "")
        rows = table.get("approx_rows")
        rows_str = str(rows) if rows is not None else ""
        lines.append(f"| {name} | {ttype} | {rows_str} |")
    lines.append("")
    return "\n".join(lines)


def generate_snapshot() -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "db_enabled": bool(db_config.db_enabled()),
        "db_config_redacted": _redacted_config(),
    }

    if not db_config.db_enabled():
        snapshot["note"] = "DB disabled; no connection attempted."
        return snapshot

    engine = DatabaseEngine().as_reader()
    try:
        engine.fetch_one("SELECT 1")
        required_tables = ["schema_version", *db_writer.REQUIRED_TABLES]
        table_rows = engine.fetch_all(
            """
            SELECT table_name, table_type, table_rows
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
            ORDER BY table_name
            """
        ) or []
        present_tables = {str(r[0]) for r in table_rows if r and r[0]}
        snapshot["required_tables"] = {name: (name in present_tables) for name in required_tables}

        snapshot["tables"] = [
            {
                "name": str(r[0]),
                "type": str(r[1]) if r[1] is not None else "",
                "approx_rows": int(r[2]) if r[2] is not None else None,
            }
            for r in table_rows
            if r and r[0]
        ]

        try:
            rows = engine.fetch_all(
                "SELECT version, applied_at_utc FROM schema_version ORDER BY applied_at_utc DESC LIMIT 20"
            ) or []
            snapshot["schema_version_history"] = [
                {"version": str(r[0]), "applied_at_utc": str(r[1])} for r in rows if r and len(r) >= 2
            ]
        except Exception as exc:
            snapshot["schema_version_history_error"] = f"{exc.__class__.__name__}: {exc}"

        optional_checks = [
            ("metrics", "static_run_id"),
            ("buckets", "static_run_id"),
        ]
        col_rows = engine.fetch_all(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            """
        ) or []
        col_map: dict[str, set[str]] = {}
        for row in col_rows:
            if not row or len(row) < 2:
                continue
            tname = str(row[0])
            cname = str(row[1]).lower()
            col_map.setdefault(tname, set()).add(cname)

        optional_results: list[_OptionalColumnCheck] = []
        for table, column in optional_checks:
            present = column.lower() in col_map.get(table, set())
            optional_results.append(_OptionalColumnCheck(table=table, column=column, present=present))
        snapshot["optional_columns"] = [asdict(x) for x in optional_results]
    finally:
        engine.close()

    return snapshot


def main(argv: list[str] | None = None) -> int:
    _ = argv  # future: accept output dir override
    stamp = _utc_stamp()
    out_dir = Path("output") / "audit" / "db" / stamp
    snapshot = generate_snapshot()
    markdown = _render_markdown(snapshot)
    _write_report(out_dir, snapshot=snapshot, markdown=markdown)
    print(f"[OK] Wrote DB schema snapshot: {out_dir}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
