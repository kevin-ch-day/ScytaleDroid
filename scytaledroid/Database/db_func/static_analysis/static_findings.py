"""Persistence helpers for static analysis findings."""

from __future__ import annotations

import json
from typing import Mapping, Sequence

from ...db_core import database_session, run_sql
from ...db_core import db_config
from ...db_queries.static_analysis import static_findings as queries
from scytaledroid.Utils.LoggingUtils import logging_utils as log

_IS_SQLITE = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower() == "sqlite"

SQLITE_CREATE_FINDINGS_SUMMARY = """
CREATE TABLE IF NOT EXISTS static_findings_summary (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package_name TEXT NOT NULL,
  session_stamp TEXT NOT NULL,
  scope_label TEXT NOT NULL,
  run_id INTEGER NULL,
  static_run_id INTEGER NULL,
  high INTEGER NOT NULL DEFAULT 0,
  med INTEGER NOT NULL DEFAULT 0,
  low INTEGER NOT NULL DEFAULT 0,
  info INTEGER NOT NULL DEFAULT 0,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(package_name, session_stamp, scope_label)
);
"""

SQLITE_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS static_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  summary_id INTEGER NOT NULL,
  run_id INTEGER NULL,
  static_run_id INTEGER NULL,
  finding_id TEXT NULL,
  severity TEXT NOT NULL,
  title TEXT NULL,
  evidence TEXT NULL,
  fix TEXT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

def _table_has_column(table: str, column: str) -> bool:
    try:
        rows = run_sql(f"SHOW COLUMNS FROM {table}", fetch="all")
        return any(row[0] == column for row in rows)
    except Exception:
        return False


def _table_has_index(table: str, index: str) -> bool:
    try:
        rows = run_sql(f"SHOW INDEX FROM {table}", fetch="all")
        return any(row[2] == index for row in rows)
    except Exception:
        return False


def ensure_tables() -> bool:
    if _IS_SQLITE:
        try:
            row1 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_findings_summary'",
                fetch="one",
            )
            row2 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_findings'",
                fetch="one",
            )
            ok_summary = bool(row1)
            ok_findings = bool(row2)
        except Exception:
            return False
    else:
        row = run_sql(queries.TABLE_EXISTS_SUMMARY, fetch="one")
        ok_summary = bool(row and int(row[0]) > 0)
        row = run_sql(queries.TABLE_EXISTS_FINDINGS, fetch="one")
        ok_findings = bool(row and int(row[0]) > 0)
    if not (ok_summary and ok_findings):
        log.warning(
            "static_findings tables missing; load a DB snapshot or apply migrations.",
            category="database",
        )
    return ok_summary and ok_findings


def tables_exist() -> bool:
    if _IS_SQLITE:
        try:
            row1 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_findings_summary'",
                fetch="one",
            )
            row2 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_findings'",
                fetch="one",
            )
            return bool(row1 and row2)
        except Exception:
            return False
    try:
        row1 = run_sql(queries.TABLE_EXISTS_SUMMARY, fetch="one")
        row2 = run_sql(queries.TABLE_EXISTS_FINDINGS, fetch="one")
        return bool(row1 and int(row1[0]) > 0 and row2 and int(row2[0]) > 0)
    except Exception:
        return False


def upsert_summary(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    severity_counts: Mapping[str, int],
    details: Mapping[str, object] | None = None,
    run_id: int | None = None,
    static_run_id: int | None = None,
) -> int | None:
    if _IS_SQLITE:
        payload = {
            "package_name": package_name,
            "session_stamp": session_stamp,
            "scope_label": scope_label,
            "high": int(severity_counts.get("High", 0) or severity_counts.get("H", 0)),
            "med": int(severity_counts.get("Medium", 0) or severity_counts.get("Med", 0) or severity_counts.get("M", 0)),
            "low": int(severity_counts.get("Low", 0) or severity_counts.get("L", 0)),
            "info": int(severity_counts.get("Info", 0) or severity_counts.get("I", 0)),
            "details": json.dumps(details or {}),
            "run_id": int(run_id) if run_id is not None else None,
            "static_run_id": int(static_run_id) if static_run_id is not None else None,
        }
        stmt = """
        INSERT INTO static_findings_summary (
          package_name, session_stamp, scope_label, run_id, static_run_id,
          high, med, low, info, details
        ) VALUES (
          %(package_name)s, %(session_stamp)s, %(scope_label)s, %(run_id)s, %(static_run_id)s,
          %(high)s, %(med)s, %(low)s, %(info)s, %(details)s
        )
        ON CONFLICT(package_name, session_stamp, scope_label) DO UPDATE SET
          run_id=excluded.run_id,
          static_run_id=excluded.static_run_id,
          high=excluded.high,
          med=excluded.med,
          low=excluded.low,
          info=excluded.info,
          details=excluded.details;
        """
        try:
            with database_session():
                run_sql(stmt, payload)
                row = run_sql(
                    "SELECT id FROM static_findings_summary WHERE package_name=%s AND session_stamp=%s AND scope_label=%s",
                    (package_name, session_stamp, scope_label),
                    fetch="one",
                )
            return int(row[0]) if row else None
        except Exception:
            return None
    payload = {
        "package_name": package_name,
        "session_stamp": session_stamp,
        "scope_label": scope_label,
        "high": int(severity_counts.get("High", 0) or severity_counts.get("H", 0)),
        "med": int(severity_counts.get("Medium", 0) or severity_counts.get("Med", 0) or severity_counts.get("M", 0)),
        "low": int(severity_counts.get("Low", 0) or severity_counts.get("L", 0)),
        "info": int(severity_counts.get("Info", 0) or severity_counts.get("I", 0)),
        "details": json.dumps(details or {}),
    }
    has_run_column = _table_has_column("static_findings_summary", "run_id")
    has_static_column = _table_has_column("static_findings_summary", "static_run_id")
    if run_id is not None and has_run_column:
        payload["run_id"] = int(run_id)
    if static_run_id is not None and has_static_column:
        payload["static_run_id"] = int(static_run_id)

    if static_run_id is not None and has_static_column:
        queries_select = queries.SELECT_FINDINGS_SUMMARY_ID_BY_STATIC_RUN
        select_params = (int(static_run_id), payload["scope_label"])
    elif run_id is not None and has_run_column:
        # Prefer run_id when available to avoid session collisions.
        queries_select = queries.SELECT_FINDINGS_SUMMARY_ID_BY_RUN
        select_params = (payload["run_id"], payload["scope_label"])
    else:
        queries_select = queries.SELECT_FINDINGS_SUMMARY_ID
        select_params = (package_name, session_stamp, scope_label)
    statement = (
        queries.UPSERT_FINDINGS_SUMMARY
        if has_run_column
        else queries.UPSERT_FINDINGS_SUMMARY_LEGACY
    )

    try:
        with database_session():
            run_sql(statement, payload)
            row = run_sql(
                queries_select,
                select_params,
                fetch="one",
            )
            if not row and queries_select is queries.SELECT_FINDINGS_SUMMARY_ID_BY_RUN:
                # Fallback in case run_id was not populated during insert.
                row = run_sql(
                    queries.SELECT_FINDINGS_SUMMARY_ID,
                    (package_name, session_stamp, scope_label),
                    fetch="one",
                )
        return int(row[0]) if row else None
    except Exception:
        return None


def replace_findings(
    summary_id: int,
    findings: Sequence[Mapping[str, object]],
    run_id: int | None = None,
    static_run_id: int | None = None,
) -> tuple[int, int]:
    if _IS_SQLITE:
        deleted = 0
        inserted = 0
        with database_session():
            try:
                run_sql("DELETE FROM static_findings WHERE summary_id=%s", (summary_id,))
                deleted = 1
            except Exception:
                pass
            for f in findings or ():
                try:
                    finding_id = (f.get("id") if isinstance(f, dict) else None) or None
                    severity = str(f.get("severity") or "Info")
                    title = str(f.get("title") or "")[:512]
                    evidence = f.get("evidence") if isinstance(f, dict) else None
                    fix = f.get("fix") if isinstance(f, dict) else None
                    ev_json = json.dumps(evidence or {})
                    run_sql(
                        """
                        INSERT INTO static_findings (
                          summary_id, run_id, static_run_id, finding_id, severity, title, evidence, fix
                        ) VALUES (
                          %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            summary_id,
                            run_id,
                            static_run_id,
                            finding_id,
                            severity,
                            title,
                            ev_json,
                            fix,
                        ),
                    )
                    inserted += 1
                except Exception:
                    continue
        return deleted, inserted
    deleted = 0
    inserted = 0
    has_run_id = _table_has_column("static_findings", "run_id")
    has_static_run = _table_has_column("static_findings", "static_run_id")
    with database_session():
        try:
            run_sql(queries.DELETE_FINDINGS_FOR_SUMMARY, (summary_id,))
            deleted = 1
        except Exception:
            pass
        for f in findings or ():
            try:
                finding_id = (f.get("id") if isinstance(f, dict) else None) or None
                severity = str(f.get("severity") or "Info")
                title = str(f.get("title") or "")[:512]
                evidence = f.get("evidence") if isinstance(f, dict) else None
                fix = f.get("fix") if isinstance(f, dict) else None
                ev_json = json.dumps(evidence or {})
                if has_run_id or has_static_run:
                    run_sql(
                        queries.INSERT_FINDING_WITH_RUN,
                        (
                            summary_id,
                            run_id if has_run_id else None,
                            static_run_id if has_static_run else None,
                            finding_id,
                            severity,
                            title,
                            ev_json,
                            fix,
                        ),
                    )
                else:
                    run_sql(queries.INSERT_FINDING, (summary_id, finding_id, severity, title, ev_json, fix))
                inserted += 1
            except Exception:
                continue
    return deleted, inserted


def lookup_summary_id(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    run_id: int | None = None,
    static_run_id: int | None = None,
) -> int | None:
    """Best-effort fetch of a summary id even on legacy schemas."""
    if _IS_SQLITE:
        try:
            row = run_sql(
                "SELECT id FROM static_findings_summary WHERE package_name=%s AND session_stamp=%s AND scope_label=%s",
                (package_name, session_stamp, scope_label),
                fetch="one",
            )
            return int(row[0]) if row else None
        except Exception:
            return None
    has_run_column = _table_has_column("static_findings_summary", "run_id")
    has_static_column = _table_has_column("static_findings_summary", "static_run_id")
    try:
        if static_run_id is not None and has_static_column:
            row = run_sql(
                queries.SELECT_FINDINGS_SUMMARY_ID_BY_STATIC_RUN,
                (int(static_run_id), scope_label),
                fetch="one",
            )
            if row:
                return int(row[0])
        if run_id is not None and has_run_column:
            row = run_sql(
                queries.SELECT_FINDINGS_SUMMARY_ID_BY_RUN,
                (int(run_id), scope_label),
                fetch="one",
            )
            if row:
                return int(row[0])
        row = run_sql(
            queries.SELECT_FINDINGS_SUMMARY_ID,
            (package_name, session_stamp, scope_label),
            fetch="one",
        )
        return int(row[0]) if row else None
    except Exception:
        return None


__all__ = [
    "ensure_tables",
    "tables_exist",
    "upsert_summary",
    "replace_findings",
    "lookup_summary_id",
]
