"""Persistence helpers for static analysis findings."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import database_session, db_config, run_sql
from ...db_queries.static_analysis import static_findings as queries

_ENGINE = str(db_config.DB_CONFIG.get("engine", "")).strip().lower()
_IS_SQLITE = _ENGINE == "sqlite"
if _IS_SQLITE and not db_config.is_test_env():
    raise RuntimeError("SQLite backend is test-only; configure MySQL/MariaDB or disable DB.")
_JWT_LIKE_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def _redact_secret_like(value: str) -> str:
    redacted = _JWT_LIKE_RE.sub("[REDACTED:JWT]", value)
    redacted = _AWS_KEY_RE.sub("[REDACTED:AWS_KEY]", redacted)
    return redacted


def _sanitize_evidence_payload(evidence: object) -> object:
    if isinstance(evidence, dict):
        payload = dict(evidence)
        detail = payload.get("detail")
        if isinstance(detail, str):
            payload["detail"] = _redact_secret_like(detail)
        return payload
    if isinstance(evidence, str):
        return _redact_secret_like(evidence)
    return evidence

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
        if _IS_SQLITE:
            rows = run_sql(f"PRAGMA table_info({table})", fetch="all")
            return any(row[1] == column for row in rows or ())
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


def _require_canonical_schema() -> None:
    missing = []
    if not _table_has_column("static_findings_summary", "static_run_id"):
        missing.append("static_findings_summary.static_run_id")
    if not _table_has_column("static_findings", "static_run_id"):
        missing.append("static_findings.static_run_id")
    if missing:
        raise RuntimeError(
            "Legacy schema detected: missing columns: "
            + ", ".join(missing)
            + ". Run migrations before persisting."
        )


def _require_static_run_id(static_run_id: int | None) -> int:
    if static_run_id is None:
        raise ValueError(
            "Legacy write blocked: static_run_id is required for canonical schema writes. "
            "Run migrations or regenerate static outputs."
        )
    return int(static_run_id)


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
        static_run_id = _require_static_run_id(static_run_id)
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
            "static_run_id": static_run_id,
        }
        try:
            with database_session():
                row = run_sql(
                    "SELECT id FROM static_findings_summary "
                    "WHERE package_name=%s AND session_stamp=%s AND scope_label=%s "
                    "ORDER BY id DESC LIMIT 1",
                    (package_name, session_stamp, scope_label),
                    fetch="one",
                )
                if row:
                    run_sql(
                        """
                        UPDATE static_findings_summary
                        SET run_id=%s,
                            static_run_id=%s,
                            high=%s,
                            med=%s,
                            low=%s,
                            info=%s,
                            details=%s
                        WHERE id=%s
                        """,
                        (
                            payload["run_id"],
                            payload["static_run_id"],
                            payload["high"],
                            payload["med"],
                            payload["low"],
                            payload["info"],
                            payload["details"],
                            int(row[0]),
                        ),
                    )
                else:
                    run_sql(
                        """
                        INSERT INTO static_findings_summary (
                          package_name, session_stamp, scope_label, run_id, static_run_id,
                          high, med, low, info, details
                        ) VALUES (
                          %(package_name)s, %(session_stamp)s, %(scope_label)s, %(run_id)s, %(static_run_id)s,
                          %(high)s, %(med)s, %(low)s, %(info)s, %(details)s
                        )
                        """,
                        payload,
                    )
                row = run_sql(
                    "SELECT id FROM static_findings_summary WHERE package_name=%s AND session_stamp=%s AND scope_label=%s ORDER BY id DESC LIMIT 1",
                    (package_name, session_stamp, scope_label),
                    fetch="one",
                )
            return int(row[0]) if row else None
        except Exception:
            return None
    _require_canonical_schema()
    static_run_id = _require_static_run_id(static_run_id)
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
        "static_run_id": static_run_id,
    }
    queries_select = queries.SELECT_FINDINGS_SUMMARY_ID_BY_STATIC_RUN
    select_params = (static_run_id, scope_label)
    statement = queries.UPSERT_FINDINGS_SUMMARY

    try:
        with database_session():
            run_sql(statement, payload)
            row = run_sql(
                queries_select,
                select_params,
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
        static_run_id = _require_static_run_id(static_run_id)
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
                    evidence = _sanitize_evidence_payload(evidence)
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
                except Exception as exc:
                    log.warning(
                        f"static_findings SQLite insert failed summary_id={summary_id}: "
                        f"{exc.__class__.__name__}:{exc}",
                        category="database",
                    )
                    continue
        return deleted, inserted
    deleted = 0
    inserted = 0
    _require_canonical_schema()
    static_run_id = _require_static_run_id(static_run_id)
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
                evidence = _sanitize_evidence_payload(evidence)
                fix = f.get("fix") if isinstance(f, dict) else None
                ev_json = json.dumps(evidence or {})
                run_sql(
                    queries.INSERT_FINDING_WITH_RUN,
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
            except Exception as exc:
                log.warning(
                    f"static_findings insert failed summary_id={summary_id} static_run_id={static_run_id}: "
                    f"{exc.__class__.__name__}:{exc}",
                    category="database",
                )
                continue
    return deleted, inserted


def lookup_summary_id(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    static_run_id: int | None = None,
) -> int | None:
    """Fetch a summary id for the canonical schema."""
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
    try:
        if static_run_id is not None:
            row = run_sql(
                queries.SELECT_FINDINGS_SUMMARY_ID_BY_STATIC_RUN,
                (int(static_run_id), scope_label),
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
