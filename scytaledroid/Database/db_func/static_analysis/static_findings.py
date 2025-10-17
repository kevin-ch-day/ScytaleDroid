"""Persistence helpers for static analysis findings."""

from __future__ import annotations

import json
from typing import Mapping, Sequence

from ...db_core import database_session, run_sql
from ...db_queries.static_analysis import static_findings as queries


def ensure_tables() -> bool:
    try:
        with database_session():
            run_sql(queries.CREATE_FINDINGS_SUMMARY)
            run_sql(queries.CREATE_FINDINGS)
        return True
    except Exception:
        return False


def tables_exist() -> bool:
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
) -> int | None:
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
    try:
        with database_session():
            run_sql(queries.UPSERT_FINDINGS_SUMMARY, payload)
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
) -> tuple[int, int]:
    deleted = 0
    inserted = 0
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
                run_sql(queries.INSERT_FINDING, (summary_id, finding_id, severity, title, ev_json, fix))
                inserted += 1
            except Exception:
                continue
    return deleted, inserted


__all__ = [
    "ensure_tables",
    "tables_exist",
    "upsert_summary",
    "replace_findings",
]

