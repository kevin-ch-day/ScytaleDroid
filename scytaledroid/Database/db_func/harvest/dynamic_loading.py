"""Database helpers for the dynamic loading module."""

from __future__ import annotations

from typing import Iterable, Mapping

from ...db_core import db_config, run_sql
from ...db_queries.harvest import dynamic_loading as q
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_tables() -> bool:
    engine = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower()
    if engine != "sqlite" and not db_config.allow_auto_create():
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            ("static_dynload_events",),
            fetch="one",
        )
        ok_dyn = bool(row and int(row[0]) > 0)
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            ("static_reflection_calls",),
            fetch="one",
        )
        ok_ref = bool(row and int(row[0]) > 0)
        if not (ok_dyn and ok_ref):
            log.warning(
                "dynamic loading tables missing; run bootstrap or migrations.",
                category="database",
            )
        return ok_dyn and ok_ref
    try:
        run_sql(q.CREATE_TABLE_DYNLOAD_EVENTS)
        run_sql(q.CREATE_TABLE_REFLECTION)
        return True
    except Exception:
        return False


def replace_events(context: Mapping[str, object], events: Iterable[Mapping[str, object]]) -> None:
    package = context.get("package_name")
    session = context.get("session_stamp")
    if not package or not session:
        return
    try:
        run_sql(q.DELETE_EVENTS_FOR_SESSION, (package, session))
        for event in events:
            row = dict(event)
            row.update({
                "package_name": package,
                "session_stamp": session,
                "scope_label": context.get("scope_label"),
                "app_id": context.get("app_id"),
                "apk_id": context.get("apk_id"),
                "sha256": context.get("sha256"),
            })
            run_sql(q.INSERT_EVENT, row)
    except Exception:
        return


def replace_reflection_calls(context: Mapping[str, object], calls: Iterable[Mapping[str, object]]) -> None:
    package = context.get("package_name")
    session = context.get("session_stamp")
    if not package or not session:
        return
    try:
        run_sql(q.DELETE_REFLECTION_FOR_SESSION, (package, session))
        for call in calls:
            row = dict(call)
            evidence = row.get("evidence")
            if evidence is not None and not isinstance(evidence, str):
                row["evidence"] = json_dumps_safe(evidence)
            row.update({
                "package_name": package,
                "session_stamp": session,
                "scope_label": context.get("scope_label"),
                "app_id": context.get("app_id"),
                "apk_id": context.get("apk_id"),
                "sha256": context.get("sha256"),
            })
            run_sql(q.INSERT_REFLECTION, row)
    except Exception:
        return


def json_dumps_safe(value: object) -> str:
    try:
        import json

        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "{}"


__all__ = ["ensure_tables", "replace_events", "replace_reflection_calls"]
