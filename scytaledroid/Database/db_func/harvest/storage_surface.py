"""Database helpers for the storage surface module."""

from __future__ import annotations

from typing import Iterable, Mapping

from ...db_core import run_sql
from ...db_queries.harvest import storage_surface as q
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_tables() -> bool:
    try:
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            ("static_fileproviders",),
            fetch="one",
        )
        ok_fp = bool(row and int(row[0]) > 0)
        row = run_sql(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
            ("static_provider_acl",),
            fetch="one",
        )
        ok_acl = bool(row and int(row[0]) > 0)
        if not (ok_fp and ok_acl):
            log.warning(
                "storage surface tables missing; load a DB snapshot or apply migrations.",
                category="database",
            )
        return ok_fp and ok_acl
    except Exception:
        return False


def replace_fileproviders(context: Mapping[str, object], rows: Iterable[Mapping[str, object]]) -> None:
    package = context.get("package_name")
    session = context.get("session_stamp")
    run_key = context.get("run_key")
    if not package or not session or not run_key:
        return
    try:
        run_sql(q.DELETE_FILEPROVIDERS_FOR_SESSION, (package, session))
        for row in rows:
            payload = dict(row)
            payload.update({
                "package_name": package,
                "session_stamp": session,
                "scope_label": context.get("scope_label"),
                "app_id": context.get("app_id"),
                "apk_id": context.get("apk_id"),
                "sha256": context.get("sha256"),
                "run_key": run_key,
                "base_perm": row.get("base_perm"),
                "read_perm": row.get("read_perm"),
                "write_perm": row.get("write_perm"),
                "grant_uri_permissions": int(row.get("grant_uri_permissions", 0) or 0),
            })
            run_sql(q.INSERT_FILEPROVIDER, payload)
    except Exception:
        return


def replace_provider_acl(context: Mapping[str, object], rows: Iterable[Mapping[str, object]]) -> None:
    package = context.get("package_name")
    session = context.get("session_stamp")
    run_key = context.get("run_key")
    if not package or not session or not run_key:
        return
    try:
        run_sql(q.DELETE_PROVIDER_ACL_FOR_SESSION, (package, session))
        for row in rows:
            payload = dict(row)
            payload.update({
                "package_name": package,
                "session_stamp": session,
                "scope_label": context.get("scope_label"),
                "app_id": context.get("app_id"),
                "apk_id": context.get("apk_id"),
                "sha256": context.get("sha256"),
                "run_key": run_key,
                "path": row.get("path") or "*",
                "path_type": row.get("path_type") or "base",
                "read_perm": row.get("read_perm"),
                "write_perm": row.get("write_perm"),
                "base_perm": row.get("base_perm"),
            })
            run_sql(q.INSERT_PROVIDER_ACL, payload)
    except Exception:
        return


def _ensure_extended_columns() -> None:
    log.warning(
        "storage surface schema checks are disabled at runtime; apply migrations if columns are missing.",
        category="database",
    )


__all__ = ["ensure_tables", "replace_fileproviders", "replace_provider_acl"]
