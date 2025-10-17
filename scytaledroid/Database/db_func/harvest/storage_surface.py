"""Database helpers for the storage surface module."""

from __future__ import annotations

from typing import Iterable, Mapping

from ...db_core import run_sql
from ...db_queries.harvest import storage_surface as q
from .dynamic_loading import json_dumps_safe


def ensure_tables() -> bool:
    try:
        run_sql(q.CREATE_TABLE_FILEPROVIDERS)
        run_sql(q.CREATE_TABLE_PROVIDER_ACL)
        return True
    except Exception:
        return False


def replace_fileproviders(context: Mapping[str, object], rows: Iterable[Mapping[str, object]]) -> None:
    package = context.get("package_name")
    session = context.get("session_stamp")
    if not package or not session:
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
            })
            run_sql(q.INSERT_FILEPROVIDER, payload)
    except Exception:
        return


def replace_provider_acl(context: Mapping[str, object], rows: Iterable[Mapping[str, object]]) -> None:
    package = context.get("package_name")
    session = context.get("session_stamp")
    if not package or not session:
        return
    try:
        run_sql(q.DELETE_PROVIDER_ACL_FOR_SESSION, (package, session))
        for row in rows:
            payload = dict(row)
            path_json = payload.get("path_perms_json")
            if path_json is not None and not isinstance(path_json, str):
                payload["path_perms_json"] = json_dumps_safe(path_json)
            payload.update({
                "package_name": package,
                "session_stamp": session,
                "scope_label": context.get("scope_label"),
                "app_id": context.get("app_id"),
                "apk_id": context.get("apk_id"),
                "sha256": context.get("sha256"),
            })
            run_sql(q.INSERT_PROVIDER_ACL, payload)
    except Exception:
        return


__all__ = ["ensure_tables", "replace_fileproviders", "replace_provider_acl"]

