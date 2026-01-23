"""Database helpers for the storage surface module."""

from __future__ import annotations

from typing import Iterable, Mapping

from ...db_core import db_config, run_sql
from ...db_queries.harvest import storage_surface as q
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def ensure_tables() -> bool:
    engine = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower()
    if engine != "sqlite" and not db_config.allow_auto_create():
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
                "storage surface tables missing; run bootstrap or migrations.",
                category="database",
            )
        return ok_fp and ok_acl
    try:
        run_sql(q.CREATE_TABLE_FILEPROVIDERS)
        run_sql(q.CREATE_TABLE_PROVIDER_ACL)
        _ensure_extended_columns()
        return True
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
    def column_exists(table: str, column: str) -> bool:
        try:
            row = run_sql(f"SHOW COLUMNS FROM {table} LIKE %s", (column,), fetch="one")
            return bool(row)
        except Exception:
            return False

    def add_column(sql: str) -> None:
        try:
            run_sql(sql)
        except Exception:
            pass

    if not column_exists("static_fileproviders", "run_key"):
        add_column("ALTER TABLE static_fileproviders ADD COLUMN run_key VARCHAR(128) NULL AFTER id;")
    if not column_exists("static_fileproviders", "base_perm"):
        add_column("ALTER TABLE static_fileproviders ADD COLUMN base_perm VARCHAR(191) NULL AFTER provider_name;")
    if not column_exists("static_fileproviders", "read_perm"):
        add_column("ALTER TABLE static_fileproviders ADD COLUMN read_perm VARCHAR(191) NULL AFTER base_perm;")
    if not column_exists("static_fileproviders", "write_perm"):
        add_column("ALTER TABLE static_fileproviders ADD COLUMN write_perm VARCHAR(191) NULL AFTER read_perm;")
    if not column_exists("static_fileproviders", "grant_uri_permissions"):
        add_column("ALTER TABLE static_fileproviders ADD COLUMN grant_uri_permissions TINYINT(1) NOT NULL DEFAULT 0 AFTER write_perm;")
    try:
        run_sql("ALTER TABLE static_fileproviders ADD UNIQUE KEY uq_fileproviders_run (run_key, authority)")
    except Exception:
        pass
    if not column_exists("static_fileproviders", "risk"):
        add_column("ALTER TABLE static_fileproviders ADD COLUMN risk VARCHAR(32) NULL AFTER grant_uri_permissions;")
    try:
        run_sql("ALTER TABLE static_fileproviders ADD UNIQUE KEY uq_fileproviders_run (run_key, authority)")
    except Exception:
        pass

    if not column_exists("static_provider_acl", "run_key"):
        add_column("ALTER TABLE static_provider_acl ADD COLUMN run_key VARCHAR(128) NULL AFTER id;")
    if not column_exists("static_provider_acl", "path"):
        add_column("ALTER TABLE static_provider_acl ADD COLUMN path TEXT NULL AFTER provider_name;")
    if not column_exists("static_provider_acl", "path_type"):
        add_column("ALTER TABLE static_provider_acl ADD COLUMN path_type VARCHAR(16) NULL AFTER path;")
    if not column_exists("static_provider_acl", "read_perm"):
        add_column("ALTER TABLE static_provider_acl ADD COLUMN read_perm VARCHAR(191) NULL AFTER path_type;")
    if not column_exists("static_provider_acl", "write_perm"):
        add_column("ALTER TABLE static_provider_acl ADD COLUMN write_perm VARCHAR(191) NULL AFTER read_perm;")
    try:
        run_sql(
            "ALTER TABLE static_provider_acl ADD UNIQUE KEY uq_provider_acl_run (run_key, authority, path(191), path_type)"
        )
    except Exception:
        pass


__all__ = ["ensure_tables", "replace_fileproviders", "replace_provider_acl"]
