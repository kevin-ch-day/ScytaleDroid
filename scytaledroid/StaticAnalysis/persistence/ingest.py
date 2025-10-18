"""Idempotent ingest helpers for canonical static-analysis tables.

This module provides minimal utilities to upsert app/app_version and attach
observations (endpoints, secrets, analytics IDs, findings). It is safe to
import without a live database; functions return booleans or IDs and swallow
errors where appropriate.
"""

from __future__ import annotations

from typing import Mapping, Optional

from scytaledroid.Database.db_core import db_queries as core_q


def _get_or_create_app(package_name: str, display_name: Optional[str] = None) -> Optional[int]:
    try:
        row = core_q.run_sql(
            "SELECT id FROM apps WHERE package_name = %s",
            (package_name,),
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])
        new_id = core_q.run_sql(
            "INSERT INTO apps (package_name, display_name) VALUES (%s, %s)",
            (package_name, display_name),
            return_lastrowid=True,
        )
        return int(new_id) if new_id else None
    except Exception:
        return None


def _get_or_create_version(
    app_id: int,
    *,
    version_name: Optional[str],
    version_code: Optional[int],
    min_sdk: Optional[int],
    target_sdk: Optional[int],
) -> Optional[int]:
    try:
        row = core_q.run_sql(
            "SELECT id FROM app_versions WHERE app_id = %s AND version_name <=> %s AND version_code <=> %s",
            (app_id, version_name, version_code),
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])
        new_id = core_q.run_sql(
            (
                "INSERT INTO app_versions (app_id, version_name, version_code, min_sdk, target_sdk) "
                "VALUES (%s, %s, %s, %s, %s)"
            ),
            (app_id, version_name, version_code, min_sdk, target_sdk),
            return_lastrowid=True,
        )
        return int(new_id) if new_id else None
    except Exception:
        return None


def ingest_baseline_payload(payload: Mapping[str, object]) -> bool:
    """Upsert app + version rows from a baseline payload. Returns True on success.

    This function does not yet persist observations; it establishes the app and
    version records to support later canonical ingestion.
    """
    try:
        app = payload.get("app", {}) if isinstance(payload, Mapping) else {}
        package = str(app.get("package") or app.get("package_name") or "")
        if not package:
            return False
        display_name = str(app.get("label") or app.get("app_label") or package)
        app_id = _get_or_create_app(package, display_name)
        if not app_id:
            return False
        version_name = app.get("version_name")
        version_code = app.get("version_code")
        min_sdk = app.get("min_sdk")
        target_sdk = app.get("target_sdk")
        _ = _get_or_create_version(
            int(app_id),
            version_name=str(version_name) if version_name is not None else None,
            version_code=int(version_code) if version_code is not None else None,
            min_sdk=int(min_sdk) if min_sdk is not None else None,
            target_sdk=int(target_sdk) if target_sdk is not None else None,
        )
        return True
    except Exception:
        return False


__all__ = ["ingest_baseline_payload"]

