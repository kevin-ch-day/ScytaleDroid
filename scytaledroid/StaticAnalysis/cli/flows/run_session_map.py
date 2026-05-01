"""Run-map and session-link helpers for static analysis run dispatch."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.package_utils import resolve_package_identity
from scytaledroid.Utils.DisplayUtils import status_messages

from ..core.models import AppRunResult, RunOutcome
from .session_finalizer import persist_static_session_links


def _session_run_map_path(session_stamp: str | None) -> Path | None:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return None
    return Path(app_config.DATA_DIR) / "sessions" / stamp / "run_map.json"


def _session_run_link_count(session_stamp: str | None) -> int:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return 0

    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM static_session_run_links WHERE session_stamp=%s",
            (stamp,),
            fetch="one",
        )
        return int((row or [0])[0] or 0)
    except Exception:
        return 0


def _session_completed_run_count(session_stamp: str | None) -> int:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return 0

    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_stamp=%s
              AND status='COMPLETED'
            """,
            (stamp,),
            fetch="one",
        )
        return int((row or [0])[0] or 0)
    except Exception:
        return 0


def _build_session_run_map(
    outcome: RunOutcome | None,
    session_stamp: str | None,
    *,
    allow_overwrite: bool,
) -> dict | None:
    if outcome is None or not session_stamp:
        return None

    results = outcome.results or []
    if not results:
        return None

    duplicates = _detect_duplicate_packages(results)
    if duplicates:
        raise RuntimeError(
            "Duplicate package(s) detected in session; cannot build run map. "
            f"Duplicates: {', '.join(sorted(duplicates))}. "
            "Disambiguate the scope or rerun with a single package per session."
        )

    static_ids = [res.static_run_id for res in results if res.static_run_id]
    origin_map: dict[int, str | None] = {}

    if static_ids:
        try:
            rows = core_q.run_sql(
                f"SELECT id, session_stamp FROM static_analysis_runs WHERE id IN ({','.join(['%s'] * len(static_ids))})",
                tuple(static_ids),
                fetch="all",
            )
            for row in rows:
                if not row or row[0] is None:
                    continue
                origin_map[int(row[0])] = row[1] if row[1] else None
        except Exception:
            origin_map = {}

    apps = []
    by_package = {}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    for res in results:
        static_run_id = res.static_run_id
        base_report = res.base_report()
        meta = getattr(base_report, "metadata", {}) if base_report else {}

        if not isinstance(meta, dict):
            meta = {}

        identity = resolve_package_identity(str(res.package_name or ""), context="static_analysis")
        package_name = identity.normalized_package_name or str(res.package_name or "").strip()

        entry = {
            "package": package_name,
            "static_run_id": static_run_id,
            "run_origin": None,
            "origin_session_stamp": None,
            "pipeline_version": meta.get("pipeline_version"),
            "base_apk_sha256": meta.get("base_apk_sha256"),
            "artifact_set_hash": meta.get("artifact_set_hash"),
            "run_signature": meta.get("run_signature"),
            "run_signature_version": meta.get("run_signature_version"),
            "identity_valid": meta.get("identity_valid"),
            "identity_error_reason": meta.get("identity_error_reason"),
        }
        entry.update(identity.as_metadata())

        if static_run_id:
            origin_session = origin_map.get(static_run_id)
            entry["origin_session_stamp"] = origin_session
            entry["run_origin"] = "created" if origin_session == session_stamp else "reused"

        apps.append(entry)
        by_package[package_name] = entry

    run_map = {
        "session_stamp": session_stamp,
        "created_at_utc": now,
        "apps": apps,
        "by_package": by_package,
    }

    _write_run_map_atomic(session_stamp, run_map, allow_overwrite=bool(allow_overwrite))

    return run_map


def _persist_session_run_links(session_stamp: str | None, run_map: dict | None) -> None:
    if not session_stamp or not run_map:
        return

    try:
        from scytaledroid.Database.db_utils import diagnostics

        def _run_sql(sql, params=(), **kwargs):
            query_name = kwargs.get("query_name")
            fetch = kwargs.get("fetch")
            if query_name and not fetch:
                return core_q.run_sql_write(sql, params, query_name=query_name)
            return core_q.run_sql(sql, params, **kwargs)

        persist_static_session_links(
            session_stamp,
            run_map,
            run_sql=_run_sql,
            get_table_columns=diagnostics.get_table_columns,
            write_query_name="static.run_dispatch.persist_session_run_links",
        )
    except Exception as exc:
        print(
            status_messages.status(
                f"Failed to persist static session run links: {exc}",
                level="warn",
            )
        )


def _rebuild_session_run_map_from_db(session_stamp: str | None) -> dict | None:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return None

    rows = core_q.run_sql(
        """
        SELECT a.package_name,
               sar.id AS static_run_id,
               sar.session_stamp,
               sar.pipeline_version,
               sar.base_apk_sha256,
               sar.artifact_set_hash,
               sar.run_signature,
               sar.run_signature_version,
               sar.identity_valid,
               sar.identity_error_reason
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id=sar.app_version_id
        JOIN apps a ON a.id=av.app_id
        WHERE sar.session_label=%s
          AND sar.status='COMPLETED'
        ORDER BY a.package_name
        """,
        (stamp,),
        fetch="all_dict",
        dictionary=True,
    ) or []

    if not rows:
        return None

    apps: list[dict[str, object]] = []
    by_package: dict[str, dict[str, object]] = {}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    for row in rows:
        package_name = str(row.get("package_name") or "").strip()
        identity = resolve_package_identity(package_name, context="static_analysis")
        normalized = identity.normalized_package_name or package_name

        if not normalized:
            continue

        entry = {
            "package": normalized,
            "static_run_id": int(row.get("static_run_id") or 0),
            "run_origin": "created",
            "origin_session_stamp": row.get("session_stamp") or stamp,
            "pipeline_version": row.get("pipeline_version"),
            "base_apk_sha256": row.get("base_apk_sha256"),
            "artifact_set_hash": row.get("artifact_set_hash"),
            "run_signature": row.get("run_signature"),
            "run_signature_version": row.get("run_signature_version"),
            "identity_valid": row.get("identity_valid"),
            "identity_error_reason": row.get("identity_error_reason"),
        }
        entry.update(identity.as_metadata())
        apps.append(entry)
        by_package[normalized] = entry

    if not apps:
        return None

    run_map = {
        "session_stamp": stamp,
        "created_at_utc": now,
        "apps": apps,
        "by_package": by_package,
    }

    _write_run_map_atomic(stamp, run_map, allow_overwrite=True)

    return run_map


def _ensure_session_finalization_outputs(session_stamp: str | None) -> list[str]:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return []

    issues: list[str] = []
    run_map_path = _session_run_map_path(stamp)
    expected_count = _session_completed_run_count(stamp)
    link_count = _session_run_link_count(stamp)

    if (run_map_path and run_map_path.exists()) and link_count >= expected_count > 0:
        return issues

    try:
        rebuilt_run_map = _rebuild_session_run_map_from_db(stamp)

        if rebuilt_run_map is not None and _session_run_link_count(stamp) < max(
            expected_count,
            len(rebuilt_run_map.get("apps", [])),
        ):
            _persist_session_run_links(stamp, rebuilt_run_map)

        if run_map_path and not run_map_path.exists():
            issues.append("run_map_missing")

        final_link_count = _session_run_link_count(stamp)
        if expected_count > 0 and final_link_count < expected_count:
            issues.append("session_links_incomplete")
        elif final_link_count == 0:
            issues.append("session_links_missing")

    except Exception:
        if run_map_path and not run_map_path.exists():
            issues.append("run_map_missing")

        final_link_count = _session_run_link_count(stamp)
        if expected_count > 0 and final_link_count < expected_count:
            issues.append("session_links_incomplete")
        elif final_link_count == 0:
            issues.append("session_links_missing")

    return issues


def _detect_duplicate_packages(results: list[AppRunResult]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for res in results:
        identity = resolve_package_identity(str(res.package_name or ""), context="static_analysis")
        pkg = identity.normalized_package_name or str(res.package_name or "").strip()

        if not pkg:
            continue

        if pkg in seen:
            duplicates.add(pkg)
        else:
            seen.add(pkg)

    return duplicates


def _write_run_map_atomic(session_stamp: str, run_map: dict, *, allow_overwrite: bool) -> None:
    session_dir = Path(app_config.DATA_DIR) / "sessions" / session_stamp
    session_dir.mkdir(parents=True, exist_ok=True)
    final_path = session_dir / "run_map.json"

    if final_path.exists():
        if not allow_overwrite:
            raise RuntimeError(
                f"run_map.json already exists for session {session_stamp}; "
                "set SCYTALEDROID_RUN_MAP_OVERWRITE=1 to overwrite."
            )

        print(
            status_messages.status(
                f"Overwriting existing run_map.json for session {session_stamp}.",
                level="warn",
            )
        )

    lock_path = session_dir / ".run_map.lock"
    lock_fd = None

    try:
        lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"run_map.json is locked for session {session_stamp}; another process may be writing it."
        ) from exc

    try:
        tmp_path = session_dir / "run_map.json.tmp"
        payload = json.dumps(run_map, indent=2, sort_keys=True)

        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, final_path)

    finally:
        if lock_fd is not None:
            os.close(lock_fd)

            try:
                os.unlink(lock_path)
            except OSError:
                pass


__all__ = [
    "_build_session_run_map",
    "_ensure_session_finalization_outputs",
    "_persist_session_run_links",
    "_session_completed_run_count",
    "_session_run_link_count",
    "_session_run_map_path",
]