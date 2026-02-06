"""DB writers for static analysis run persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from collections.abc import Sequence
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.db_queries import run_sql_write
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .dep_export import export_dep_json
from .utils import safe_int


def _normalize_datetime_value(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if "T" in candidate or candidate.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return candidate
    return candidate


def _utc_now_dbstr() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _ensure_app_version(
    *,
    package_for_run: str,
    display_name: str,
    version_name: str | None,
    version_code: int | None,
    min_sdk: int | None,
    target_sdk: int | None,
) -> int | None:
    """Fetch or create an app_version row for static_analysis_runs."""
    try:
        from scytaledroid.Database.db_utils.package_utils import normalize_package_name
        from scytaledroid.Database.db_utils.publisher_rules import apply_publisher_mapping

        cleaned_package = normalize_package_name(package_for_run, context="database")
        if not cleaned_package:
            return None
        app_id = None
        row = core_q.run_sql(
            "SELECT id, display_name FROM apps WHERE package_name=%s",
            (cleaned_package,),
            fetch="one",
        )
        if row and row[0]:
            app_id = int(row[0])
            existing_name = row[1] if len(row) > 1 else None
            if (
                isinstance(display_name, str)
                and display_name.strip()
                and display_name != package_for_run
                and (existing_name is None or existing_name == "" or existing_name == package_for_run)
            ):
                core_q.run_sql(
                    "UPDATE apps SET display_name=%s WHERE id=%s",
                    (display_name, app_id),
                )
        else:
            app_id = core_q.run_sql(
                "INSERT INTO apps (package_name, display_name) VALUES (%s,%s)",
                (cleaned_package, display_name),
                return_lastrowid=True,
            )
            app_id = int(app_id) if app_id else None
            apply_publisher_mapping([cleaned_package])
        if app_id is None:
            return None

        params = (app_id, version_name, version_code)
        row = core_q.run_sql(
            """
            SELECT id FROM app_versions
            WHERE app_id=%s AND version_name<=>%s AND version_code<=>%s
            ORDER BY id DESC LIMIT 1
            """,
            params,
            fetch="one",
        )
        if row and row[0]:
            return int(row[0])

        av_id = core_q.run_sql(
            """
            INSERT INTO app_versions (app_id, version_name, version_code, min_sdk, target_sdk)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (app_id, version_name, version_code, min_sdk, target_sdk),
            return_lastrowid=True,
        )
        return int(av_id) if av_id else None
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to resolve/create app_version for {package_for_run}: {exc}",
            category="static_analysis",
        )
        return None


def _create_static_run(
    *,
    app_version_id: int,
    session_stamp: str,
    session_label: str,
    scope_label: str,
    category: str | None,
    profile: str,
    profile_key: str | None,
    scenario_id: str | None,
    device_serial: str | None,
    tool_semver: str | None,
    tool_git_commit: str | None,
    schema_version: str | None,
    findings_total: int,
    run_started_utc: str | None,
    status: str,
    is_canonical: bool | None = None,
    canonical_set_at_utc: str | None = None,
    canonical_reason: str | None = None,
    sha256: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
) -> int | None:
    normalized_started_at = _normalize_datetime_value(run_started_utc)

    def _insert_run(columns: list[str], values: list[object]) -> int | None:
        placeholders = ", ".join(["%s"] * len(columns))
        sql = f"INSERT INTO static_analysis_runs ({', '.join(columns)}) VALUES ({placeholders})"
        run_id = core_q.run_sql(sql, tuple(values), return_lastrowid=True)
        return int(run_id) if run_id else None

    full_columns = [
        "app_version_id",
        "session_stamp",
        "session_label",
        "scope_label",
        "category",
        "profile_key",
        "scenario_id",
        "device_serial",
        "sha256",
        "base_apk_sha256",
        "artifact_set_hash",
        "run_signature",
        "run_signature_version",
        "identity_valid",
        "identity_error_reason",
        "analysis_version",
        "pipeline_version",
        "catalog_versions",
        "config_hash",
        "study_tag",
        "profile",
        "tool_semver",
        "tool_git_commit",
        "schema_version",
        "findings_total",
        "run_started_utc",
        "status",
        "is_canonical",
        "canonical_set_at_utc",
        "canonical_reason",
    ]
    full_values: list[object] = [
        app_version_id,
        session_stamp,
        session_label,
        scope_label,
        category,
        profile_key,
        scenario_id,
        device_serial,
        sha256,
        base_apk_sha256,
        artifact_set_hash,
        run_signature,
        run_signature_version,
        identity_valid,
        identity_error_reason,
        analysis_version,
        pipeline_version,
        catalog_versions,
        config_hash,
        study_tag,
        profile,
        tool_semver,
        tool_git_commit,
        schema_version,
        findings_total,
        normalized_started_at,
        status,
        1 if is_canonical else 0 if is_canonical is not None else None,
        _normalize_datetime_value(canonical_set_at_utc) if canonical_set_at_utc else None,
        canonical_reason,
    ]
    try:
        return _insert_run(full_columns, full_values)
    except Exception as exc:
        log.warning(
            f"Failed to create static run row for {session_stamp}: {exc}",
            category="static_analysis",
        )
        return None


def create_static_run_ledger(
    *,
    package_name: str,
    display_name: str,
    version_name: str | None,
    version_code: int | None,
    min_sdk: int | None,
    target_sdk: int | None,
    session_stamp: str,
    session_label: str,
    scope_label: str,
    category: str | None,
    profile: str,
    profile_key: str | None,
    scenario_id: str | None,
    device_serial: str | None,
    tool_semver: str | None,
    tool_git_commit: str | None,
    schema_version: str | None,
    findings_total: int,
    run_started_utc: str | None,
    status: str,
    is_canonical: bool | None = None,
    canonical_set_at_utc: str | None = None,
    canonical_reason: str | None = None,
    sha256: str | None = None,
    base_apk_sha256: str | None = None,
    artifact_set_hash: str | None = None,
    run_signature: str | None = None,
    run_signature_version: str | None = None,
    identity_valid: bool | None = None,
    identity_error_reason: str | None = None,
    config_hash: str | None = None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
) -> int | None:
    if is_canonical and session_label:
        try:
            row = core_q.run_sql(
                """
                SELECT COUNT(*)
                FROM static_analysis_runs
                WHERE session_label=%s AND is_canonical=1
                """,
                (session_label,),
                fetch="one",
            )
            existing_canonical = int(row[0] or 0) if row else 0
        except Exception:
            existing_canonical = 0
        if existing_canonical:
            is_canonical = False
            canonical_set_at_utc = None
    app_version_id = _ensure_app_version(
        package_for_run=package_name,
        display_name=display_name,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
    )
    if app_version_id is None:
        return None
    static_run_id = _create_static_run(
        app_version_id=app_version_id,
        session_stamp=session_stamp,
        session_label=session_label,
        scope_label=scope_label,
        category=category,
        profile=profile,
        profile_key=profile_key,
        scenario_id=scenario_id,
        device_serial=device_serial,
        tool_semver=tool_semver,
        tool_git_commit=tool_git_commit,
        schema_version=schema_version,
        findings_total=findings_total,
        run_started_utc=run_started_utc,
        status=status,
        is_canonical=is_canonical,
        canonical_set_at_utc=canonical_set_at_utc,
        canonical_reason=canonical_reason,
        sha256=sha256,
        base_apk_sha256=base_apk_sha256,
        artifact_set_hash=artifact_set_hash,
        run_signature=run_signature,
        run_signature_version=run_signature_version,
        identity_valid=identity_valid,
        identity_error_reason=identity_error_reason,
        config_hash=config_hash,
        pipeline_version=pipeline_version,
        analysis_version=analysis_version,
        catalog_versions=catalog_versions,
        study_tag=study_tag,
    )
    if static_run_id is None:
        return None
    if canonical_reason:
        _maybe_set_canonical_static_run(
            static_run_id=static_run_id,
            session_label=session_label,
            canonical_reason=canonical_reason,
        )
    try:
        run_id = core_q.run_sql(
            """
            INSERT INTO runs (session_stamp, package_name, scope_label, profile, static_run_id)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (session_stamp, package_name, scope_label, profile, static_run_id),
            return_lastrowid=True,
        )
    except Exception:
        run_id = None
    return static_run_id


def _update_static_run_metadata(
    *,
    static_run_id: int,
    run_signature: str | None,
    run_signature_version: str | None,
    identity_valid: bool | None,
    identity_error_reason: str | None,
    artifact_set_hash: str | None,
    base_apk_sha256: str | None,
    sha256: str | None,
    config_hash: str | None,
    pipeline_version: str | None = None,
    analysis_version: str | None = None,
    catalog_versions: str | None = None,
    study_tag: str | None = None,
) -> None:
    try:
        run_sql_write(
            """
            UPDATE static_analysis_runs
            SET run_signature=%s,
                run_signature_version=%s,
                identity_valid=%s,
                identity_error_reason=%s,
                artifact_set_hash=%s,
                base_apk_sha256=%s,
                sha256=%s,
                config_hash=%s,
                pipeline_version=%s,
                analysis_version=%s,
                catalog_versions=%s,
                study_tag=%s
            WHERE id=%s
            """,
            (
                run_signature,
                run_signature_version,
                identity_valid,
                identity_error_reason,
                artifact_set_hash,
                base_apk_sha256,
                sha256,
                config_hash,
                pipeline_version,
                analysis_version,
                catalog_versions,
                study_tag,
                static_run_id,
            ),
        )
    except Exception as exc:
        log.warning(
            f"Failed to update static run metadata for {static_run_id}: {exc}",
            category="static_analysis",
        )


def _maybe_set_canonical_static_run(
    *,
    static_run_id: int,
    session_label: str,
    canonical_reason: str | None = None,
) -> None:
    now = _utc_now_dbstr()
    canonical_reason = canonical_reason or "replace"
    try:
        core_q.run_sql(
            """
            UPDATE static_analysis_runs
            SET is_canonical=0
            WHERE session_label=%s AND is_canonical=1 AND id<>%s
            """,
            (session_label, static_run_id),
        )
        core_q.run_sql(
            """
            UPDATE static_analysis_runs
            SET is_canonical=1, canonical_set_at_utc=%s, canonical_reason=%s
            WHERE id=%s
            """,
            (now, canonical_reason, static_run_id),
        )
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s AND is_canonical=1
            """,
            (session_label,),
            fetch="one",
        )
        canonical_count = int(row[0] or 0) if row else 0
        if canonical_count != 1:
            raise RuntimeError(
                "canonical enforcement failed "
                f"(session_label={session_label}, count={canonical_count})"
            )
    except Exception as exc:
        log.warning(
            f"Failed to set canonical static run {static_run_id}: {exc}",
            category="static_analysis",
        )
        raise


def update_static_run_status(
    *,
    static_run_id: int,
    status: str,
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    now = _utc_now_dbstr()
    ended_at = _normalize_datetime_value(ended_at_utc) or now
    try:
        run_sql_write(
            """
            UPDATE static_analysis_runs
            SET status=%s,
                ended_at_utc=%s,
                abort_reason=%s,
                abort_signal=%s
            WHERE id=%s
            """,
            (status, ended_at, abort_reason, abort_signal, static_run_id),
        )
    except Exception as exc:
        log.warning(
            f"Failed to update static run status for {static_run_id}: {exc}",
            category="static_analysis",
        )


def finalize_open_static_runs(
    static_run_ids: Sequence[int] | None = None,
    *,
    status: str = "ABORTED",
    ended_at_utc: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> int:
    now = _utc_now_dbstr()
    try:
        normalized_ended_at = _normalize_datetime_value(ended_at_utc) or now
        params = [status, normalized_ended_at, abort_reason, abort_signal]
        sql = """
            UPDATE static_analysis_runs
            SET status=%s, ended_at_utc=%s, abort_reason=%s, abort_signal=%s
            WHERE status='RUNNING' AND ended_at_utc IS NULL
        """
        if static_run_ids:
            placeholders = ",".join(["%s"] * len(static_run_ids))
            sql += f" AND id IN ({placeholders})"
            params.extend(static_run_ids)
        return safe_int(
            run_sql_write(
                sql,
                tuple(params),
                return_rowcount=True,
            ),
            default=0,
        )
    except Exception:
        return 0


def update_static_run_metadata(**kwargs: Any) -> None:
    _update_static_run_metadata(**kwargs)


def maybe_set_canonical_static_run(**kwargs: Any) -> None:
    _maybe_set_canonical_static_run(**kwargs)


def export_dep_snapshot(static_run_id: int | None) -> None:
    if not static_run_id:
        return
    dep_path = export_dep_json(static_run_id)
    if dep_path:
        log.info(
            f"DEP snapshot written for static_run_id={static_run_id}",
            category="static_analysis",
        )


__all__ = [
    "create_static_run_ledger",
    "update_static_run_status",
    "finalize_open_static_runs",
    "update_static_run_metadata",
    "maybe_set_canonical_static_run",
    "export_dep_snapshot",
]
