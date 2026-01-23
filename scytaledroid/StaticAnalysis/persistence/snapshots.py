"""Snapshot persistence helpers for permission audit rollups."""

from __future__ import annotations

from typing import Optional

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_func.permissions import permission_support
from scytaledroid.Utils.LoggingUtils import logging_utils as log

SNAPSHOT_PREFIX = "perm-audit:app:"

_INDEX_DEFINITIONS: tuple[tuple[str, str, str], ...] = (
    (
        "permission_audit_snapshots",
        "ux_permission_audit_snapshots_key",
        "ALTER TABLE permission_audit_snapshots "
        "ADD UNIQUE KEY ux_permission_audit_snapshots_key (snapshot_key)",
    ),
    (
        "permission_audit_apps",
        "ux_permission_audit_apps_snapshot_pkg",
        "ALTER TABLE permission_audit_apps "
        "ADD UNIQUE KEY ux_permission_audit_apps_snapshot_pkg (snapshot_id, package_name)",
    ),
    (
        "permission_audit_apps",
        "ix_permission_audit_apps_score",
        "ALTER TABLE permission_audit_apps "
        "ADD INDEX ix_permission_audit_apps_score (snapshot_id, score_capped)",
    ),
)


def _ensure_index(table: str, index: str, statement: str) -> None:
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND index_name = %s
            """,
            (table, index),
            fetch="one",
        )
        exists = bool(row and int(row[0]) > 0)
    except Exception:
        exists = False
    if exists:
        return
    try:
        core_q.run_sql(statement)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug(
            "Failed to create index %s on %s: %s",
            index,
            table,
            exc,
            category="static_analysis",
        )


def _ensure_snapshot_schema() -> None:
    try:
        permission_support.ensure_audit_snapshots()
        permission_support.ensure_audit_apps()
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to ensure permission audit tables: {exc}",
            category="static_analysis",
        )
    for table, index, statement in _INDEX_DEFINITIONS:
        _ensure_index(table, index, statement)


def write_permission_snapshot(
    session_stamp: str,
    *,
    scope_label: Optional[str] = None,
    static_run_id: Optional[int] = None,
) -> Optional[int]:
    """Upsert a permission snapshot for ``session_stamp`` and return the snapshot ID."""

    if not session_stamp:
        raise ValueError("session_stamp is required for snapshot persistence")

    _ensure_snapshot_schema()

    if static_run_id is None:
        try:
            row = core_q.run_sql(
                "SELECT id FROM static_analysis_runs WHERE session_stamp=%s ORDER BY id DESC LIMIT 1",
                (session_stamp,),
                fetch="one",
            )
            if row and row[0]:
                static_run_id = int(row[0])
        except Exception:
            static_run_id = None
    else:
        try:
            static_run_id = int(static_run_id)
        except Exception:
            static_run_id = None

    run_id: Optional[int] = None
    derived_package: Optional[str] = None
    if scope_label:
        scope_label = scope_label.strip()
        if scope_label.startswith("com."):
            derived_package = scope_label
        elif "(com." in scope_label:
            derived_package = scope_label.rsplit("(", 1)[-1].rstrip(")")
            if not derived_package.startswith("com."):
                derived_package = None
    if derived_package:
        try:
            row = core_q.run_sql(
                """
                SELECT run_id
                FROM runs
                WHERE session_stamp=%s AND package=%s
                ORDER BY run_id DESC
                LIMIT 1
                """,
                (session_stamp, derived_package),
                fetch="one",
            )
            if row and row[0]:
                run_id = int(row[0])
        except Exception:
            run_id = None

    snapshot_key = SNAPSHOT_PREFIX + session_stamp
    scope_display = scope_label or f"Session {session_stamp}"
    metadata_scope = scope_label or scope_display
    metadata_package = derived_package

    header_sql = """
        INSERT INTO permission_audit_snapshots (
          snapshot_key, scope_label, run_id, apps_total, metadata, static_run_id
        )
        SELECT %s,
               %s,
               %s,
               COUNT(DISTINCT package_name),
               JSON_OBJECT(
                 'session', %s,
                 'scope_label', %s,
                 'package', %s,
                 'source', 'static-cli'
               ),
               %s
        FROM static_findings_summary
        WHERE session_stamp = %s
        ON DUPLICATE KEY UPDATE
          scope_label = VALUES(scope_label),
          run_id = VALUES(run_id),
          apps_total = VALUES(apps_total),
          metadata = VALUES(metadata),
          static_run_id = VALUES(static_run_id)
    """
    try:
        core_q.run_sql(
            header_sql,
            (
                snapshot_key,
                scope_display,
                run_id,
                session_stamp,
                metadata_scope,
                metadata_package,
                static_run_id,
                session_stamp,
            ),
        )
    except Exception:
        log.exception(
            "Permission snapshot header skipped (session=%s)",
            session_stamp,
            category="static_analysis",
        )
        return None

    row = core_q.run_sql(
        "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key=%s",
        (snapshot_key,),
        fetch="one",
    )
    if not row:
        fallback_sql = """
            INSERT INTO permission_audit_snapshots (
              snapshot_key, scope_label, run_id, apps_total, metadata, static_run_id
            )
            VALUES (
              %s,
              %s,
              %s,
              0,
              JSON_OBJECT(
                'session', %s,
                'scope_label', %s,
                'package', %s,
                'source', 'static-cli',
                'note', 'header_fallback'
              ),
              %s
            )
            ON DUPLICATE KEY UPDATE
              scope_label = VALUES(scope_label),
              run_id = VALUES(run_id),
              apps_total = VALUES(apps_total),
              metadata = VALUES(metadata),
              static_run_id = VALUES(static_run_id)
        """
        try:
            core_q.run_sql(
                fallback_sql,
                (
                    snapshot_key,
                    scope_display,
                    run_id,
                    session_stamp,
                    metadata_scope,
                    metadata_package,
                    static_run_id,
                ),
            )
        except Exception:
            log.exception(
                "Permission snapshot header fallback failed (session=%s)",
                session_stamp,
                category="static_analysis",
            )
            return None
        row = core_q.run_sql(
            "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key=%s",
            (snapshot_key,),
            fetch="one",
        )
        if not row:
            log.warning(
                "Permission snapshot header was not created for session %s",
                session_stamp,
                category="static_analysis",
            )
            return None

    snapshot_id = int(row[0])

    fallback = "LEAST(50*MAX(sfs.high) + 12*MAX(sfs.med) + 3*MAX(sfs.low), 100)"
    grade_case = (
        "CASE "
        "WHEN {fallback} >= 90 THEN 'F' "
        "WHEN {fallback} >= 70 THEN 'D' "
        "WHEN {fallback} >= 50 THEN 'C' "
        "WHEN {fallback} >= 30 THEN 'B' "
        "ELSE 'A' END"
    ).format(fallback=fallback)

    # NOTE: Column order matters; align explicitly with permission_audit_apps schema.
    # Schema (in order): audit_id (PK), snapshot_id, static_run_id, package_name,
    # app_label, run_id, score_raw, score_capped, grade, dangerous_count,
    # signature_count, vendor_count, combos_total, surprises_total, legacy_total,
    # vendor_modifier, modernization_credit, details, created_at.
    apps_sql = f"""
        INSERT INTO permission_audit_apps (
          snapshot_id, static_run_id, package_name, app_label, run_id,
          score_raw, score_capped, grade,
          dangerous_count, signature_count, vendor_count,
          combos_total, surprises_total, legacy_total,
          vendor_modifier, modernization_credit,
          details
        )
        SELECT
          %s,
          %s,
          sfs.package_name,
          MAX(r.app_label),
          MAX(r.run_id),
          COALESCE(MAX(spr.risk_score), MAX(rs.risk_score), {fallback}),
          COALESCE(LEAST(MAX(spr.risk_score), 100), LEAST(MAX(rs.risk_score), 100), {fallback}),
          COALESCE(MAX(spr.risk_grade), MAX(rs.risk_grade), {grade_case}),
          COALESCE(MAX(spr.dangerous), MAX(rs.dangerous), 0),
          COALESCE(MAX(spr.signature), MAX(rs.signature), 0),
          COALESCE(MAX(spr.vendor), MAX(rs.vendor), 0),
          0,  -- combo totals (column absent in static_permission_risk on schema 0.2.x)
          0,  -- surprise totals (column absent in static_permission_risk on schema 0.2.x)
          0,  -- legacy totals (column absent in static_permission_risk on schema 0.2.x)
          0,  -- vendor modifier (column absent in static_permission_risk on schema 0.2.x)
          0,  -- modernization credit (column absent in static_permission_risk on schema 0.2.x)
          JSON_OBJECT(
            'session', %s,
            'scope_label', %s,
            'high', MAX(sfs.high),
            'medium', MAX(sfs.med),
            'low', MAX(sfs.low),
            'info', MAX(sfs.info)
          )
        FROM static_findings_summary sfs
        LEFT JOIN runs r
          ON r.session_stamp = %s AND r.package = sfs.package_name
        LEFT JOIN static_permission_risk spr
          ON spr.session_stamp = %s AND spr.scope_label = sfs.scope_label
          AND spr.package_name = sfs.package_name
        LEFT JOIN risk_scores rs
          ON rs.session_stamp = %s AND rs.scope_label = sfs.scope_label
          AND rs.package_name = sfs.package_name
        WHERE sfs.session_stamp = %s
        GROUP BY sfs.package_name
        ON DUPLICATE KEY UPDATE
          score_raw = VALUES(score_raw),
          score_capped = VALUES(score_capped),
          grade = VALUES(grade),
          dangerous_count = VALUES(dangerous_count),
          signature_count = VALUES(signature_count),
          vendor_count = VALUES(vendor_count),
          combos_total = VALUES(combos_total),
          surprises_total = VALUES(surprises_total),
          legacy_total = VALUES(legacy_total),
          vendor_modifier = VALUES(vendor_modifier),
          modernization_credit = VALUES(modernization_credit),
          details = VALUES(details)
    """

    try:
        core_q.run_sql(
            apps_sql,
            (
                snapshot_id,
                static_run_id,
                session_stamp,
                metadata_scope,
                session_stamp,
                session_stamp,
                session_stamp,
                session_stamp,
            ),
        )
    except Exception as exc:
        log.error(
            f"Failed to persist permission audit apps "
            f"(snapshot_id={snapshot_id} static_run_id={static_run_id} session={session_stamp}): {exc}",
            category="static_analysis",
        )
        # Do not abort the entire snapshot on optional/legacy schema issues.
        return snapshot_id

    return snapshot_id


__all__ = ["SNAPSHOT_PREFIX", "write_permission_snapshot"]
