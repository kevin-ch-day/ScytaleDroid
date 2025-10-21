"""Snapshot persistence helpers for permission audit rollups."""

from __future__ import annotations

from typing import Optional

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_func.permissions import permission_support
from scytaledroid.Utils.LoggingUtils import logging_utils as log

SNAPSHOT_PREFIX = "perm-audit:app:"

_SNAPSHOT_FIXES: tuple[str, ...] = (
    "ALTER TABLE permission_audit_snapshots ADD UNIQUE KEY ux_permission_audit_snapshots_key (snapshot_key)",
    "ALTER TABLE permission_audit_apps ADD UNIQUE KEY ux_permission_audit_apps_snapshot_pkg (snapshot_id, package_name)",
    "ALTER TABLE permission_audit_apps ADD INDEX ix_permission_audit_apps_score (snapshot_id, score_capped)",
)


def _ensure_snapshot_schema() -> None:
    try:
        permission_support.ensure_audit_snapshots()
        permission_support.ensure_audit_apps()
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            "Failed to ensure permission audit tables: %s", exc, category="static_analysis"
        )
    for statement in _SNAPSHOT_FIXES:
        try:
            core_q.run_sql(statement)
        except Exception:
            continue


def write_permission_snapshot(session_stamp: str, *, scope_label: Optional[str] = None) -> Optional[int]:
    """Upsert a permission snapshot for ``session_stamp`` and return the snapshot ID."""

    if not session_stamp:
        raise ValueError("session_stamp is required for snapshot persistence")

    _ensure_snapshot_schema()

    snapshot_key = SNAPSHOT_PREFIX + session_stamp
    scope_display = scope_label or f"Session {session_stamp}"
    metadata_scope = scope_label or scope_display

    header_sql = """
        INSERT INTO permission_audit_snapshots (snapshot_key, scope_label, apps_total, metadata)
        SELECT %s,
               %s,
               COUNT(DISTINCT package_name),
               JSON_OBJECT('session', %s, 'scope_label', %s, 'source', 'static-cli')
        FROM static_findings_summary
        WHERE session_stamp = %s
        ON DUPLICATE KEY UPDATE
          scope_label = VALUES(scope_label),
          apps_total = VALUES(apps_total),
          metadata = VALUES(metadata)
    """
    core_q.run_sql(
        header_sql,
        (snapshot_key, scope_display, session_stamp, metadata_scope, session_stamp),
    )

    row = core_q.run_sql(
        "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key=%s",
        (snapshot_key,),
        fetch="one",
    )
    if not row:
        log.warning(
            "Permission snapshot header was not created for session %s", session_stamp, category="static_analysis"
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

    apps_sql = f"""
        INSERT INTO permission_audit_apps (
          snapshot_id, package_name, app_label,
          score_raw, score_capped, grade,
          dangerous_count, signature_count, vendor_count,
          details
        )
        SELECT
          %s,
          sfs.package_name,
          MAX(r.app_label),
          COALESCE(MAX(spr.risk_score), MAX(rs.risk_score), {fallback}),
          COALESCE(LEAST(MAX(spr.risk_score), 100), LEAST(MAX(rs.risk_score), 100), {fallback}),
          COALESCE(MAX(spr.risk_grade), MAX(rs.risk_grade), {grade_case}),
          COALESCE(MAX(spr.dangerous), MAX(rs.dangerous), 0),
          COALESCE(MAX(spr.signature), MAX(rs.signature), 0),
          COALESCE(MAX(spr.vendor), MAX(rs.vendor), 0),
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
          details = VALUES(details)
    """

    core_q.run_sql(
        apps_sql,
        (
            snapshot_id,
            session_stamp,
            metadata_scope,
            session_stamp,
            session_stamp,
            session_stamp,
            session_stamp,
        ),
    )

    return snapshot_id


__all__ = ["SNAPSHOT_PREFIX", "write_permission_snapshot"]
