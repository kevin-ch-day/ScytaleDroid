"""Typed linkage migration helpers for ``artifact_registry``.

This module is intentionally non-destructive: it audits and backfills typed
linkage columns but never deletes rows or host files.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


def _scalar(
    run_sql: Callable[..., Any],
    sql: str,
    params: Sequence[Any] = (),
    *,
    query_name: str,
) -> int:
    row = run_sql(sql, tuple(params), fetch="one", dictionary=True, query_name=query_name)
    if isinstance(row, dict):
        return int(next(iter(row.values())) or 0)
    if row and row[0] is not None:
        return int(row[0])
    return 0


def _rows(
    run_sql: Callable[..., Any],
    sql: str,
    params: Sequence[Any] = (),
    *,
    query_name: str,
) -> list[dict[str, Any]]:
    rows = run_sql(sql, tuple(params), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _legacy_integrity_totals_sql() -> str:
    return """
        SELECT
          ar.run_type,
          CASE
            WHEN ar.run_type = 'dynamic' AND ds.dynamic_run_id IS NOT NULL THEN 'linked'
            WHEN ar.run_type = 'dynamic' THEN 'dangling_dynamic_run'
            WHEN ar.run_type = 'static' AND ar.run_id REGEXP '^[0-9]+$' AND sar.id IS NOT NULL THEN 'linked'
            WHEN ar.run_type = 'static' THEN 'dangling_static_run'
            ELSE 'unknown_run_type'
          END AS link_state,
          COUNT(*) AS row_count
        FROM artifact_registry ar
        LEFT JOIN dynamic_sessions ds
          ON ar.run_type = 'dynamic'
         AND ds.dynamic_run_id = ar.run_id
        LEFT JOIN static_analysis_runs sar
          ON ar.run_type = 'static'
         AND ar.run_id REGEXP '^[0-9]+$'
         AND sar.id = CAST(ar.run_id AS UNSIGNED)
        GROUP BY ar.run_type, link_state
        ORDER BY ar.run_type, link_state
    """


def _typed_preferred_integrity_totals_sql() -> str:
    return """
        SELECT
          ar.run_type,
          CASE
            WHEN ar.run_type = 'dynamic'
             AND (ds_typed.dynamic_run_id IS NOT NULL OR ds_legacy.dynamic_run_id IS NOT NULL)
              THEN 'linked'
            WHEN ar.run_type = 'dynamic' THEN 'dangling_dynamic_run'
            WHEN ar.run_type = 'static'
             AND (sar_typed.id IS NOT NULL OR sar_legacy.id IS NOT NULL)
              THEN 'linked'
            WHEN ar.run_type = 'static' THEN 'dangling_static_run'
            ELSE 'unknown_run_type'
          END AS link_state,
          COUNT(*) AS row_count
        FROM artifact_registry ar
        LEFT JOIN dynamic_sessions ds_typed
          ON ar.run_type = 'dynamic'
         AND ar.dynamic_run_id IS NOT NULL
         AND ds_typed.dynamic_run_id = ar.dynamic_run_id
        LEFT JOIN dynamic_sessions ds_legacy
          ON ar.run_type = 'dynamic'
         AND ar.dynamic_run_id IS NULL
         AND TRIM(COALESCE(ar.run_id, '')) <> ''
         AND ds_legacy.dynamic_run_id = ar.run_id
        LEFT JOIN static_analysis_runs sar_typed
          ON ar.run_type = 'static'
         AND ar.static_run_id IS NOT NULL
         AND sar_typed.id = ar.static_run_id
        LEFT JOIN static_analysis_runs sar_legacy
          ON ar.run_type = 'static'
         AND ar.static_run_id IS NULL
         AND ar.run_id REGEXP '^[0-9]+$'
         AND sar_legacy.id = CAST(ar.run_id AS UNSIGNED)
        GROUP BY ar.run_type, link_state
        ORDER BY ar.run_type, link_state
    """


def collect_artifact_registry_typed_linkage_audit(
    run_sql: Callable[..., Any],
) -> dict[str, Any]:
    rows_by_run_type = _rows(
        run_sql,
        """
        SELECT run_type, COUNT(*) AS row_count
        FROM artifact_registry
        GROUP BY run_type
        ORDER BY run_type
        """,
        query_name="artifact_registry_typed_linkage.audit.rows_by_run_type",
    )
    legacy_counts = _rows(
        run_sql,
        _legacy_integrity_totals_sql(),
        query_name="artifact_registry_typed_linkage.audit.legacy_counts",
    )
    typed_counts = _rows(
        run_sql,
        _typed_preferred_integrity_totals_sql(),
        query_name="artifact_registry_typed_linkage.audit.typed_counts",
    )
    return {
        "total_artifact_registry_rows": _scalar(
            run_sql,
            "SELECT COUNT(*) AS c FROM artifact_registry",
            query_name="artifact_registry_typed_linkage.audit.total_rows",
        ),
        "rows_by_run_type": rows_by_run_type,
        "migrated_static_rows": _scalar(
            run_sql,
            """
            SELECT COUNT(*) AS c
            FROM artifact_registry
            WHERE run_type = 'static'
              AND static_run_id IS NOT NULL
            """,
            query_name="artifact_registry_typed_linkage.audit.migrated_static",
        ),
        "migrated_dynamic_rows": _scalar(
            run_sql,
            """
            SELECT COUNT(*) AS c
            FROM artifact_registry
            WHERE run_type = 'dynamic'
              AND dynamic_run_id IS NOT NULL
              AND TRIM(dynamic_run_id) <> ''
            """,
            query_name="artifact_registry_typed_linkage.audit.migrated_dynamic",
        ),
        "malformed_static_run_id_rows": _scalar(
            run_sql,
            """
            SELECT COUNT(*) AS c
            FROM artifact_registry
            WHERE run_type = 'static'
              AND static_run_id IS NULL
              AND NOT run_id REGEXP '^[0-9]+$'
            """,
            query_name="artifact_registry_typed_linkage.audit.malformed_static",
        ),
        "dangling_static_run_id_rows": _scalar(
            run_sql,
            """
            SELECT COUNT(*) AS c
            FROM artifact_registry ar
            LEFT JOIN static_analysis_runs sar
              ON sar.id = ar.static_run_id
            WHERE ar.run_type = 'static'
              AND ar.static_run_id IS NOT NULL
              AND sar.id IS NULL
            """,
            query_name="artifact_registry_typed_linkage.audit.dangling_static_typed",
        ),
        "dangling_dynamic_run_id_rows": _scalar(
            run_sql,
            """
            SELECT COUNT(*) AS c
            FROM artifact_registry ar
            LEFT JOIN dynamic_sessions ds
              ON ds.dynamic_run_id = ar.dynamic_run_id
            WHERE ar.run_type = 'dynamic'
              AND ar.dynamic_run_id IS NOT NULL
              AND TRIM(ar.dynamic_run_id) <> ''
              AND ds.dynamic_run_id IS NULL
            """,
            query_name="artifact_registry_typed_linkage.audit.dangling_dynamic_typed",
        ),
        "fallback_needed_rows": _scalar(
            run_sql,
            """
            SELECT COUNT(*) AS c
            FROM artifact_registry
            WHERE (run_type = 'static' AND static_run_id IS NULL AND run_id REGEXP '^[0-9]+$')
               OR (run_type = 'dynamic' AND (dynamic_run_id IS NULL OR TRIM(dynamic_run_id) = '') AND TRIM(COALESCE(run_id, '')) <> '')
            """,
            query_name="artifact_registry_typed_linkage.audit.fallback_needed",
        ),
        "legacy_integrity_counts": legacy_counts,
        "typed_preferred_integrity_counts": typed_counts,
    }


@dataclass(frozen=True)
class TypedLinkageBackfillResult:
    applied: bool
    static_rows_updated: int
    dynamic_rows_updated: int


def backfill_artifact_registry_typed_linkage(
    run_sql_rowcount: Callable[..., int],
    *,
    apply: bool,
) -> TypedLinkageBackfillResult:
    """Backfill typed linkage columns without touching legacy ``run_id``."""

    if not apply:
        return TypedLinkageBackfillResult(
            applied=False,
            static_rows_updated=0,
            dynamic_rows_updated=0,
        )

    static_rows_updated = int(
        run_sql_rowcount(
            """
            UPDATE artifact_registry
            SET static_run_id = CAST(run_id AS UNSIGNED),
                linkage_migration_status = 'typed_static_backfilled'
            WHERE run_type = 'static'
              AND run_id REGEXP '^[0-9]+$'
              AND static_run_id IS NULL
            """,
            (),
            query_name="artifact_registry_typed_linkage.backfill_static",
        )
    )
    dynamic_rows_updated = int(
        run_sql_rowcount(
            """
            UPDATE artifact_registry
            SET dynamic_run_id = run_id,
                linkage_migration_status = 'typed_dynamic_backfilled'
            WHERE run_type = 'dynamic'
              AND TRIM(COALESCE(run_id, '')) <> ''
              AND (dynamic_run_id IS NULL OR TRIM(dynamic_run_id) = '')
            """,
            (),
            query_name="artifact_registry_typed_linkage.backfill_dynamic",
        )
    )
    return TypedLinkageBackfillResult(
        applied=True,
        static_rows_updated=static_rows_updated,
        dynamic_rows_updated=dynamic_rows_updated,
    )


__all__ = [
    "TypedLinkageBackfillResult",
    "backfill_artifact_registry_typed_linkage",
    "collect_artifact_registry_typed_linkage_audit",
]
