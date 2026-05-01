"""Dataset readiness helpers for operator-facing reporting views."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Reporting.services.publication_status import fetch_latest_analysis_snapshot


def _as_int(value: Any) -> int:
    try:
        if isinstance(value, Decimal):
            return int(value)
        return int(value or 0)
    except Exception:
        return 0


def classify_dataset_readiness(row: dict[str, Any]) -> str:
    """Return an operator-facing readiness label for one dataset app row."""

    installed = str(row.get("installed") or "N").upper()
    harvested = str(row.get("harvested") or "N").upper()
    static_ready = str(row.get("static_ready") or "N").upper()
    dyn_runs = _as_int(row.get("dyn_runs"))
    analysis_runs = _as_int(row.get("analysis_runs"))

    if installed != "Y":
        return "BLOCKED_NOT_INSTALLED"
    if harvested != "Y":
        return "NEEDS_HARVEST"
    if static_ready != "Y":
        return "NEEDS_STATIC"
    if analysis_runs > 0:
        return "DATASET_READY_ANALYSIS"
    if dyn_runs > 0:
        return "CAPTURED_NOT_IN_ANALYSIS"
    return "NEEDS_DYNAMIC"


def fetch_dataset_readiness_dashboard(
    profile_key: str = "RESEARCH_DATASET_ALPHA",
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Return latest analysis snapshot plus per-app readiness rows."""

    analysis_snapshot = fetch_latest_analysis_snapshot()
    rows = core_q.run_sql(
        """
        WITH latest_snap AS (
          SELECT snapshot_id
          FROM device_inventory_snapshots
          ORDER BY captured_at DESC
          LIMIT 1
        ),
        repo_latest AS (
          SELECT package_name,
                 MAX(CAST(version_code AS UNSIGNED)) AS repo_version,
                 MAX(harvested_at) AS harvested_at
          FROM android_apk_repository
          GROUP BY package_name
        ),
        static_latest AS (
          SELECT a.package_name, MAX(sar.id) AS static_run_id
          FROM static_analysis_runs sar
          JOIN app_versions av ON av.id = sar.app_version_id
          JOIN apps a ON a.id = av.app_id
          GROUP BY a.package_name
        ),
        dyn_counts AS (
          SELECT package_name,
                 COUNT(*) AS total_runs,
                 SUM(CASE WHEN grade = 'PAPER_GRADE' THEN 1 ELSE 0 END) AS canonical_runs,
                 MAX(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END) AS pcap_valid
          FROM dynamic_sessions
          GROUP BY package_name
        ),
        latest_analysis_cohort AS (
          SELECT ac.cohort_id
          FROM analysis_cohorts ac
          LEFT JOIN (
            SELECT r1.*
            FROM analysis_derivation_receipts r1
            INNER JOIN (
              SELECT cohort_id, MAX(receipt_id) AS max_receipt_id
              FROM analysis_derivation_receipts
              GROUP BY cohort_id
            ) latest
              ON latest.cohort_id = r1.cohort_id
             AND latest.max_receipt_id = r1.receipt_id
          ) adr
            ON adr.cohort_id = ac.cohort_id
          ORDER BY COALESCE(adr.finished_at_utc, ac.created_at_utc) DESC, ac.created_at_utc DESC
          LIMIT 1
        ),
        analysis_latest AS (
          SELECT acr.package_name,
                 SUM(CASE WHEN acr.included = 1 THEN 1 ELSE 0 END) AS analysis_runs,
                 SUM(CASE WHEN acr.included = 1 AND acr.run_role = 'baseline' THEN 1 ELSE 0 END) AS analysis_baseline_runs,
                 SUM(CASE WHEN acr.included = 1 AND acr.run_role = 'interactive' THEN 1 ELSE 0 END) AS analysis_interactive_runs
          FROM analysis_cohort_runs acr
          JOIN latest_analysis_cohort lac ON lac.cohort_id = acr.cohort_id
          GROUP BY acr.package_name
        )
        SELECT
          a.display_name,
          a.package_name,
          CASE WHEN i.package_name IS NULL THEN 'N' ELSE 'Y' END AS installed,
          i.version_code,
          CASE WHEN r.package_name IS NULL THEN 'N' ELSE 'Y' END AS harvested,
          r.repo_version,
          r.harvested_at,
          CASE WHEN s.static_run_id IS NULL THEN 'N' ELSE 'Y' END AS static_ready,
          COALESCE(d.total_runs, 0) AS dyn_runs,
          COALESCE(d.canonical_runs, 0) AS canonical_runs,
          CASE
            WHEN d.pcap_valid IS NULL THEN 'N/A'
            WHEN d.pcap_valid = 1 THEN 'Y'
            ELSE 'N'
          END AS pcap_valid,
          COALESCE(al.analysis_runs, 0) AS analysis_runs,
          COALESCE(al.analysis_baseline_runs, 0) AS analysis_baseline_runs,
          COALESCE(al.analysis_interactive_runs, 0) AS analysis_interactive_runs
        FROM apps a
        LEFT JOIN latest_snap ls ON 1=1
        LEFT JOIN device_inventory i
          ON LOWER(a.package_name) COLLATE utf8mb4_general_ci =
             LOWER(i.package_name) COLLATE utf8mb4_general_ci
         AND i.snapshot_id = ls.snapshot_id
        LEFT JOIN repo_latest r
          ON LOWER(r.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN static_latest s
          ON LOWER(s.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN dyn_counts d
          ON LOWER(d.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        LEFT JOIN analysis_latest al
          ON LOWER(al.package_name) COLLATE utf8mb4_general_ci =
             LOWER(a.package_name) COLLATE utf8mb4_general_ci
        WHERE a.profile_key = %s
        ORDER BY a.display_name
        """,
        (profile_key,),
        fetch="all_dict",
        query_name="reporting.fetch_dataset_readiness_dashboard",
    ) or []

    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        normalized = dict(row)
        normalized["dyn_runs"] = _as_int(row.get("dyn_runs"))
        normalized["canonical_runs"] = _as_int(row.get("canonical_runs"))
        normalized["analysis_runs"] = _as_int(row.get("analysis_runs"))
        normalized["analysis_baseline_runs"] = _as_int(row.get("analysis_baseline_runs"))
        normalized["analysis_interactive_runs"] = _as_int(row.get("analysis_interactive_runs"))
        normalized["status"] = classify_dataset_readiness(normalized)
        normalized_rows.append(normalized)

    return analysis_snapshot, normalized_rows
