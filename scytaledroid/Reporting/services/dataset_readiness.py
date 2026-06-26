"""Dataset readiness helpers for operator-facing reporting views."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_func.research_cohorts import (
    ALPHA_COHORT_KEY,
    resolve_research_cohort_context,
    resolve_research_cohort_packages,
)
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
    valid_runs = _as_int(row.get("valid_runs"))
    quota_valid_runs = _as_int(row.get("quota_valid_runs"))
    invalid_runs = _as_int(row.get("invalid_runs"))
    legacy_unknown_runs = _as_int(row.get("legacy_unknown_runs"))
    analysis_runs = _as_int(row.get("analysis_runs"))

    if installed != "Y":
        return "BLOCKED_NOT_INSTALLED"
    if harvested != "Y":
        return "NEEDS_HARVEST"
    if static_ready != "Y":
        return "NEEDS_STATIC"
    if analysis_runs > 0:
        return "DATASET_READY_ANALYSIS"
    if quota_valid_runs > 0 or valid_runs > 0:
        return "CAPTURED_VALID_NOT_IN_ANALYSIS"
    if invalid_runs > 0 and legacy_unknown_runs > 0:
        return "INVALID_AND_LEGACY_ONLY"
    if invalid_runs > 0:
        return "INVALID_EVIDENCE_ONLY"
    if legacy_unknown_runs > 0:
        return "LEGACY_EVIDENCE_ONLY"
    if dyn_runs > 0:
        return "CAPTURED_UNQUALIFIED_ONLY"
    return "NEEDS_DYNAMIC"


def _resolve_target_packages(*, cohort_key: str | None, profile_key: str) -> list[str]:
    return resolve_research_cohort_packages(
        cohort_key,
        fallback_profile_key=profile_key,
    )


def fetch_dataset_readiness_dashboard(
    profile_key: str | None = "RESEARCH_DATASET_ALPHA",
    *,
    cohort_key: str | None = ALPHA_COHORT_KEY,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Return latest analysis snapshot plus per-app readiness rows."""

    if not profile_key and not cohort_key:
        cohort_ctx = resolve_research_cohort_context()
        profile_key = str(cohort_ctx.get("profile_key") or "") or None
        cohort_key = str(cohort_ctx.get("cohort_key") or "") or None
    analysis_snapshot = fetch_latest_analysis_snapshot()
    packages = _resolve_target_packages(cohort_key=cohort_key, profile_key=profile_key)
    if packages:
        placeholders = ", ".join(["%s"] * len(packages))
        sql = f"""
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
                 SUM(CASE WHEN technical_validity_state = 'TECH_VALID' THEN 1 ELSE 0 END) AS valid_runs,
                 SUM(CASE WHEN quota_state = 'QUOTA_VALID' THEN 1 ELSE 0 END) AS quota_valid_runs,
                 SUM(CASE WHEN quota_state = 'SUPPLEMENTAL_VALID' THEN 1 ELSE 0 END) AS supplemental_valid_runs,
                 SUM(CASE WHEN technical_validity_state = 'TECH_INVALID' THEN 1 ELSE 0 END) AS invalid_runs,
                 SUM(CASE WHEN technical_validity_state = 'TECH_LEGACY_UNKNOWN' THEN 1 ELSE 0 END) AS legacy_unknown_runs,
                 MAX(
                   CASE
                     WHEN technical_validity_state = 'TECH_VALID' AND pcap_valid = 1 THEN 1
                     ELSE 0
                   END
                 ) AS valid_run_has_pcap
          FROM v_dynamic_run_context_v1
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
          COALESCE(d.valid_runs, 0) AS valid_runs,
          COALESCE(d.quota_valid_runs, 0) AS quota_valid_runs,
          COALESCE(d.supplemental_valid_runs, 0) AS supplemental_valid_runs,
          COALESCE(d.invalid_runs, 0) AS invalid_runs,
          COALESCE(d.legacy_unknown_runs, 0) AS legacy_unknown_runs,
          CASE
            WHEN COALESCE(d.valid_runs, 0) = 0 THEN 'N/A'
            WHEN d.valid_run_has_pcap = 1 THEN 'Y'
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
        WHERE LOWER(a.package_name) COLLATE utf8mb4_general_ci IN ({placeholders})
        ORDER BY a.display_name
        """
        params: tuple[object, ...] = tuple(packages)
    else:
        sql = """
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
                 SUM(CASE WHEN technical_validity_state = 'TECH_VALID' THEN 1 ELSE 0 END) AS valid_runs,
                 SUM(CASE WHEN quota_state = 'QUOTA_VALID' THEN 1 ELSE 0 END) AS quota_valid_runs,
                 SUM(CASE WHEN quota_state = 'SUPPLEMENTAL_VALID' THEN 1 ELSE 0 END) AS supplemental_valid_runs,
                 SUM(CASE WHEN technical_validity_state = 'TECH_INVALID' THEN 1 ELSE 0 END) AS invalid_runs,
                 SUM(CASE WHEN technical_validity_state = 'TECH_LEGACY_UNKNOWN' THEN 1 ELSE 0 END) AS legacy_unknown_runs,
                 MAX(
                   CASE
                     WHEN technical_validity_state = 'TECH_VALID' AND pcap_valid = 1 THEN 1
                     ELSE 0
                   END
                 ) AS valid_run_has_pcap
          FROM v_dynamic_run_context_v1
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
          COALESCE(d.valid_runs, 0) AS valid_runs,
          COALESCE(d.quota_valid_runs, 0) AS quota_valid_runs,
          COALESCE(d.supplemental_valid_runs, 0) AS supplemental_valid_runs,
          COALESCE(d.invalid_runs, 0) AS invalid_runs,
          COALESCE(d.legacy_unknown_runs, 0) AS legacy_unknown_runs,
          CASE
            WHEN COALESCE(d.valid_runs, 0) = 0 THEN 'N/A'
            WHEN d.valid_run_has_pcap = 1 THEN 'Y'
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
        """
        params = (profile_key,)

    rows = core_q.run_sql(
        sql,
        params,
        fetch="all_dict",
        query_name="reporting.fetch_dataset_readiness_dashboard",
    ) or []

    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        normalized = dict(row)
        normalized["dyn_runs"] = _as_int(row.get("dyn_runs"))
        normalized["valid_runs"] = _as_int(row.get("valid_runs"))
        normalized["quota_valid_runs"] = _as_int(row.get("quota_valid_runs"))
        # Compatibility alias for older reporting callers; quota_valid_runs is authoritative.
        normalized["canonical_runs"] = normalized["quota_valid_runs"]
        normalized["supplemental_valid_runs"] = _as_int(row.get("supplemental_valid_runs"))
        normalized["invalid_runs"] = _as_int(row.get("invalid_runs"))
        normalized["legacy_unknown_runs"] = _as_int(row.get("legacy_unknown_runs"))
        normalized["analysis_runs"] = _as_int(row.get("analysis_runs"))
        normalized["analysis_baseline_runs"] = _as_int(row.get("analysis_baseline_runs"))
        normalized["analysis_interactive_runs"] = _as_int(row.get("analysis_interactive_runs"))
        normalized["status"] = classify_dataset_readiness(normalized)
        normalized_rows.append(normalized)

    return analysis_snapshot, normalized_rows
