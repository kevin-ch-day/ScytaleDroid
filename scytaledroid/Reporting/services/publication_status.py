"""DB-first reporting status helpers."""

from __future__ import annotations

from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def fetch_latest_analysis_snapshot() -> dict[str, Any] | None:
    """Return the latest ingested analysis-cohort snapshot, if available.

    This is intentionally DB-first. Reporting/file exports remain important
    bundle artifacts, but the CLI should not need to rediscover basic derived
    cohort facts by scanning JSON/CSV when the DB already stores them.
    """

    row = core_q.run_sql(
        """
        SELECT
          ac.cohort_id,
          ac.name,
          ac.selector_type,
          ac.created_at_utc,
          adr.receipt_id,
          adr.status AS receipt_status,
          adr.finished_at_utc,
          (
            SELECT COUNT(*)
            FROM analysis_cohort_runs acr
            WHERE acr.cohort_id = ac.cohort_id
              AND acr.included = 1
          ) AS run_count,
          (
            SELECT COUNT(*)
            FROM analysis_cohort_runs acr
            WHERE acr.cohort_id = ac.cohort_id
              AND acr.included = 1
              AND acr.run_role = 'baseline'
          ) AS baseline_count,
          (
            SELECT COUNT(*)
            FROM analysis_cohort_runs acr
            WHERE acr.cohort_id = ac.cohort_id
              AND acr.included = 1
              AND acr.run_role = 'interactive'
          ) AS interactive_count,
          (
            SELECT COUNT(DISTINCT acr.package_name)
            FROM analysis_cohort_runs acr
            WHERE acr.cohort_id = ac.cohort_id
              AND acr.included = 1
          ) AS app_count,
          (
            SELECT COUNT(*)
            FROM analysis_static_exposure ase
            WHERE ase.cohort_id = ac.cohort_id
          ) AS static_count,
          (
            SELECT COUNT(*)
            FROM analysis_ml_app_phase_model_metrics amm
            WHERE amm.cohort_id = ac.cohort_id
          ) AS ml_metric_count,
          (
            SELECT COUNT(*)
            FROM analysis_risk_regime_summary arr
            WHERE arr.cohort_id = ac.cohort_id
          ) AS regime_count
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
        """,
        fetch="one_dict",
        query_name="reporting.fetch_latest_analysis_snapshot",
    )
    if not isinstance(row, dict) or not row:
        return None

    run_count = _as_int(row.get("run_count"))
    app_count = _as_int(row.get("app_count"))
    static_count = _as_int(row.get("static_count"))
    ml_metric_count = _as_int(row.get("ml_metric_count"))
    regime_count = _as_int(row.get("regime_count"))
    receipt_status = str(row.get("receipt_status") or "").strip().upper()
    ready = (
        receipt_status == "OK"
        and run_count > 0
        and app_count > 0
        and static_count > 0
        and ml_metric_count > 0
    )

    return {
        "cohort_id": str(row.get("cohort_id") or "").strip(),
        "name": str(row.get("name") or "").strip(),
        "selector_type": str(row.get("selector_type") or "").strip(),
        "receipt_id": _as_int(row.get("receipt_id")) if row.get("receipt_id") is not None else None,
        "receipt_status": receipt_status or "UNKNOWN",
        "finished_at_utc": row.get("finished_at_utc"),
        "run_count": run_count,
        "baseline_count": _as_int(row.get("baseline_count")),
        "interactive_count": _as_int(row.get("interactive_count")),
        "app_count": app_count,
        "static_count": static_count,
        "ml_metric_count": ml_metric_count,
        "regime_count": regime_count,
        "ready": ready,
        "summary_label": f"{run_count} runs / {app_count} apps" if run_count or app_count else "missing",
    }

