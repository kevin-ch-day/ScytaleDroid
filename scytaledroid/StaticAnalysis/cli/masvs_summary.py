"""Helpers to fetch MASVS summaries from the database."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from scytaledroid.Database.db_core import db_queries as core_q


def fetch_db_masvs_summary(run_id: Optional[int] = None) -> Optional[Tuple[int, List[Dict[str, object]]]]:
    try:
        if run_id is None:
            row = core_q.run_sql("SELECT MAX(run_id) FROM runs", fetch="one")
            if not row or not row[0]:
                return None
            run_id = int(row[0])

        rows = core_q.run_sql(
            "SELECT masvs, MAX(cvss) AS worst, "
            " SUM(CASE WHEN severity IN ('High','Medium') THEN 1 ELSE 0 END) AS sev_ge_med,"
            " SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low,"
            " SUM(CASE WHEN severity='Info' THEN 1 ELSE 0 END) AS info"
            " FROM findings WHERE run_id = %s GROUP BY masvs",
            (run_id,),
            fetch="all",
        ) or []
    except Exception:
        return None

    summary: List[Dict[str, object]] = []
    for masvs, worst, sev_ge_med, low, info in rows:
        area = (masvs or "").upper()
        if not area:
            continue
        summary.append(
            {
                "area": area,
                "sev_ge_med": int(sev_ge_med or 0),
                "low": int(low or 0),
                "info": int(info or 0),
                "worst": worst or "—",
            }
        )

    if not summary:
        return None
    return run_id, summary


__all__ = ["fetch_db_masvs_summary"]

