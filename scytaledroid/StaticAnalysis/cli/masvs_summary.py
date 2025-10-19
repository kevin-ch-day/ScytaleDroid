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
            " SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) AS high,"
            " SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) AS medium,"
            " SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low,"
            " SUM(CASE WHEN severity='Info' THEN 1 ELSE 0 END) AS info"
            " FROM findings WHERE run_id = %s GROUP BY masvs",
            (run_id,),
            fetch="all",
            dictionary=True,
        ) or []

        top_rows = core_q.run_sql(
            """
            SELECT masvs,
                   severity,
                   COALESCE(NULLIF(kind, ''), 'unknown') AS identifier,
                   COUNT(*) AS occurrences
            FROM findings
            WHERE run_id = %s
            GROUP BY masvs, severity, identifier
            ORDER BY
                CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                occurrences DESC
            """,
            (run_id,),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return None

    top_lookup: Dict[str, Dict[str, Dict[str, object]]] = {}
    for row in top_rows:
        area = (row.get("masvs") or "").upper()
        if not area:
            continue
        severity = str(row.get("severity") or "")
        identifier = row.get("identifier") or row.get("kind") or "unknown"
        descriptor = str(identifier)
        entry = top_lookup.setdefault(area, {})
        entry.setdefault(
            severity,
            {
                "descriptor": descriptor,
                "occurrences": int(row.get("occurrences") or 0),
            },
        )

    summary: List[Dict[str, object]] = []
    for row in rows:
        area = (row.get("masvs") or "").upper()
        if not area:
            continue
        high_count = int(row.get("high") or 0)
        medium_count = int(row.get("medium") or 0)
        summary.append(
            {
                "area": area,
                "high": high_count,
                "medium": medium_count,
                "sev_ge_med": high_count + medium_count,
                "low": int(row.get("low") or 0),
                "info": int(row.get("info") or 0),
                "worst": row.get("worst") or "—",
                "control_count": high_count + medium_count + int(row.get("low") or 0) + int(row.get("info") or 0),
                "top_high": top_lookup.get(area, {}).get("High"),
                "top_medium": top_lookup.get(area, {}).get("Medium"),
            }
        )

    if not summary:
        return None
    return run_id, summary


def fetch_masvs_matrix() -> Dict[str, Dict[str, object]]:
    """Return MASVS pass/fail matrix keyed by package using latest run per package."""

    try:
        latest_runs = core_q.run_sql(
            "SELECT package, MAX(run_id) AS run_id FROM runs GROUP BY package",
            fetch="all",
            dictionary=True,
        ) or []
        rows = core_q.run_sql(
            """
            SELECT pkg.package,
                   pkg.run_id,
                   f.masvs,
                   SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN f.severity = 'Low' THEN 1 ELSE 0 END) AS low,
                   SUM(CASE WHEN f.severity = 'Info' THEN 1 ELSE 0 END) AS info
            FROM (
                SELECT package, MAX(run_id) AS run_id
                FROM runs
                GROUP BY package
            ) AS pkg
            JOIN runs r ON r.package = pkg.package AND r.run_id = pkg.run_id
            LEFT JOIN findings f ON f.run_id = r.run_id
            GROUP BY pkg.package, pkg.run_id, f.masvs
            ORDER BY pkg.package
            """,
            fetch="all",
            dictionary=True,
        ) or []

        top_rows = core_q.run_sql(
            """
            SELECT pkg.package,
                   pkg.run_id,
                   f.masvs,
                   f.severity,
                   COALESCE(NULLIF(f.kind, ''), 'unknown') AS identifier,
                   COUNT(*) AS occurrences
            FROM (
                SELECT package, MAX(run_id) AS run_id
                FROM runs
                GROUP BY package
            ) AS pkg
            JOIN runs r ON r.package = pkg.package AND r.run_id = pkg.run_id
            LEFT JOIN findings f ON f.run_id = r.run_id
            WHERE f.masvs IS NOT NULL
            GROUP BY pkg.package, pkg.run_id, f.masvs, f.severity, identifier
            ORDER BY
                pkg.package,
                CASE f.severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                occurrences DESC
            """,
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return {}

    top_lookup: Dict[tuple[str, str], Dict[str, Dict[str, object]]] = {}
    for row in top_rows:
        package = row.get("package")
        area = (row.get("masvs") or "").upper()
        if not package or not area:
            continue
        severity = str(row.get("severity") or "")
        identifier = row.get("identifier") or row.get("kind") or "unknown"
        descriptor = str(identifier)
        key = (package, area)
        entry = top_lookup.setdefault(key, {})
        entry.setdefault(
            severity,
            {
                "descriptor": descriptor,
                "occurrences": int(row.get("occurrences") or 0),
            },
        )

    matrix: Dict[str, Dict[str, object]] = {}
    for row in rows:
        package = row.get("package")
        area = (row.get("masvs") or "").upper()
        if not package or not area:
            continue
        entry = matrix.setdefault(
            package,
            {
                "run_id": int(row.get("run_id") or 0),
                "status": {},
                "counts": {},
                "top": {},
            },
        )
        high = int(row.get("high") or 0)
        medium = int(row.get("medium") or 0)
        low = int(row.get("low") or 0)
        info = int(row.get("info") or 0)
        if high > 0:
            status = "FAIL"
        elif medium > 0:
            status = "WARN"
        else:
            status = "PASS"
        entry["status"][area] = status
        entry["counts"][area] = {
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }
        entry["top"][area] = {
            "high": top_lookup.get((package, area), {}).get("High"),
            "medium": top_lookup.get((package, area), {}).get("Medium"),
        }

    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    for package, data in matrix.items():
        statuses = data["status"]
        passed = 0
        for area in areas:
            if area not in statuses:
                statuses[area] = "PASS"
            if statuses[area] == "PASS":
                passed += 1
        data["pass_rate"] = int(round((passed / len(areas)) * 100))

    for entry in latest_runs:
        package = entry.get("package")
        if not package or package in matrix:
            continue
        matrix[package] = {
            "run_id": int(entry.get("run_id") or 0),
            "status": {area: "PASS" for area in areas},
            "counts": {area: {"high": 0, "medium": 0, "low": 0, "info": 0} for area in areas},
            "top": {area: {"high": None, "medium": None} for area in areas},
            "pass_rate": 100,
        }

    return matrix


__all__ = ["fetch_db_masvs_summary", "fetch_masvs_matrix"]
