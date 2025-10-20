"""Helpers to fetch MASVS summaries from the database."""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

from scytaledroid.StaticAnalysis.analytics.masvs_quality import (
    compute_quality_metrics,
)

from scytaledroid.Database.db_core import db_queries as core_q

from .cvss_v4 import parse_vector, score_vector, severity_band

_AREA_ORDER = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")


def _empty_area(area: str) -> Dict[str, object]:
    return {
        "area": area,
        "high": 0,
        "medium": 0,
        "sev_ge_med": 0,
        "low": 0,
        "info": 0,
        "control_count": 0,
        "cvss": {
            "worst_score": None,
            "worst_vector": None,
            "worst_identifier": None,
            "worst_severity": None,
            "worst_basis": None,
            "band_counts": Counter(),
            "average_score": None,
            "scored_count": 0,
            "missing": 0,
            "_score_sum": 0.0,
            "_score_count": 0,
            "_worst_cmp": None,
        },
        "top_high": None,
        "top_medium": None,
    }


def _finalise_cvss(entry: Mapping[str, object]) -> Dict[str, object]:
    cvss = dict(entry)
    score_sum = float(cvss.pop("_score_sum", 0.0))
    score_count = int(cvss.pop("_score_count", 0))
    if score_count:
        cvss["average_score"] = round(score_sum / score_count, 2)
    else:
        cvss["average_score"] = None
    cvss["scored_count"] = score_count
    cvss["total"] = score_count + int(cvss.get("missing", 0))
    band_counts = cvss.get("band_counts")
    distribution: Dict[str, float] = {}
    if isinstance(band_counts, Counter):
        band_counts = dict(band_counts)
    if isinstance(band_counts, Mapping):
        total_counts = sum(int(v) for v in band_counts.values())
        if total_counts:
            distribution = {
                band: round(int(count) / total_counts, 4)
                for band, count in band_counts.items()
            }
        cvss["band_counts"] = {band: int(count) for band, count in band_counts.items()}
    else:
        cvss["band_counts"] = {}
    if distribution:
        cvss["band_distribution"] = distribution
    cvss.pop("_worst_cmp", None)
    return cvss


def _cvss_band_rank(band: Optional[str]) -> int:
    band_order = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "None": 1,
        "Unknown": 0,
    }
    return band_order.get(band or "", 0)


def _cvss_scope_rank(vector: Optional[str]) -> int:
    if not vector:
        return 0
    metrics = parse_vector(vector)
    if not metrics:
        return 0
    rank_map = {"H": 2, "L": 1}
    values = [rank_map.get(metrics.get(key, ""), 0) for key in ("SC", "SI", "SA")]
    return max(values) if values else 0


def _cvss_impact_tuple(vector: Optional[str]) -> tuple[int, int]:
    if not vector:
        return (0, 0)
    metrics = parse_vector(vector)
    if not metrics:
        return (0, 0)
    high = sum(1 for key in ("VC", "VI", "VA") if metrics.get(key) == "H")
    medium = sum(1 for key in ("VC", "VI", "VA") if metrics.get(key) == "L")
    return high, medium


def _cvss_candidate_key(
    score: float,
    band: Optional[str],
    scope_rank: int,
    impact: tuple[int, int],
    vector: Optional[str],
    identifier: Optional[str],
) -> tuple:
    impact_high, impact_medium = impact
    return (
        round(float(score), 4),
        _cvss_band_rank(band),
        scope_rank,
        impact_high,
        impact_medium,
        len(vector or ""),
        vector or "",
        identifier or "",
    )


def _merge_counts(entry: Dict[str, object], row: Mapping[str, object]) -> None:
    high = int(row.get("high") or 0)
    medium = int(row.get("medium") or 0)
    low = int(row.get("low") or 0)
    info = int(row.get("info") or 0)
    entry["high"] = high
    entry["medium"] = medium
    entry["low"] = low
    entry["info"] = info
    entry["sev_ge_med"] = high + medium
    entry["control_count"] = high + medium + low + info


def _merge_top(top_lookup: Mapping[str, Mapping[str, object]], area: str, entry: Dict[str, object]) -> None:
    top = top_lookup.get(area, {})
    entry["top_high"] = top.get("High") if isinstance(top, Mapping) else None
    entry["top_medium"] = top.get("Medium") if isinstance(top, Mapping) else None


def _integrate_cvss(cvss_rows: Iterable[Mapping[str, object]], summary: Dict[str, Dict[str, object]]) -> None:
    for row in cvss_rows:
        area = (row.get("masvs") or "").upper()
        if not area:
            continue
        entry = summary.setdefault(area, _empty_area(area))
        cvss_meta = entry.setdefault("cvss", _empty_area(area)["cvss"])
        if not isinstance(cvss_meta.get("band_counts"), Counter):
            cvss_meta["band_counts"] = Counter(cvss_meta.get("band_counts") or {})

        vector = row.get("cvss")
        identifier = row.get("identifier") or row.get("kind") or "unknown"
        score = score_vector(vector)

        if score is None:
            cvss_meta["missing"] = int(cvss_meta.get("missing", 0)) + 1
        else:
            cvss_meta["_score_sum"] += float(score)
            cvss_meta["_score_count"] += 1
            band = severity_band(score) or "Unknown"
            cvss_meta["band_counts"][band] += 1
            scope_rank = _cvss_scope_rank(vector)
            impact = _cvss_impact_tuple(vector)
            candidate = _cvss_candidate_key(
                float(score),
                band,
                scope_rank,
                impact,
                vector,
                identifier,
            )
            worst_cmp = cvss_meta.get("_worst_cmp")
            if not isinstance(worst_cmp, tuple) or candidate > worst_cmp:
                cvss_meta["_worst_cmp"] = candidate
                cvss_meta["worst_score"] = float(score)
                cvss_meta["worst_vector"] = vector
                cvss_meta["worst_identifier"] = identifier
                cvss_meta["worst_severity"] = band
                cvss_meta["worst_basis"] = {
                    "score": float(score),
                    "band": band,
                    "scope_rank": scope_rank,
                    "impact_high": impact[0],
                    "impact_medium": impact[1],
                    "vector_length": len(vector or ""),
                    "vector": vector,
                    "identifier": identifier,
                }

        entry["cvss"] = cvss_meta


def _build_summary(
    counts_rows: Iterable[Mapping[str, object]],
    top_rows: Iterable[Mapping[str, object]],
    cvss_rows: Iterable[Mapping[str, object]],
) -> List[Dict[str, object]]:
    summary: Dict[str, Dict[str, object]] = {}

    top_lookup: Dict[str, Dict[str, Dict[str, object]]] = {}
    for row in top_rows:
        area = (row.get("masvs") or "").upper()
        if not area:
            continue
        severity = str(row.get("severity") or "")
        identifier = row.get("identifier") or row.get("kind") or "unknown"
        occurrences = int(row.get("occurrences") or 0)
        entry = top_lookup.setdefault(area, {})
        entry.setdefault(
            severity,
            {
                "descriptor": str(identifier),
                "occurrences": occurrences,
            },
        )

    for row in counts_rows:
        area = (row.get("masvs") or "").upper()
        if not area:
            continue
        entry = summary.setdefault(area, _empty_area(area))
        _merge_counts(entry, row)

    _integrate_cvss(cvss_rows, summary)

    for area, entry in summary.items():
        _merge_top(top_lookup, area, entry)
        cvss_meta = entry.get("cvss")
        if isinstance(cvss_meta, dict):
            entry["cvss"] = _finalise_cvss(cvss_meta)
        entry["quality"] = compute_quality_metrics(entry)

    ordered: List[Dict[str, object]] = []
    for area in _AREA_ORDER:
        if area in summary:
            ordered.append(summary[area])

    for area, entry in summary.items():
        if area not in _AREA_ORDER:
            ordered.append(entry)

    return ordered


def fetch_db_masvs_summary(run_id: Optional[int] = None) -> Optional[Tuple[int, List[Dict[str, object]]]]:
    try:
        if run_id is None:
            row = core_q.run_sql("SELECT MAX(run_id) FROM runs", fetch="one")
            if not row or not row[0]:
                return None
            run_id = int(row[0])

        rows = core_q.run_sql(
            """
            SELECT masvs,
                   SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low,
                   SUM(CASE WHEN severity='Info' THEN 1 ELSE 0 END) AS info
            FROM findings
            WHERE run_id = %s
            GROUP BY masvs
            """,
            (run_id,),
            fetch="all",
            dictionary=True,
        ) or []

        cvss_rows = core_q.run_sql(
            """
            SELECT masvs,
                   cvss,
                   COALESCE(NULLIF(kind, ''), 'unknown') AS identifier,
                   severity
            FROM findings
            WHERE run_id = %s AND masvs IS NOT NULL
            """,
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

    summary = _build_summary(rows, top_rows, cvss_rows)

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
