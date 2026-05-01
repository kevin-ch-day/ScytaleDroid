"""Helpers to fetch MASVS summaries from the database."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.analytics.masvs_quality import (
    compute_quality_metrics,
)

from ...core.cvss_v4 import parse_vector, score_vector, severity_band

_AREA_ORDER = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")


def _masvs_area_case_sql(column: str, *, fallback_sql: str | None = None) -> str:
    upper = f"UPPER(COALESCE({column}, ''))"
    fallback = fallback_sql or f"NULLIF(TRIM({upper}), '')"
    return f"""
              CASE
                WHEN {upper} = 'NETWORK' OR {upper} LIKE 'NETWORK-%%' THEN 'NETWORK'
                WHEN {upper} = 'PLATFORM' OR {upper} LIKE 'PLATFORM-%%' THEN 'PLATFORM'
                WHEN {upper} = 'PRIVACY' OR {upper} LIKE 'PRIVACY-%%' THEN 'PRIVACY'
                WHEN {upper} = 'STORAGE' OR {upper} LIKE 'STORAGE-%%' THEN 'STORAGE'
                ELSE {fallback}
              END
    """.strip()


def _empty_area(area: str) -> dict[str, object]:
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


def _finalise_cvss(entry: Mapping[str, object]) -> dict[str, object]:
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
    distribution: dict[str, float] = {}
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


def _cvss_band_rank(band: str | None) -> int:
    band_order = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "None": 1,
        "Unknown": 0,
    }
    return band_order.get(band or "", 0)


def _cvss_scope_rank(vector: str | None) -> int:
    if not vector:
        return 0
    metrics = parse_vector(vector)
    if not metrics:
        return 0
    rank_map = {"H": 2, "L": 1}
    values = [rank_map.get(metrics.get(key, ""), 0) for key in ("SC", "SI", "SA")]
    return max(values) if values else 0


def _cvss_impact_tuple(vector: str | None) -> tuple[int, int]:
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
    band: str | None,
    scope_rank: int,
    impact: tuple[int, int],
    vector: str | None,
    identifier: str | None,
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


def _merge_counts(entry: dict[str, object], row: Mapping[str, object]) -> None:
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


def _merge_top(top_lookup: Mapping[str, Mapping[str, object]], area: str, entry: dict[str, object]) -> None:
    top = top_lookup.get(area, {})
    entry["top_high"] = top.get("High") if isinstance(top, Mapping) else None
    entry["top_medium"] = top.get("Medium") if isinstance(top, Mapping) else None


def _integrate_cvss(cvss_rows: Iterable[Mapping[str, object]], summary: dict[str, dict[str, object]]) -> None:
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
        direct_score = row.get("score")
        score = score_vector(vector)
        scope_rank = 0
        impact = (0, 0)

        if score is None and direct_score is not None:
            try:
                score = float(direct_score)
            except (TypeError, ValueError):
                score = None
        elif score is not None:
            scope_rank = _cvss_scope_rank(vector)
            impact = _cvss_impact_tuple(vector)

        if score is None:
            cvss_meta["missing"] = int(cvss_meta.get("missing", 0)) + 1
        else:
            cvss_meta["_score_sum"] += float(score)
            cvss_meta["_score_count"] += 1
            band = severity_band(score) or "Unknown"
            cvss_meta["band_counts"][band] += 1
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
) -> list[dict[str, object]]:
    summary: dict[str, dict[str, object]] = {}

    top_lookup: dict[str, dict[str, dict[str, object]]] = {}
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

    for area in _AREA_ORDER:
        summary.setdefault(area, _empty_area(area))

    _integrate_cvss(cvss_rows, summary)

    for area, entry in summary.items():
        _merge_top(top_lookup, area, entry)
        cvss_meta = entry.get("cvss")
        if isinstance(cvss_meta, dict):
            entry["cvss"] = _finalise_cvss(cvss_meta)
        entry["quality"] = compute_quality_metrics(entry)

    ordered: list[dict[str, object]] = []
    for area in _AREA_ORDER:
        if area in summary:
            ordered.append(summary[area])

    for area, entry in summary.items():
        if area not in _AREA_ORDER:
            ordered.append(entry)

    return ordered


def fetch_db_masvs_summary(run_id: int | None = None) -> tuple[int, list[dict[str, object | None]]] | None:
    try:
        if run_id is None:
            row = core_q.run_sql("SELECT MAX(run_id) FROM runs", fetch="one")
            if not row or not row[0]:
                return None
            run_id = int(row[0])

        linked_static_rows = core_q.run_sql(
            """
            SELECT DISTINCT static_run_id
            FROM findings
            WHERE run_id = %s AND static_run_id IS NOT NULL
            ORDER BY static_run_id DESC
            """,
            (run_id,),
            fetch="all",
        ) or []
        linked_static_ids = [int(row[0]) for row in linked_static_rows if row and row[0]]
        if linked_static_ids:
            summary = fetch_db_masvs_summary_static_many(linked_static_ids)
            if summary is not None:
                return run_id, summary[1]

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


def fetch_db_masvs_summary_static(static_run_id: int) -> tuple[int, list[dict[str, object | None]]] | None:
    return fetch_db_masvs_summary_static_many([static_run_id])


def fetch_db_masvs_summary_static_many(
    static_run_ids: Sequence[int],
) -> tuple[int, list[dict[str, object | None]]] | None:
    ids = [int(value) for value in static_run_ids if value is not None]
    if not ids:
        return None
    placeholders = ",".join(["%s"] * len(ids))
    params = tuple(ids)
    canonical_area_case = _masvs_area_case_sql("COALESCE(saf.masvs_area, saf.masvs_control)")
    try:
        rows = core_q.run_sql(
            f"""
            SELECT
                   {canonical_area_case} AS masvs,
                   SUM(CASE WHEN LOWER(COALESCE(saf.severity, ''))='high' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN LOWER(COALESCE(saf.severity, ''))='medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN LOWER(COALESCE(saf.severity, ''))='low' THEN 1 ELSE 0 END) AS low,
                   SUM(CASE WHEN LOWER(COALESCE(saf.severity, ''))='info' THEN 1 ELSE 0 END) AS info
            FROM static_analysis_findings saf
            WHERE saf.run_id IN ({placeholders})
              AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
            GROUP BY masvs
            """,
            params,
            fetch="all",
            dictionary=True,
        ) or []

        cvss_rows = core_q.run_sql(
            f"""
            SELECT
                   {canonical_area_case} AS masvs,
                   saf.cvss_score AS score,
                   COALESCE(NULLIF(saf.rule_id, ''), NULLIF(saf.detector, ''), NULLIF(saf.title, ''), 'unknown') AS identifier,
                   saf.severity
            FROM static_analysis_findings saf
            WHERE saf.run_id IN ({placeholders})
              AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
            """,
            params,
            fetch="all",
            dictionary=True,
        ) or []

        top_rows = core_q.run_sql(
            f"""
            SELECT
                   {canonical_area_case} AS masvs,
                   saf.severity,
                   COALESCE(NULLIF(saf.rule_id, ''), NULLIF(saf.detector, ''), NULLIF(saf.title, ''), 'unknown') AS identifier,
                   COUNT(*) AS occurrences
            FROM static_analysis_findings saf
            WHERE saf.run_id IN ({placeholders})
              AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
            GROUP BY masvs, saf.severity, identifier
            ORDER BY
                CASE saf.severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                occurrences DESC
            """,
            params,
            fetch="all",
            dictionary=True,
        ) or []

        if not rows and not cvss_rows and not top_rows:
            rows = core_q.run_sql(
                f"""
                SELECT masvs,
                       SUM(CASE WHEN severity='High' THEN 1 ELSE 0 END) AS high,
                       SUM(CASE WHEN severity='Medium' THEN 1 ELSE 0 END) AS medium,
                       SUM(CASE WHEN severity='Low' THEN 1 ELSE 0 END) AS low,
                       SUM(CASE WHEN severity='Info' THEN 1 ELSE 0 END) AS info
                FROM static_findings
                WHERE static_run_id IN ({placeholders})
                GROUP BY masvs
                """,
                params,
                fetch="all",
                dictionary=True,
            ) or []

            cvss_rows = core_q.run_sql(
                f"""
                SELECT masvs,
                       cvss,
                       COALESCE(NULLIF(kind, ''), 'unknown') AS identifier,
                       severity
                FROM static_findings
                WHERE static_run_id IN ({placeholders}) AND masvs IS NOT NULL
                """,
                params,
                fetch="all",
                dictionary=True,
            ) or []

            top_rows = core_q.run_sql(
                f"""
                SELECT masvs,
                       severity,
                       COALESCE(NULLIF(kind, ''), 'unknown') AS identifier,
                       COUNT(*) AS occurrences
                FROM static_findings
                WHERE static_run_id IN ({placeholders})
                GROUP BY masvs, severity, identifier
                ORDER BY
                    CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                    occurrences DESC
                """,
                params,
                fetch="all",
                dictionary=True,
            ) or []
    except Exception:
        return None

    summary = _build_summary(rows, top_rows, cvss_rows)
    if not summary:
        return None
    return max(ids), summary


def fetch_masvs_matrix() -> dict[str, dict[str, object]]:
    """Return MASVS pass/fail matrix keyed by package using latest canonical static runs."""

    try:
        latest_runs = core_q.run_sql(
            """
            SELECT
              a.package_name,
              COALESCE(NULLIF(a.display_name, ''), a.package_name) AS app_label,
              sar.id AS static_run_id,
              sar.session_stamp,
              sar.scope_label,
              av.version_name,
              av.version_code,
              av.target_sdk
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            JOIN (
              SELECT
                a2.package_name,
                COALESCE(
                  MAX(CASE
                    WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
                     AND UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
                    THEN sar2.id
                  END),
                  MAX(CASE
                    WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
                    THEN sar2.id
                  END),
                  MAX(sar2.id)
                ) AS preferred_static_run_id
              FROM static_analysis_runs sar2
              JOIN app_versions av2 ON av2.id = sar2.app_version_id
              JOIN apps a2 ON a2.id = av2.app_id
              GROUP BY a2.package_name
            ) preferred
              ON preferred.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
             AND preferred.preferred_static_run_id = sar.id
            ORDER BY a.package_name
            """,
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return {}

    latest_by_package = {
        str(row.get("package_name")): row
        for row in latest_runs
        if row.get("package_name") is not None and row.get("static_run_id") is not None
    }
    run_to_package = {
        int(row.get("static_run_id")): package
        for package, row in latest_by_package.items()
    }
    run_ids = sorted(run_to_package.keys())
    if not run_ids:
        return {}

    placeholders = ",".join(["%s"] * len(run_ids))
    params = tuple(run_ids)
    area_case = _masvs_area_case_sql("COALESCE(saf.masvs_area, saf.masvs_control)", fallback_sql="'OTHER'")
    try:
        rows = core_q.run_sql(
            f"""
            SELECT
              saf.run_id AS static_run_id,
              {area_case} AS masvs,
              SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'high' THEN 1 ELSE 0 END) AS high,
              SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'medium' THEN 1 ELSE 0 END) AS medium,
              SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'low' THEN 1 ELSE 0 END) AS low,
              SUM(CASE WHEN LOWER(COALESCE(saf.severity, '')) = 'info' THEN 1 ELSE 0 END) AS info
            FROM static_analysis_findings saf
            WHERE saf.run_id IN ({placeholders})
            GROUP BY saf.run_id, masvs
            ORDER BY saf.run_id
            """,
            params,
            fetch="all",
            dictionary=True,
        ) or []

        top_rows = core_q.run_sql(
            f"""
            SELECT
              saf.run_id AS static_run_id,
              {area_case} AS masvs,
              saf.severity,
              COALESCE(NULLIF(saf.rule_id, ''), NULLIF(saf.detector, ''), NULLIF(saf.title, ''), 'unknown') AS identifier,
              COUNT(*) AS occurrences
            FROM static_analysis_findings saf
            WHERE saf.run_id IN ({placeholders})
              AND NULLIF(TRIM(COALESCE(saf.masvs_control, '')), '') IS NOT NULL
            GROUP BY saf.run_id, masvs, saf.severity, identifier
            ORDER BY
              saf.run_id,
              CASE saf.severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
              occurrences DESC
            """,
            params,
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return {}

    top_lookup: dict[tuple[str, str], dict[str, dict[str, object]]] = {}
    for row in top_rows:
        try:
            package = run_to_package[int(row.get("static_run_id") or 0)]
        except Exception:
            package = None
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

    matrix: dict[str, dict[str, object]] = {}
    for row in rows:
        try:
            package = run_to_package[int(row.get("static_run_id") or 0)]
        except Exception:
            package = None
        area = (row.get("masvs") or "").upper()
        if not package or not area:
            continue
        entry = matrix.setdefault(
            package,
            {
                "run_id": int(row.get("static_run_id") or 0),
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
    for _package, data in matrix.items():
        statuses = data["status"]
        passed = 0
        for area in areas:
            if area not in statuses:
                statuses[area] = "PASS"
            if statuses[area] == "PASS":
                passed += 1
        data["pass_rate"] = int(round((passed / len(areas)) * 100))

    for package, entry in latest_by_package.items():
        if package in matrix:
            continue
        matrix[package] = {
            "run_id": int(entry.get("static_run_id") or 0),
            "status": {area: "PASS" for area in areas},
            "counts": {area: {"high": 0, "medium": 0, "low": 0, "info": 0} for area in areas},
            "top": {area: {"high": None, "medium": None} for area in areas},
            "pass_rate": 100,
        }

    def _first_text(*values: object | None) -> str | None:
        for value in values:
            if value is None:
                continue
            try:
                text = str(value).strip()
            except Exception:
                continue
            if text:
                return text
        return None

    def _maybe_int(value: object | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    for package, data in matrix.items():
        meta = latest_by_package.get(package)
        label = None
        version_name = None
        version_code: int | None = None
        target_sdk: int | None = None
        scope_label = None
        session_stamp = None
        if isinstance(meta, Mapping):
            label = _first_text(meta.get("app_label"), label)
            scope_label = _first_text(meta.get("scope_label"))
            version_name = _first_text(meta.get("version_name"))
            version_code = _maybe_int(meta.get("version_code"))
            target_sdk = _maybe_int(meta.get("target_sdk"))
            session_stamp = _first_text(meta.get("session_stamp"))

        data["package"] = package
        data["label"] = label or package
        if version_name:
            data["version_name"] = version_name
        if version_code is not None:
            data["version_code"] = version_code
        if target_sdk is not None:
            data["target_sdk"] = target_sdk
        if scope_label:
            data["scope_label"] = scope_label
        if session_stamp:
            data["session_stamp"] = session_stamp

    return matrix


__all__ = [
    "fetch_db_masvs_summary",
    "fetch_db_masvs_summary_static",
    "fetch_db_masvs_summary_static_many",
    "fetch_masvs_matrix",
]
