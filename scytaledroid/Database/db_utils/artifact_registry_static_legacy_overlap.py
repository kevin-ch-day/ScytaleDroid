"""Read-only audit helpers for static dangling rows overlapping legacy mirror tables."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

RunSql = Callable[..., Any]

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "legacy_overlap_sessions.csv",
    "legacy_overlap_runs.csv",
    "legacy_overlap_top_packages.csv",
)


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params or ()), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] | None = None, *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params or ()), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def collect_static_legacy_overlap_report(run_sql: RunSql) -> dict[str, Any]:
    summary = _row(
        run_sql,
        """
        SELECT
          COUNT(*) AS overlap_registry_rows,
          COUNT(DISTINCT v.resolved_static_run_id) AS overlap_run_ids,
          COUNT(DISTINCT r.session_stamp) AS overlap_session_stamps,
          SUM(CASE WHEN v.host_path IS NOT NULL AND TRIM(v.host_path) <> '' THEN 1 ELSE 0 END) AS host_path_rows,
          SUM(CASE WHEN v.host_path IS NULL OR TRIM(v.host_path) = '' THEN 1 ELSE 0 END) AS blank_host_rows
        FROM v_artifact_registry_integrity v
        INNER JOIN runs r
          ON r.run_id = v.resolved_static_run_id
        WHERE v.run_type = 'static'
          AND v.link_state = 'dangling_static_run'
        """,
        query_name="artifact_registry_static_legacy_overlap.summary",
    )
    session_rows = _rows(
        run_sql,
        """
        SELECT
          r.session_stamp,
          COUNT(*) AS overlap_run_ids,
          SUM(COALESCE(m.metrics_rows, 0)) AS metrics_rows,
          SUM(COALESCE(b.buckets_rows, 0)) AS buckets_rows,
          SUM(COALESCE(c.contributor_rows, 0)) AS contributor_rows,
          SUM(COALESCE(f.finding_rows, 0)) AS finding_rows
        FROM runs r
        INNER JOIN (
          SELECT DISTINCT v.resolved_static_run_id AS run_id
          FROM v_artifact_registry_integrity v
          INNER JOIN runs rr
            ON rr.run_id = v.resolved_static_run_id
          WHERE v.run_type = 'static'
            AND v.link_state = 'dangling_static_run'
        ) x
          ON x.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS metrics_rows FROM metrics GROUP BY run_id) m
          ON m.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS buckets_rows FROM buckets GROUP BY run_id) b
          ON b.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS contributor_rows FROM contributors GROUP BY run_id) c
          ON c.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS finding_rows FROM findings GROUP BY run_id) f
          ON f.run_id = r.run_id
        GROUP BY r.session_stamp
        ORDER BY overlap_run_ids DESC, r.session_stamp
        """,
        query_name="artifact_registry_static_legacy_overlap.sessions",
    )
    run_rows = _rows(
        run_sql,
        """
        SELECT
          r.run_id,
          r.package,
          r.session_stamp,
          COALESCE(m.metrics_rows, 0) AS metrics_rows,
          COALESCE(b.buckets_rows, 0) AS buckets_rows,
          COALESCE(c.contributor_rows, 0) AS contributor_rows,
          COALESCE(f.finding_rows, 0) AS finding_rows
        FROM runs r
        INNER JOIN (
          SELECT DISTINCT v.resolved_static_run_id AS run_id
          FROM v_artifact_registry_integrity v
          INNER JOIN runs rr
            ON rr.run_id = v.resolved_static_run_id
          WHERE v.run_type = 'static'
            AND v.link_state = 'dangling_static_run'
        ) x
          ON x.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS metrics_rows FROM metrics GROUP BY run_id) m
          ON m.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS buckets_rows FROM buckets GROUP BY run_id) b
          ON b.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS contributor_rows FROM contributors GROUP BY run_id) c
          ON c.run_id = r.run_id
        LEFT JOIN (SELECT run_id, COUNT(*) AS finding_rows FROM findings GROUP BY run_id) f
          ON f.run_id = r.run_id
        ORDER BY COALESCE(f.finding_rows, 0) DESC, COALESCE(m.metrics_rows, 0) DESC, r.run_id DESC
        """,
        query_name="artifact_registry_static_legacy_overlap.runs",
    )

    package_counter = Counter()
    for row in run_rows:
        package_counter[str(row.get("package") or "")] += 1
    top_packages = [
        {"package": package, "run_count": count}
        for package, count in sorted(package_counter.items(), key=lambda item: (-item[1], item[0]))[:50]
    ]

    summary_payload = {
        "overlap_registry_rows": int(summary.get("overlap_registry_rows") or 0),
        "overlap_run_ids": int(summary.get("overlap_run_ids") or 0),
        "overlap_session_stamps": int(summary.get("overlap_session_stamps") or 0),
        "host_path_rows": int(summary.get("host_path_rows") or 0),
        "blank_host_rows": int(summary.get("blank_host_rows") or 0),
        "session_row_count": len(session_rows),
        "run_row_count": len(run_rows),
        "top_session_stamps": [str(row.get("session_stamp") or "") for row in session_rows[:10]],
    }
    return {
        "summary": summary_payload,
        "legacy_overlap_sessions": session_rows,
        "legacy_overlap_runs": run_rows,
        "legacy_overlap_top_packages": top_packages,
    }


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def write_static_legacy_overlap_bundle(report: Mapping[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, payload in (
        ("summary.json", report.get("summary") or {}),
        ("legacy_overlap_sessions.csv", report.get("legacy_overlap_sessions") or []),
        ("legacy_overlap_runs.csv", report.get("legacy_overlap_runs") or []),
        ("legacy_overlap_top_packages.csv", report.get("legacy_overlap_top_packages") or []),
    ):
        path = output_dir / name
        if name.endswith(".json"):
            path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
        else:
            _write_csv(path, payload if isinstance(payload, Sequence) else [])
        written.append(path)
    return written


__all__ = [
    "OUTPUT_FILES",
    "collect_static_legacy_overlap_report",
    "write_static_legacy_overlap_bundle",
]
