#!/usr/bin/env python3
"""Generate static corpus tables from a frozen DB snapshot."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from statistics import median
from typing import Any
from urllib.parse import unquote, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.version_utils import get_git_commit


@dataclass(frozen=True)
class SnapshotRow:
    run_id: int
    package_name: str
    display_name: str | None
    profile_key: str
    version_code: int | None
    version_name: str | None
    sha256: str | None
    session_stamp: str | None
    scope_label: str | None
    risk_score: float | None
    risk_grade: str | None
    dangerous: int | None
    signature: int | None
    vendor: int | None
    config_hash: str | None
    ended_at_utc: str | None


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _category(value: str | None) -> str:
    text = (value or "").strip()
    return text if text else "UNKNOWN"


def _configure_db_target(db_target: str) -> None:
    parsed = urlparse(db_target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"mysql", "mariadb", "sqlite", "file"}:
        raise RuntimeError("Unsupported --db-target scheme. Use mysql://... or sqlite:///...")

    os.environ["SCYTALEDROID_DB_URL"] = db_target
    if scheme in {"sqlite", "file"}:
        db_path = parsed.path or parsed.netloc
        if not db_path:
            raise RuntimeError("sqlite --db-target must include a path, e.g. sqlite:///abs/path.db")
        db_config.DB_CONFIG = {
            "engine": "sqlite",
            "database": db_path,
            "charset": "utf8",
            "readonly": False,
        }
        db_config.DB_CONFIG_SOURCE = "cli:--db-target"
        print(f"[DB TARGET] backend=sqlite path={db_path}")
        return

    db_config.DB_CONFIG = {
        "engine": "mysql",
        "host": parsed.hostname or "localhost",
        "port": int(parsed.port or 3306),
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "database": (parsed.path or "").lstrip("/"),
        "charset": "utf8mb4",
    }
    db_config.DB_CONFIG_SOURCE = "cli:--db-target"
    print(
        "[DB TARGET] "
        f"backend=mysql host={db_config.DB_CONFIG['host']} "
        f"port={db_config.DB_CONFIG['port']} db={db_config.DB_CONFIG['database']}"
    )


def _resolve_snapshot_rows() -> list[SnapshotRow]:
    rows = core_q.run_sql(
        """
        SELECT
          r.id,
          a.package_name,
          a.display_name,
          a.profile_key,
          av.version_code,
          av.version_name,
          r.sha256,
          r.session_stamp,
          r.scope_label,
          rs.risk_score,
          rs.risk_grade,
          rs.dangerous,
          rs.signature,
          rs.vendor,
          r.config_hash,
          CAST(r.ended_at_utc AS CHAR)
        FROM static_analysis_runs r
        JOIN app_versions av ON av.id = r.app_version_id
        JOIN apps a ON a.id = av.app_id
        JOIN (
            SELECT
              a2.package_name AS package_name,
              COALESCE(av2.version_code, -1) AS version_code_key,
              COALESCE(r2.sha256, '') AS sha256_key,
              MAX(r2.id) AS max_run_id
            FROM static_analysis_runs r2
            JOIN app_versions av2 ON av2.id = r2.app_version_id
            JOIN apps a2 ON a2.id = av2.app_id
            WHERE r2.status = 'COMPLETED'
            GROUP BY
              a2.package_name,
              COALESCE(av2.version_code, -1),
              COALESCE(r2.sha256, '')
        ) latest
          ON latest.max_run_id = r.id
        LEFT JOIN risk_scores rs
          ON rs.package_name COLLATE utf8mb4_unicode_ci = a.package_name COLLATE utf8mb4_unicode_ci
         AND rs.session_stamp COLLATE utf8mb4_unicode_ci = r.session_stamp COLLATE utf8mb4_unicode_ci
         AND rs.scope_label COLLATE utf8mb4_unicode_ci = r.scope_label COLLATE utf8mb4_unicode_ci
        ORDER BY
          a.package_name ASC,
          COALESCE(av.version_code, -1) ASC,
          COALESCE(r.sha256, '') ASC,
          r.id ASC
        """,
        fetch="all",
    ) or []

    out: list[SnapshotRow] = []
    for row in rows:
        out.append(
            SnapshotRow(
                run_id=int(row[0]),
                package_name=str(row[1]),
                display_name=row[2],
                profile_key=_category(row[3]),
                version_code=_safe_int(row[4]),
                version_name=row[5],
                sha256=row[6],
                session_stamp=row[7],
                scope_label=row[8],
                risk_score=_safe_float(row[9]),
                risk_grade=row[10],
                dangerous=_safe_int(row[11]),
                signature=_safe_int(row[12]),
                vendor=_safe_int(row[13]),
                config_hash=row[14],
                ended_at_utc=row[15],
            )
        )
    return out


def _config_hash_set_hash(rows: list[SnapshotRow]) -> str:
    hashes = sorted({row.config_hash for row in rows if row.config_hash})
    payload = json.dumps(hashes, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def _snapshot_metadata(rows: list[SnapshotRow]) -> dict[str, Any]:
    anchor = max((row.ended_at_utc for row in rows if row.ended_at_utc), default=None)
    return {
        "snapshot_definition": "latest completed static run per (package_name, version_code, sha256)",
        "snapshot_anchor_utc": anchor,
        "snapshot_row_count": len(rows),
        "tool_semver": app_config.APP_VERSION,
        "tool_git_commit": get_git_commit(),
        "config_hash_set_sha256": _config_hash_set_hash(rows),
        "snapshot_generated_utc": anchor,
    }


def _risk_values(rows: list[SnapshotRow]) -> list[float]:
    return sorted([value for value in (row.risk_score for row in rows) if value is not None])


def _overall_risk_distribution(rows: list[SnapshotRow], meta: dict[str, Any]) -> list[dict[str, Any]]:
    values = _risk_values(rows)
    if not values:
        return [
            {
                "snapshot_row_count": len(rows),
                "scored_row_count": 0,
                "missing_score_count": len(rows),
                "risk_avg": None,
                "risk_median": None,
                "risk_min": None,
                "risk_max": None,
                "snapshot_anchor_utc": meta.get("snapshot_anchor_utc"),
                "tool_semver": meta.get("tool_semver"),
                "tool_git_commit": meta.get("tool_git_commit"),
                "config_hash_set_sha256": meta.get("config_hash_set_sha256"),
            }
        ]
    return [
        {
            "snapshot_row_count": len(rows),
            "scored_row_count": len(values),
            "missing_score_count": len(rows) - len(values),
            "risk_avg": round(sum(values) / len(values), 6),
            "risk_median": round(float(median(values)), 6),
            "risk_min": min(values),
            "risk_max": max(values),
            "snapshot_anchor_utc": meta.get("snapshot_anchor_utc"),
            "tool_semver": meta.get("tool_semver"),
            "tool_git_commit": meta.get("tool_git_commit"),
            "config_hash_set_sha256": meta.get("config_hash_set_sha256"),
        }
    ]


def _risk_by_category(rows: list[SnapshotRow], meta: dict[str, Any]) -> list[dict[str, Any]]:
    buckets: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        if row.risk_score is None:
            continue
        buckets[_category(row.profile_key)].append(float(row.risk_score))
    result: list[dict[str, Any]] = []
    for category in sorted(buckets):
        values = sorted(buckets[category])
        result.append(
            {
                "category": category,
                "apps_count": len(values),
                "risk_avg": round(sum(values) / len(values), 6),
                "risk_median": round(float(median(values)), 6),
                "risk_min": min(values),
                "risk_max": max(values),
                "snapshot_anchor_utc": meta.get("snapshot_anchor_utc"),
                "tool_semver": meta.get("tool_semver"),
                "tool_git_commit": meta.get("tool_git_commit"),
                "config_hash_set_sha256": meta.get("config_hash_set_sha256"),
            }
        )
    return result


def _top_holes(rows: list[SnapshotRow], meta: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    run_ids = [row.run_id for row in rows]
    if not run_ids:
        return []
    placeholders = ",".join(["%s"] * len(run_ids))
    params: list[Any] = [*run_ids]
    findings = core_q.run_sql(
        f"""
        SELECT
          f.run_id,
          COALESCE(NULLIF(f.rule_id, ''), '<none>') AS rule_id,
          COALESCE(NULLIF(f.title, ''), '<untitled>') AS title,
          COALESCE(NULLIF(f.severity, ''), 'UNKNOWN') AS severity,
          COALESCE(NULLIF(f.detector, ''), NULLIF(f.module, ''), '<unknown>') AS detector_key
        FROM static_analysis_findings f
        WHERE f.run_id IN ({placeholders})
        """,
        tuple(params),
        fetch="all",
    ) or []

    run_to_category = {row.run_id: _category(row.profile_key) for row in rows}
    overall_counter: dict[tuple[str, str, str, str], int] = defaultdict(int)
    category_counter: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
    for finding in findings:
        run_id = int(finding[0])
        rule_id = str(finding[1])
        title = str(finding[2])
        severity = str(finding[3])
        detector_key = str(finding[4])
        key = (rule_id, title, severity, detector_key)
        overall_counter[key] += 1
        category = run_to_category.get(run_id, "UNKNOWN")
        category_counter[(category, rule_id, title, severity, detector_key)] += 1

    result: list[dict[str, Any]] = []
    overall_sorted = sorted(
        overall_counter.items(),
        key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2], item[0][3]),
    )[:limit]
    for (rule_id, title, severity, detector_key), count in overall_sorted:
        result.append(
            {
                "slice": "overall",
                "category": "ALL",
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "detector": detector_key,
                "finding_count": count,
                "snapshot_anchor_utc": meta.get("snapshot_anchor_utc"),
                "tool_semver": meta.get("tool_semver"),
                "tool_git_commit": meta.get("tool_git_commit"),
                "config_hash_set_sha256": meta.get("config_hash_set_sha256"),
            }
        )

    category_sorted = sorted(
        category_counter.items(),
        key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2], item[0][3], item[0][4]),
    )[:limit]
    for (category, rule_id, title, severity, detector_key), count in category_sorted:
        result.append(
            {
                "slice": "by_category",
                "category": category,
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "detector": detector_key,
                "finding_count": count,
                "snapshot_anchor_utc": meta.get("snapshot_anchor_utc"),
                "tool_semver": meta.get("tool_semver"),
                "tool_git_commit": meta.get("tool_git_commit"),
                "config_hash_set_sha256": meta.get("config_hash_set_sha256"),
            }
        )
    return result


def _detector_frequency(rows: list[SnapshotRow], meta: dict[str, Any]) -> list[dict[str, Any]]:
    run_ids = [row.run_id for row in rows]
    if not run_ids:
        return []
    placeholders = ",".join(["%s"] * len(run_ids))
    params: list[Any] = [*run_ids]
    freq_rows = core_q.run_sql(
        f"""
        SELECT
          COALESCE(NULLIF(detector, ''), NULLIF(module, ''), '<unknown>') AS detector_key,
          COUNT(*) AS n
        FROM static_analysis_findings
        WHERE run_id IN ({placeholders})
        GROUP BY COALESCE(NULLIF(detector, ''), NULLIF(module, ''), '<unknown>')
        ORDER BY n DESC, detector_key ASC
        """,
        tuple(params),
        fetch="all",
    ) or []
    return [
        {
            "detector": str(row[0]),
            "finding_count": int(row[1]),
            "snapshot_anchor_utc": meta.get("snapshot_anchor_utc"),
            "tool_semver": meta.get("tool_semver"),
            "tool_git_commit": meta.get("tool_git_commit"),
            "config_hash_set_sha256": meta.get("config_hash_set_sha256"),
        }
        for row in freq_rows
    ]


def _evidence_hash(record: Any) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def _per_app_explainability(rows: list[SnapshotRow], *, limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        findings = core_q.run_sql(
            """
            SELECT
              rule_id,
              title,
              severity,
              COALESCE(NULLIF(detector, ''), NULLIF(module, ''), '<unknown>') AS detector_key,
              evidence
            FROM static_analysis_findings
            WHERE run_id = %s
            ORDER BY
              CASE severity
                WHEN 'P0' THEN 0
                WHEN 'P1' THEN 1
                WHEN 'P2' THEN 2
                ELSE 9
              END ASC,
              id ASC
            LIMIT %s
            """,
            (row.run_id, max(1, limit)),
            fetch="all",
        ) or []
        contributors = [
            {
                "rule_id": finding[0],
                "title": finding[1],
                "severity": finding[2],
                "detector": finding[3],
                "evidence_hash": _evidence_hash(finding[4]),
            }
            for finding in findings
        ]
        out.append(
            {
                "run_id": row.run_id,
                "package_name": row.package_name,
                "display_name": row.display_name,
                "category": _category(row.profile_key),
                "session_stamp": row.session_stamp,
                "scope_label": row.scope_label,
                "risk_score": row.risk_score,
                "risk_grade": row.risk_grade,
                "breakdown": {
                    "dangerous": int(row.dangerous or 0),
                    "signature": int(row.signature or 0),
                    "vendor": int(row.vendor or 0),
                },
                "top_contributors": contributors,
            }
        )
    return out


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _emit_table(out_dir: Path, stem: str, rows: list[dict[str, Any]], meta: dict[str, Any], *, formats: tuple[str, ...]) -> None:
    payload = {"metadata": meta, "rows": rows}
    if "json" in formats:
        _write_json(out_dir / f"{stem}.json", payload)
    if "csv" in formats:
        _write_csv(out_dir / f"{stem}.csv", rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate static corpus tables from canonical DB.")
    parser.add_argument(
        "--db-target",
        required=True,
        help="Explicit DB target DSN (mysql://... or sqlite:///...). Required for audit safety.",
    )
    parser.add_argument("--out-dir", default="output/audit/static_baseline", help="Output directory.")
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["csv", "json"],
        choices=["csv", "json"],
        help="Output formats.",
    )
    parser.add_argument("--top-limit", type=int, default=50, help="Top-N rows for holes/detector tables.")
    parser.add_argument("--contributors-limit", type=int, default=10, help="Top-N finding contributors per app.")
    args = parser.parse_args(argv)
    _configure_db_target(str(args.db_target))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = tuple(sorted(set(args.formats)))

    snapshot_rows = _resolve_snapshot_rows()
    meta = _snapshot_metadata(snapshot_rows)
    _write_json(out_dir / "snapshot_metadata.json", meta)
    _write_json(
        out_dir / "snapshot_rows.json",
        {
            "metadata": meta,
            "rows": [row.__dict__ for row in snapshot_rows],
        },
    )

    overall = _overall_risk_distribution(snapshot_rows, meta)
    risk_by_category = _risk_by_category(snapshot_rows, meta)
    top_holes = _top_holes(snapshot_rows, meta, limit=max(1, args.top_limit))
    detector_frequency = _detector_frequency(snapshot_rows, meta)
    explainability = _per_app_explainability(snapshot_rows, limit=max(1, args.contributors_limit))

    _emit_table(out_dir, "overall_risk_distribution", overall, meta, formats=formats)
    _emit_table(out_dir, "risk_by_category", risk_by_category, meta, formats=formats)
    _emit_table(out_dir, "top_holes", top_holes, meta, formats=formats)
    _emit_table(out_dir, "detector_frequency", detector_frequency, meta, formats=formats)
    _emit_table(out_dir, "per_app_explainability", explainability, meta, formats=formats)

    summary = {
        "status": "ok",
        "out_dir": str(out_dir),
        "snapshot_row_count": len(snapshot_rows),
        "files": sorted([path.name for path in out_dir.iterdir() if path.is_file()]),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
