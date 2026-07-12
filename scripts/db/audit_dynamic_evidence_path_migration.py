#!/usr/bin/env python3
"""Audit or normalize DB paths after dynamic evidence moved under data/.

Dry-run is the default.  With --apply, this script only rewrites direct path
columns whose current value points at the legacy dynamic evidence root and whose
normalized target exists on disk:

- dynamic_sessions.evidence_path
- artifact_registry.host_path

It does not rewrite JSON metadata, delete files, move evidence, or change
tracker/quota state.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class PathCandidate:
    table_name: str
    id_column: str
    row_id: Any
    path_column: str
    current_path: str
    normalized_path: str
    target_exists: bool
    status: str
    reason: str


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "output" / "audit" / "dynamic_evidence_path_migration",
        help="Directory for timestamped summary/candidate/action receipts.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Limit candidate rows for audit/apply; 0 means no limit.")
    parser.add_argument(
        "--reference-root",
        action="append",
        default=[],
        help=(
            "Search this local root for missing run-id references. Repeatable. "
            "Defaults to output/paper, data/archive, and data/state."
        ),
    )
    parser.add_argument("--apply", action="store_true", help="Rewrite verified direct path columns. Default is dry-run.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    return parser


def _legacy_abs_root() -> Path:
    return _REPO_ROOT / "output" / "evidence" / "dynamic"


def _canonical_abs_root() -> Path:
    return _REPO_ROOT / "data" / "evidence" / "dynamic"


def normalize_dynamic_evidence_path(value: str) -> str | None:
    """Return the canonical replacement for a legacy dynamic evidence path."""

    raw = str(value or "").strip()
    if not raw:
        return None

    legacy_abs = str(_legacy_abs_root())
    canonical_abs = str(_canonical_abs_root())
    if raw == legacy_abs or raw.startswith(legacy_abs + "/"):
        return canonical_abs + raw[len(legacy_abs) :]

    legacy_rel = "output/evidence/dynamic"
    canonical_rel = "data/evidence/dynamic"
    if raw == legacy_rel or raw.startswith(legacy_rel + "/"):
        return canonical_rel + raw[len(legacy_rel) :]

    legacy_suffix = "/" + legacy_rel
    marker_index = raw.find(legacy_suffix + "/")
    if marker_index >= 0:
        suffix = raw[marker_index + len(legacy_suffix) :]
        return str(_canonical_abs_root()) + suffix

    return None


def _path_exists(path_text: str) -> bool:
    path = Path(path_text)
    if not path.is_absolute():
        path = _REPO_ROOT / path
    return path.exists()


def _column_exists(run_sql: Any, table: str, column: str) -> bool:
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (table, column),
        fetch="one_dict",
    )
    return bool(row and int(row.get("n") or 0) > 0)


def _table_exists(run_sql: Any, table: str) -> bool:
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (table,),
        fetch="one_dict",
    )
    return bool(row and int(row.get("n") or 0) > 0)


def _collect_direct_path_candidates(run_sql: Any, *, limit: int = 0) -> list[PathCandidate]:
    specs = (
        ("dynamic_sessions", "dynamic_run_id", "evidence_path"),
        ("artifact_registry", "artifact_id", "host_path"),
    )
    candidates: list[PathCandidate] = []
    for table, id_col, path_col in specs:
        if not _table_exists(run_sql, table):
            continue
        if not (_column_exists(run_sql, table, id_col) and _column_exists(run_sql, table, path_col)):
            continue
        sql = f"""
            SELECT {id_col} AS row_id, {path_col} AS path_value
            FROM {table}
            WHERE {path_col} LIKE %s
               OR {path_col} LIKE %s
        """
        params: list[Any] = [
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
        ]
        if limit > 0:
            sql += " LIMIT %s"
            params.append(int(limit))
        rows = run_sql(sql, tuple(params), fetch="all_dict") or []
        for row in rows:
            current = str(row.get("path_value") or "")
            normalized = normalize_dynamic_evidence_path(current)
            if not normalized:
                candidates.append(
                    PathCandidate(
                        table_name=table,
                        id_column=id_col,
                        row_id=row.get("row_id"),
                        path_column=path_col,
                        current_path=current,
                        normalized_path="",
                        target_exists=False,
                        status="blocked",
                        reason="path_contains_legacy_root_but_not_rewriteable",
                    )
                )
                continue
            exists = _path_exists(normalized)
            candidates.append(
                PathCandidate(
                    table_name=table,
                    id_column=id_col,
                    row_id=row.get("row_id"),
                    path_column=path_col,
                    current_path=current,
                    normalized_path=normalized,
                    target_exists=exists,
                    status="candidate" if exists else "blocked",
                    reason="target_exists" if exists else "canonical_target_missing",
                )
            )
    return candidates


def _count_json_legacy_rows(run_sql: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    specs = (
        ("artifact_registry", "meta_json"),
        ("dynamic_sessions", "metadata_json"),
        ("dynamic_sessions", "extras_json"),
    )
    for table, column in specs:
        key = f"{table}.{column}"
        if not (_table_exists(run_sql, table) and _column_exists(run_sql, table, column)):
            out[key] = 0
            continue
        row = run_sql(
            f"""
            SELECT COUNT(*) AS n
            FROM {table}
            WHERE {column} LIKE %s
               OR {column} LIKE %s
            """,
            ("%output/evidence/dynamic%", f"%{str(_legacy_abs_root())}%"),
            fetch="one_dict",
        )
        out[key] = int((row or {}).get("n") or 0)
    return out


def _apply_candidates(run_sql_rowcount: Any, candidates: Sequence[PathCandidate]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.status != "candidate":
            actions.append({**candidate.__dict__, "applied": False, "rows_updated": 0})
            continue
        updated = run_sql_rowcount(
            f"""
            UPDATE {candidate.table_name}
            SET {candidate.path_column} = %s
            WHERE {candidate.id_column} = %s
              AND {candidate.path_column} = %s
            """,
            (candidate.normalized_path, candidate.row_id, candidate.current_path),
        )
        actions.append({**candidate.__dict__, "applied": bool(updated), "rows_updated": int(updated)})
    return actions


def _collect_missing_runs(run_sql: Any) -> list[dict[str, Any]]:
    if not (_table_exists(run_sql, "dynamic_sessions") and _table_exists(run_sql, "artifact_registry")):
        return []
    required = (
        _column_exists(run_sql, "dynamic_sessions", "dynamic_run_id")
        and _column_exists(run_sql, "dynamic_sessions", "package_name")
        and _column_exists(run_sql, "dynamic_sessions", "status")
        and _column_exists(run_sql, "dynamic_sessions", "evidence_path")
        and _column_exists(run_sql, "artifact_registry", "artifact_id")
        and _column_exists(run_sql, "artifact_registry", "run_id")
        and _column_exists(run_sql, "artifact_registry", "dynamic_run_id")
        and _column_exists(run_sql, "artifact_registry", "host_path")
    )
    if not required:
        return []
    rows = run_sql(
        """
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          ds.status,
          ds.evidence_path,
          COUNT(ar.artifact_id) AS legacy_artifact_rows
        FROM dynamic_sessions ds
        LEFT JOIN artifact_registry ar
          ON (ar.dynamic_run_id = ds.dynamic_run_id OR ar.run_id = ds.dynamic_run_id)
         AND (ar.host_path LIKE %s OR ar.host_path LIKE %s)
        WHERE ds.evidence_path LIKE %s
           OR ds.evidence_path LIKE %s
        GROUP BY ds.dynamic_run_id, ds.package_name, ds.status, ds.evidence_path
        ORDER BY legacy_artifact_rows DESC, ds.package_name, ds.dynamic_run_id
        """,
        (
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
        ),
        fetch="all_dict",
    )
    out: list[dict[str, Any]] = []
    for row in rows or []:
        normalized = normalize_dynamic_evidence_path(str(row.get("evidence_path") or ""))
        out.append(
            {
                "dynamic_run_id": row.get("dynamic_run_id") or "",
                "package_name": row.get("package_name") or "",
                "status": row.get("status") or "",
                "evidence_path": row.get("evidence_path") or "",
                "normalized_evidence_path": normalized or "",
                "normalized_target_exists": _path_exists(normalized) if normalized else False,
                "legacy_artifact_rows": int(row.get("legacy_artifact_rows") or 0),
                "classification": "missing_evidence_pack",
                "recommended_next_step": "restore_pack_or_review_for_session_retirement",
            }
        )
    return out


def _default_reference_roots() -> tuple[Path, ...]:
    return (
        _REPO_ROOT / "output" / "paper",
        _REPO_ROOT / "data" / "archive",
        _REPO_ROOT / "data" / "state",
    )


def _iter_reference_files(roots: Sequence[Path]) -> list[Path]:
    suffixes = {".json", ".csv", ".md", ".txt", ".yaml", ".yml"}
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            files.append(root)
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in suffixes:
                files.append(path)
    return files


def _collect_reference_hits(run_ids: Sequence[str], roots: Sequence[Path]) -> dict[str, list[str]]:
    wanted = {str(run_id).strip() for run_id in run_ids if str(run_id).strip()}
    hits: dict[str, list[str]] = {run_id: [] for run_id in wanted}
    if not wanted:
        return hits
    for path in _iter_reference_files(roots):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        matched = [run_id for run_id in wanted if run_id in text]
        if not matched:
            continue
        rel = str(path.relative_to(_REPO_ROOT)) if path.is_relative_to(_REPO_ROOT) else str(path)
        for run_id in matched:
            hits[run_id].append(rel)
    return hits


def _annotate_missing_run_references(
    missing_runs: Sequence[Mapping[str, Any]], reference_hits: Mapping[str, Sequence[str]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in missing_runs:
        run_id = str(row.get("dynamic_run_id") or "")
        hits = list(reference_hits.get(run_id) or [])
        annotated = dict(row)
        annotated["reference_hit_count"] = len(hits)
        annotated["reference_hits"] = ";".join(hits[:10])
        annotated["referenced_by_local_publication_artifacts"] = bool(hits)
        annotated["classification"] = (
            "missing_evidence_restore_before_retirement"
            if hits
            else "missing_evidence_db_only_retirement_candidate"
        )
        annotated["recommended_next_step"] = (
            "restore_pack_before_retirement"
            if hits
            else "stage_explicit_db_only_retirement_after_review"
        )
        out.append(annotated)
    return out


def _collect_package_summary(run_sql: Any) -> list[dict[str, Any]]:
    if not (_table_exists(run_sql, "dynamic_sessions") and _table_exists(run_sql, "artifact_registry")):
        return []
    if not (
        _column_exists(run_sql, "dynamic_sessions", "dynamic_run_id")
        and _column_exists(run_sql, "dynamic_sessions", "package_name")
        and _column_exists(run_sql, "dynamic_sessions", "status")
        and _column_exists(run_sql, "dynamic_sessions", "evidence_path")
        and _column_exists(run_sql, "artifact_registry", "artifact_id")
        and _column_exists(run_sql, "artifact_registry", "run_id")
        and _column_exists(run_sql, "artifact_registry", "dynamic_run_id")
        and _column_exists(run_sql, "artifact_registry", "host_path")
    ):
        return []
    rows = run_sql(
        """
        SELECT
          ds.package_name,
          ds.status,
          COUNT(DISTINCT CASE
            WHEN ds.evidence_path LIKE %s OR ds.evidence_path LIKE %s
            THEN ds.dynamic_run_id ELSE NULL END
          ) AS missing_session_rows,
          COUNT(CASE
            WHEN ar.host_path LIKE %s OR ar.host_path LIKE %s
            THEN ar.artifact_id ELSE NULL END
          ) AS missing_artifact_rows
        FROM dynamic_sessions ds
        LEFT JOIN artifact_registry ar
          ON ar.dynamic_run_id = ds.dynamic_run_id OR ar.run_id = ds.dynamic_run_id
        WHERE ds.evidence_path LIKE %s
           OR ds.evidence_path LIKE %s
           OR ar.host_path LIKE %s
           OR ar.host_path LIKE %s
        GROUP BY ds.package_name, ds.status
        ORDER BY missing_artifact_rows DESC, missing_session_rows DESC, ds.package_name
        """,
        (
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
            "%output/evidence/dynamic%",
            f"%{str(_legacy_abs_root())}%",
        ),
        fetch="all_dict",
    )
    return [dict(row) for row in rows or []]


def _dir_size_and_files(path: Path) -> tuple[int, int]:
    size = 0
    files = 0
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        files += 1
        try:
            size += item.stat().st_size
        except OSError:
            pass
    return size, files


def _collect_filesystem_alignment(run_sql: Any) -> list[dict[str, Any]]:
    root = _canonical_abs_root()
    rows = run_sql("SELECT dynamic_run_id FROM dynamic_sessions", fetch="all_dict") or []
    db_ids = {str(row.get("dynamic_run_id") or "").strip() for row in rows if str(row.get("dynamic_run_id") or "").strip()}
    fs_dirs = sorted([path for path in root.iterdir() if path.is_dir()], key=lambda p: p.name) if root.exists() else []
    fs_ids = {path.name for path in fs_dirs}
    records: list[dict[str, Any]] = []
    for path in fs_dirs:
        has_manifest = (path / "run_manifest.json").exists()
        in_progress = (path / "notes" / ".scytaledroid_in_progress").exists()
        size_bytes, file_count = _dir_size_and_files(path)
        if path.name in db_ids and has_manifest:
            classification = "db_backed_manifest"
        elif path.name in db_ids:
            classification = "db_backed_missing_manifest"
        elif in_progress and not has_manifest:
            classification = "filesystem_in_progress_no_manifest"
        elif has_manifest:
            classification = "filesystem_manifest_not_db"
        else:
            classification = "filesystem_orphan_no_manifest"
        records.append(
            {
                "dynamic_run_id": path.name,
                "path": str(path),
                "in_db": path.name in db_ids,
                "has_manifest": has_manifest,
                "in_progress_marker": in_progress,
                "file_count": file_count,
                "size_bytes": size_bytes,
                "classification": classification,
            }
        )
    for run_id in sorted(db_ids - fs_ids):
        records.append(
            {
                "dynamic_run_id": run_id,
                "path": str(root / run_id),
                "in_db": True,
                "has_manifest": False,
                "in_progress_marker": False,
                "file_count": 0,
                "size_bytes": 0,
                "classification": "db_missing_filesystem_dir",
            }
        )
    return records


def _counter_to_dict(counter: Counter[Any]) -> dict[str, int]:
    return {str(key): int(value) for key, value in sorted(counter.items(), key=lambda item: str(item[0]))}


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str] | None = None) -> None:
    effective_fieldnames = list(fieldnames or [
        "table_name",
        "id_column",
        "row_id",
        "path_column",
        "current_path",
        "normalized_path",
        "target_exists",
        "status",
        "reason",
        "applied",
        "rows_updated",
    ])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=effective_fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in effective_fieldnames})


def _write_run_id_list(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    run_ids = sorted({str(row.get("dynamic_run_id") or "").strip() for row in rows if str(row.get("dynamic_run_id") or "").strip()})
    path.write_text("".join(f"{run_id}\n" for run_id in run_ids), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    receipt_dir = args.receipt_dir / stamp
    receipt_dir.mkdir(parents=True, exist_ok=True)
    reference_roots = tuple(Path(root) for root in args.reference_root) if args.reference_root else _default_reference_roots()

    try:
        with database_session(reuse_connection=False):
            candidates = _collect_direct_path_candidates(core_q.run_sql, limit=int(args.limit or 0))
            json_legacy_rows = _count_json_legacy_rows(core_q.run_sql)
            missing_runs = _collect_missing_runs(core_q.run_sql)
            package_summary = _collect_package_summary(core_q.run_sql)
            filesystem_alignment = _collect_filesystem_alignment(core_q.run_sql)
            actions: list[dict[str, Any]]
            if args.apply:
                actions = _apply_candidates(core_q.run_sql_rowcount, candidates)
            else:
                actions = [{**candidate.__dict__, "applied": False, "rows_updated": 0} for candidate in candidates]
    except Exception as exc:
        sys.stderr.write(f"Dynamic evidence path migration audit failed: {exc}\n")
        return 2

    verified = [row for row in actions if row.get("status") == "candidate"]
    blocked = [row for row in actions if row.get("status") != "candidate"]
    reference_hits = _collect_reference_hits(
        [str(row.get("dynamic_run_id") or "") for row in missing_runs],
        reference_roots,
    )
    missing_runs = _annotate_missing_run_references(missing_runs, reference_hits)
    blocked_by_table = Counter(str(row.get("table_name") or "") for row in blocked)
    blocked_by_reason = Counter(str(row.get("reason") or "") for row in blocked)
    candidates_by_table = Counter(str(row.get("table_name") or "") for row in verified)
    missing_runs_by_status = Counter(str(row.get("status") or "") for row in missing_runs)
    missing_runs_by_classification = Counter(str(row.get("classification") or "") for row in missing_runs)
    filesystem_alignment_by_classification = Counter(str(row.get("classification") or "") for row in filesystem_alignment)
    summary: dict[str, Any] = {
        "mode": "apply" if args.apply else "dry_run",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "legacy_root": str(_legacy_abs_root()),
        "canonical_root": str(_canonical_abs_root()),
        "direct_path_rows": len(actions),
        "verified_rewrite_candidates": len(verified),
        "verified_rewrite_candidates_by_table": _counter_to_dict(candidates_by_table),
        "blocked_rows": len(blocked),
        "blocked_rows_by_table": _counter_to_dict(blocked_by_table),
        "blocked_rows_by_reason": _counter_to_dict(blocked_by_reason),
        "rows_updated": sum(int(row.get("rows_updated") or 0) for row in actions),
        "json_metadata_legacy_path_rows": json_legacy_rows,
        "missing_evidence_runs": len(missing_runs),
        "missing_evidence_runs_by_status": _counter_to_dict(missing_runs_by_status),
        "missing_evidence_runs_by_classification": _counter_to_dict(missing_runs_by_classification),
        "missing_evidence_package_status_rows": len(package_summary),
        "filesystem_alignment_rows": len(filesystem_alignment),
        "filesystem_alignment_by_classification": _counter_to_dict(filesystem_alignment_by_classification),
        "reference_roots": [str(root) for root in reference_roots],
        "receipts": {
            "summary": str(receipt_dir / "summary.json"),
            "candidates": str(receipt_dir / "candidates.csv"),
            "blocked": str(receipt_dir / "blocked.csv"),
            "missing_runs": str(receipt_dir / "missing_runs.csv"),
            "missing_run_ids": str(receipt_dir / "missing_run_ids.txt"),
            "package_summary": str(receipt_dir / "package_summary.csv"),
            "filesystem_alignment": str(receipt_dir / "filesystem_alignment.csv"),
        },
    }

    _write_json(receipt_dir / "summary.json", summary)
    _write_csv(receipt_dir / "candidates.csv", actions)
    _write_csv(receipt_dir / "blocked.csv", blocked)
    _write_csv(
        receipt_dir / "missing_runs.csv",
        missing_runs,
        [
            "dynamic_run_id",
            "package_name",
            "status",
            "evidence_path",
            "normalized_evidence_path",
            "normalized_target_exists",
            "legacy_artifact_rows",
            "reference_hit_count",
            "reference_hits",
            "referenced_by_local_publication_artifacts",
            "classification",
            "recommended_next_step",
        ],
    )
    _write_run_id_list(receipt_dir / "missing_run_ids.txt", missing_runs)
    _write_csv(
        receipt_dir / "package_summary.csv",
        package_summary,
        ["package_name", "status", "missing_session_rows", "missing_artifact_rows"],
    )
    _write_csv(
        receipt_dir / "filesystem_alignment.csv",
        filesystem_alignment,
        [
            "dynamic_run_id",
            "path",
            "in_db",
            "has_manifest",
            "in_progress_marker",
            "file_count",
            "size_bytes",
            "classification",
        ],
    )

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    else:
        print(f"mode: {summary['mode']}")
        print(f"direct_path_rows: {summary['direct_path_rows']}")
        print(f"verified_rewrite_candidates: {summary['verified_rewrite_candidates']}")
        print(f"blocked_rows: {summary['blocked_rows']}")
        print(f"missing_evidence_runs: {summary['missing_evidence_runs']}")
        print(f"rows_updated: {summary['rows_updated']}")
        print(f"json_metadata_legacy_path_rows: {summary['json_metadata_legacy_path_rows']}")
        print(f"receipt: {receipt_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
