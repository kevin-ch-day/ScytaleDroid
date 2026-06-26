"""Receipt-first dedupe helpers for static ``dep_snapshot`` artifact_registry rows."""

from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]


@dataclass(frozen=True)
class StaticDepSnapshotDedupeProposal:
    duplicate_group_count: int
    duplicate_row_count: int
    affected_run_count: int
    candidate_delete_ids: tuple[int, ...]
    keep_ids: tuple[int, ...]
    groups: tuple[dict[str, Any], ...]
    delete_rows: tuple[dict[str, Any], ...]
    artifact_type_counts: dict[str, int]
    path_family_counts: dict[str, int]


@dataclass(frozen=True)
class StaticDepSnapshotDedupeApplyResult:
    deleted_count: int
    duplicate_group_count_after: int
    duplicate_row_count_after: int


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _rows(run_sql: RunSql, sql: str, params: Sequence[Any] = (), *, query_name: str) -> list[dict[str, Any]]:
    out = run_sql(sql, tuple(params), fetch="all", dictionary=True, query_name=query_name) or []
    return [dict(row) for row in out if isinstance(row, Mapping)]


def _row(run_sql: RunSql, sql: str, params: Sequence[Any] = (), *, query_name: str) -> dict[str, Any]:
    out = run_sql(sql, tuple(params), fetch="one", dictionary=True, query_name=query_name) or {}
    return dict(out) if isinstance(out, Mapping) else {}


def _duplicate_group_summary(run_sql: RunSql) -> dict[str, int]:
    row = _row(
        run_sql,
        """
        SELECT
          COUNT(*) AS duplicate_group_count,
          COALESCE(SUM(rows_n - 1), 0) AS duplicate_row_count,
          COUNT(DISTINCT run_id) AS affected_run_count
        FROM (
          SELECT run_id, host_path, COUNT(*) AS rows_n
          FROM artifact_registry
          WHERE run_type = 'static'
            AND artifact_type = 'dep_snapshot'
            AND host_path IS NOT NULL
            AND TRIM(host_path) <> ''
          GROUP BY run_id, host_path
          HAVING COUNT(*) > 1
        ) d
        """,
        (),
        query_name="artifact_registry_static_dep_snapshot_dedupe.summary",
    )
    return {
        "duplicate_group_count": int(row.get("duplicate_group_count") or 0),
        "duplicate_row_count": int(row.get("duplicate_row_count") or 0),
        "affected_run_count": int(row.get("affected_run_count") or 0),
    }


def build_static_dep_snapshot_dedupe_proposal(run_sql: RunSql) -> StaticDepSnapshotDedupeProposal:
    group_rows = _rows(
        run_sql,
        """
        SELECT
          run_id,
          static_run_id,
          host_path,
          COUNT(*) AS rows_n,
          COUNT(DISTINCT sha256) AS distinct_sha256_count,
          MIN(created_at_utc) AS created_at_min_utc,
          MAX(created_at_utc) AS created_at_max_utc
        FROM artifact_registry
        WHERE run_type = 'static'
          AND artifact_type = 'dep_snapshot'
          AND host_path IS NOT NULL
          AND TRIM(host_path) <> ''
        GROUP BY run_id, static_run_id, host_path
        HAVING COUNT(*) > 1
        ORDER BY MAX(created_at_utc) DESC, run_id DESC, host_path DESC
        """,
        (),
        query_name="artifact_registry_static_dep_snapshot_dedupe.groups",
    )
    delete_rows = _rows(
        run_sql,
        """
        SELECT
          artifact_id,
          run_id,
          static_run_id,
          artifact_type,
          host_path,
          sha256,
          size_bytes,
          created_at_utc
        FROM (
          SELECT
            artifact_id,
            run_id,
            static_run_id,
            artifact_type,
            host_path,
            sha256,
            size_bytes,
            created_at_utc,
            ROW_NUMBER() OVER (
              PARTITION BY run_id, artifact_type, host_path
              ORDER BY created_at_utc DESC, artifact_id DESC
            ) AS row_rank
          FROM artifact_registry
          WHERE run_type = 'static'
            AND artifact_type = 'dep_snapshot'
            AND host_path IS NOT NULL
            AND TRIM(host_path) <> ''
        ) ranked
        WHERE row_rank > 1
        ORDER BY run_id DESC, host_path, created_at_utc DESC, artifact_id DESC
        """,
        (),
        query_name="artifact_registry_static_dep_snapshot_dedupe.delete_rows",
    )
    keep_rows = _rows(
        run_sql,
        """
        SELECT
          artifact_id,
          run_id,
          static_run_id,
          host_path
        FROM (
          SELECT
            artifact_id,
            run_id,
            static_run_id,
            host_path,
            ROW_NUMBER() OVER (
              PARTITION BY run_id, artifact_type, host_path
              ORDER BY created_at_utc DESC, artifact_id DESC
            ) AS row_rank
          FROM artifact_registry
          WHERE run_type = 'static'
            AND artifact_type = 'dep_snapshot'
            AND host_path IS NOT NULL
            AND TRIM(host_path) <> ''
        ) ranked
        WHERE row_rank = 1
          AND EXISTS (
            SELECT 1
            FROM artifact_registry ar2
            WHERE ar2.run_type = 'static'
              AND ar2.artifact_type = 'dep_snapshot'
              AND ar2.run_id = ranked.run_id
              AND ar2.host_path = ranked.host_path
            GROUP BY ar2.run_id, ar2.host_path
            HAVING COUNT(*) > 1
          )
        ORDER BY run_id DESC, host_path
        """,
        (),
        query_name="artifact_registry_static_dep_snapshot_dedupe.keep_rows",
    )
    summary = _duplicate_group_summary(run_sql)
    artifact_type_counts = Counter(_norm_text(row.get("artifact_type")) or "unknown" for row in delete_rows)
    path_family_counts = Counter()
    for row in delete_rows:
        path = _norm_text(row.get("host_path"))
        if "/evidence/static_runs/" in path and path.endswith("/dep.json"):
            path_family_counts["dep_snapshot"] += 1
        else:
            path_family_counts["other"] += 1
    return StaticDepSnapshotDedupeProposal(
        duplicate_group_count=summary["duplicate_group_count"],
        duplicate_row_count=summary["duplicate_row_count"],
        affected_run_count=summary["affected_run_count"],
        candidate_delete_ids=tuple(int(row.get("artifact_id") or 0) for row in delete_rows),
        keep_ids=tuple(int(row.get("artifact_id") or 0) for row in keep_rows),
        groups=tuple(group_rows),
        delete_rows=tuple(delete_rows),
        artifact_type_counts=dict(sorted(artifact_type_counts.items())),
        path_family_counts=dict(sorted(path_family_counts.items())),
    )


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


def write_static_dep_snapshot_dedupe_receipt(
    receipt_dir: Path,
    *,
    proposal: StaticDepSnapshotDedupeProposal,
    deleted_count: int | None,
) -> dict[str, str]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"artifact_registry_static_dep_snapshot_dedupe_{stamp}"
    json_path = receipt_dir / f"{stem}.json"
    groups_csv = receipt_dir / f"{stem}_groups.csv"
    delete_csv = receipt_dir / f"{stem}_delete_rows.csv"
    sql_path = receipt_dir / f"{stem}.sql"
    payload = {
        "format": "scytaledroid.artifact_registry_static_dep_snapshot_dedupe_receipt.v1",
        "generated_utc": stamp,
        "duplicate_group_count": proposal.duplicate_group_count,
        "duplicate_row_count": proposal.duplicate_row_count,
        "affected_run_count": proposal.affected_run_count,
        "candidate_delete_ids": list(proposal.candidate_delete_ids),
        "keep_ids": list(proposal.keep_ids),
        "artifact_type_counts": proposal.artifact_type_counts,
        "path_family_counts": proposal.path_family_counts,
        "deleted_count": deleted_count,
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    _write_csv(groups_csv, proposal.groups)
    _write_csv(delete_csv, proposal.delete_rows)
    lines = [
        "-- ScytaleDroid artifact_registry static dep_snapshot dedupe receipt",
        f"-- generated_utc: {stamp}",
        f"-- duplicate_group_count: {proposal.duplicate_group_count}",
        f"-- duplicate_row_count: {proposal.duplicate_row_count}",
        "-- keep newest created_at_utc / artifact_id per (run_id, artifact_type, host_path)",
        "",
    ]
    ids = list(proposal.candidate_delete_ids)
    for i in range(0, len(ids), 200):
        batch = ",".join(str(int(x)) for x in ids[i : i + 200])
        lines.append(f"DELETE FROM artifact_registry WHERE artifact_id IN ({batch});")
    sql_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "json": str(json_path),
        "groups_csv": str(groups_csv),
        "delete_rows_csv": str(delete_csv),
        "sql": str(sql_path),
    }


def _delete_ids(run_sql_rowcount: RunSqlRowcount, artifact_ids: Sequence[int], *, chunk_size: int = 200) -> int:
    deleted = 0
    ids = [int(value) for value in artifact_ids]
    for i in range(0, len(ids), chunk_size):
        batch = ids[i : i + chunk_size]
        placeholders = ",".join(["%s"] * len(batch))
        deleted += int(
            run_sql_rowcount(
                f"DELETE FROM artifact_registry WHERE artifact_id IN ({placeholders})",
                tuple(batch),
                query_name="artifact_registry_static_dep_snapshot_dedupe.delete_batch",
            )
        )
    return deleted


def apply_static_dep_snapshot_dedupe(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    receipt_dir: Path | None,
    apply: bool,
) -> tuple[StaticDepSnapshotDedupeProposal, StaticDepSnapshotDedupeApplyResult | None, dict[str, str]]:
    proposal = build_static_dep_snapshot_dedupe_proposal(run_sql)
    if proposal.duplicate_row_count > 0 and receipt_dir is None:
        raise ValueError("receipt_dir is required when duplicate dep_snapshot rows exist")
    deleted_count = None
    result = None
    if apply and proposal.candidate_delete_ids:
        deleted_count = _delete_ids(run_sql_rowcount, proposal.candidate_delete_ids)
        after = _duplicate_group_summary(run_sql)
        result = StaticDepSnapshotDedupeApplyResult(
            deleted_count=deleted_count,
            duplicate_group_count_after=after["duplicate_group_count"],
            duplicate_row_count_after=after["duplicate_row_count"],
        )
    receipt_paths = (
        write_static_dep_snapshot_dedupe_receipt(receipt_dir, proposal=proposal, deleted_count=deleted_count)
        if receipt_dir is not None
        else {}
    )
    return proposal, result, receipt_paths


__all__ = [
    "StaticDepSnapshotDedupeApplyResult",
    "StaticDepSnapshotDedupeProposal",
    "apply_static_dep_snapshot_dedupe",
    "build_static_dep_snapshot_dedupe_proposal",
    "write_static_dep_snapshot_dedupe_receipt",
]
