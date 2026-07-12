"""Receipt-first cleanup proposal for exact-hash file-present static rows.

This targets only detached static ``artifact_registry`` rows whose host files
still exist but whose APK identity is covered by a canonical static run with
the same base APK SHA-256. It never deletes files and never touches static
analysis tables.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifact_registry_static_file_present_detached import (
    collect_static_file_present_detached_report,
)

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]

_STEM_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
TARGET_STAGED_ACTION = "STAGE_EXACT_HASH_REGISTRY_RESOLUTION_REVIEW"
TARGET_COVERAGE_CLASS = "COVERED_BY_CANONICAL_SAME_HASH"


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, "", 0, "0", "false", "False", "FALSE"):
        return False
    return bool(value)


def _sanitize_receipt_stem(stem: str) -> str:
    s = str(stem or "").strip() or "artifact_registry_static_file_present_resolution"
    return _STEM_SAFE.sub("_", s)[:200]


def _count_artifact_registry_rows(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS c FROM artifact_registry",
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_static_file_present_resolution.total_count",
    ) or {}
    return int(row.get("c") or 0) if isinstance(row, Mapping) else 0


def _count_static_dangling_rows(run_sql: RunSql) -> int:
    row = run_sql(
        """
        SELECT COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE run_type = 'static'
          AND link_state = 'dangling_static_run'
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_static_file_present_resolution.static_dangling_count",
    ) or {}
    return int(row.get("c") or 0) if isinstance(row, Mapping) else 0


def _delete_artifact_ids(run_sql_rowcount: RunSqlRowcount, artifact_ids: Sequence[int], *, chunk_size: int = 200) -> int:
    deleted = 0
    ids = [int(x) for x in artifact_ids]
    for i in range(0, len(ids), chunk_size):
        batch = ids[i : i + chunk_size]
        placeholders = ",".join(["%s"] * len(batch))
        deleted += int(
            run_sql_rowcount(
                f"DELETE FROM artifact_registry WHERE artifact_id IN ({placeholders})",
                tuple(batch),
                query_name="artifact_registry_static_file_present_resolution.delete_batch",
            )
        )
    return deleted


@dataclass(frozen=True)
class StaticFilePresentResolutionProposal:
    total_rows_before: int
    static_dangling_before: int
    targeted_row_count: int
    targeted_distinct_static_run_ids: int
    targeted_distinct_packages: int
    targeted_artifact_ids: tuple[int, ...]
    targeted_static_run_ids: tuple[int, ...]
    staged_action: str
    canonical_coverage_class: str
    artifact_type_counts: dict[str, int]
    path_family_counts: dict[str, int]
    package_counts: dict[str, int]
    oldest_created_at_utc: str | None
    newest_created_at_utc: str | None
    all_host_files_present: bool
    all_same_hash_covered: bool
    all_have_canonical_match: bool
    all_registry_resolution_candidates: bool
    expected_count_match: bool | None
    sample_rows: tuple[dict[str, Any], ...]
    target_rows: tuple[dict[str, Any], ...]
    exact_sql_predicate: str
    apply_delete_sql: str


@dataclass(frozen=True)
class StaticFilePresentResolutionApplyResult:
    deleted_count: int
    total_rows_after: int
    static_dangling_after: int


def build_static_file_present_resolution_proposal(
    run_sql: RunSql,
    *,
    repo_root: Path,
    expected_count: int | None = None,
) -> StaticFilePresentResolutionProposal:
    report = collect_static_file_present_detached_report(run_sql, repo_root=repo_root)
    rows = [dict(row) for row in (report.get("file_present_detached_rows") or []) if isinstance(row, Mapping)]
    targeted = [
        row
        for row in rows
        if _norm_text(row.get("staged_review_action")) == TARGET_STAGED_ACTION
        and _norm_text(row.get("canonical_coverage_class")) == TARGET_COVERAGE_CLASS
        and _norm_bool(row.get("registry_resolution_candidate"))
    ]
    targeted.sort(key=lambda row: (str(row.get("created_at_utc") or ""), int(row.get("artifact_id") or 0)))

    total_rows_before = _count_artifact_registry_rows(run_sql)
    static_dangling_before = _count_static_dangling_rows(run_sql)
    artifact_type_counts = Counter(_norm_text(row.get("artifact_type")) or "(blank)" for row in targeted)
    path_family_counts = Counter(_norm_text(row.get("host_path_family")) or "(blank)" for row in targeted)
    package_counts = Counter(_norm_text(row.get("inferred_package_name")) or "(unknown)" for row in targeted)
    artifact_ids = tuple(int(row.get("artifact_id") or 0) for row in targeted)
    static_run_ids = tuple(sorted({int(row.get("resolved_static_run_id")) for row in targeted if row.get("resolved_static_run_id") is not None}))
    created_values = [str(row.get("created_at_utc")) for row in targeted if row.get("created_at_utc")]
    exact_sql_predicate = (
        "artifact_registry row is static dangling/file-present detached; "
        f"staged_review_action = {TARGET_STAGED_ACTION!r}; "
        f"canonical_coverage_class = {TARGET_COVERAGE_CLASS!r}; "
        "registry_resolution_candidate = true"
    )
    sample_rows = tuple(
        {
            "artifact_id": row.get("artifact_id"),
            "resolved_static_run_id": row.get("resolved_static_run_id"),
            "artifact_type": row.get("artifact_type"),
            "inferred_package_name": row.get("inferred_package_name"),
            "inferred_version_code": row.get("inferred_version_code"),
            "canonical_match_static_run_id": row.get("canonical_match_static_run_id"),
            "host_path": row.get("host_path"),
        }
        for row in targeted[:12]
    )
    return StaticFilePresentResolutionProposal(
        total_rows_before=total_rows_before,
        static_dangling_before=static_dangling_before,
        targeted_row_count=len(targeted),
        targeted_distinct_static_run_ids=len(static_run_ids),
        targeted_distinct_packages=len(package_counts),
        targeted_artifact_ids=artifact_ids,
        targeted_static_run_ids=static_run_ids,
        staged_action=TARGET_STAGED_ACTION,
        canonical_coverage_class=TARGET_COVERAGE_CLASS,
        artifact_type_counts=dict(sorted(artifact_type_counts.items())),
        path_family_counts=dict(sorted(path_family_counts.items())),
        package_counts=dict(sorted(package_counts.items())),
        oldest_created_at_utc=min(created_values) if created_values else None,
        newest_created_at_utc=max(created_values) if created_values else None,
        all_host_files_present=all(row.get("host_path_exists") is True for row in targeted),
        all_same_hash_covered=all(_norm_text(row.get("canonical_coverage_class")) == TARGET_COVERAGE_CLASS for row in targeted),
        all_have_canonical_match=all(_norm_text(row.get("canonical_match_static_run_id")) for row in targeted),
        all_registry_resolution_candidates=all(_norm_bool(row.get("registry_resolution_candidate")) for row in targeted),
        expected_count_match=(len(targeted) == int(expected_count)) if expected_count is not None else None,
        sample_rows=sample_rows,
        target_rows=tuple(targeted),
        exact_sql_predicate=exact_sql_predicate,
        apply_delete_sql="DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)",
    )


def validate_static_file_present_resolution_proposal(
    proposal: StaticFilePresentResolutionProposal,
    *,
    expected_count: int | None = None,
) -> None:
    if proposal.targeted_row_count <= 0:
        raise ValueError("no exact-hash file-present static registry resolution candidates")
    if expected_count is not None and proposal.targeted_row_count != int(expected_count):
        raise ValueError(
            f"expected {int(expected_count)} target rows but proposal found {proposal.targeted_row_count}"
        )
    if not proposal.all_host_files_present:
        raise ValueError("proposal includes at least one row whose host file is not present")
    if not proposal.all_same_hash_covered:
        raise ValueError("proposal includes at least one row without same-hash canonical coverage")
    if not proposal.all_have_canonical_match:
        raise ValueError("proposal includes at least one row without a canonical static run match")
    if not proposal.all_registry_resolution_candidates:
        raise ValueError("proposal includes at least one row not marked as registry resolution candidate")
    if any(int(artifact_id) <= 0 for artifact_id in proposal.targeted_artifact_ids):
        raise ValueError("proposal contains invalid artifact_id values")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


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


def _write_sql(path: Path, *, artifact_ids: Sequence[int], static_run_ids: Sequence[int], meta: Mapping[str, Any]) -> None:
    lines = [
        "-- ScytaleDroid artifact_registry static file-present resolution receipt",
        f"-- generated_utc: {meta.get('generated_utc')}",
        f"-- targeted_row_count: {meta.get('targeted_row_count')}",
        f"-- targeted_distinct_static_run_ids: {meta.get('targeted_distinct_static_run_ids')}",
        f"-- staged_action: {meta.get('staged_action')}",
        f"-- canonical_coverage_class: {meta.get('canonical_coverage_class')}",
        "-- delete scope: artifact_registry only",
        "-- no files deleted; no static/session tables touched",
        "",
        "-- targeted static_run_id values:",
    ]
    for run_id in static_run_ids:
        lines.append(f"--   {run_id}")
    lines.append("")
    for i in range(0, len(artifact_ids), 200):
        batch = ",".join(str(int(x)) for x in artifact_ids[i : i + 200])
        lines.append(f"DELETE FROM artifact_registry WHERE artifact_id IN ({batch});")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_run_ids(path: Path, run_ids: Sequence[int]) -> None:
    text = "\n".join(str(run_id) for run_id in run_ids)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_static_file_present_resolution_receipts(
    receipt_dir: Path,
    *,
    stem: str,
    proposal: StaticFilePresentResolutionProposal,
    apply_requested: bool,
    apply_result: StaticFilePresentResolutionApplyResult | None = None,
) -> dict[str, str]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_receipt_stem(stem)
    json_path = receipt_dir / f"{base}.json"
    csv_path = receipt_dir / f"{base}.csv"
    sql_path = receipt_dir / f"{base}.sql"
    stamp = base.removeprefix("artifact_registry_static_file_present_resolution_")
    txt_path = receipt_dir / f"artifact_registry_static_file_present_resolution_run_ids_{stamp}.txt"

    meta = {
        "generated_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "apply_requested": bool(apply_requested),
        "total_artifact_registry_rows_before": proposal.total_rows_before,
        "static_dangling_rows_before": proposal.static_dangling_before,
        "targeted_row_count": proposal.targeted_row_count,
        "targeted_distinct_static_run_ids": proposal.targeted_distinct_static_run_ids,
        "targeted_distinct_packages": proposal.targeted_distinct_packages,
        "staged_action": proposal.staged_action,
        "canonical_coverage_class": proposal.canonical_coverage_class,
        "artifact_type_counts": proposal.artifact_type_counts,
        "path_family_counts": proposal.path_family_counts,
        "oldest_created_at_utc": proposal.oldest_created_at_utc,
        "newest_created_at_utc": proposal.newest_created_at_utc,
        "all_host_files_present": proposal.all_host_files_present,
        "all_same_hash_covered": proposal.all_same_hash_covered,
        "all_have_canonical_match": proposal.all_have_canonical_match,
        "all_registry_resolution_candidates": proposal.all_registry_resolution_candidates,
        "expected_count_match": proposal.expected_count_match,
        "exact_sql_predicate": proposal.exact_sql_predicate,
        "apply_delete_sql": proposal.apply_delete_sql,
    }
    if apply_result is not None:
        meta.update(
            {
                "deleted_count": apply_result.deleted_count,
                "total_artifact_registry_rows_after": apply_result.total_rows_after,
                "static_dangling_rows_after": apply_result.static_dangling_after,
            }
        )

    payload = {
        "format": "scytaledroid.artifact_registry_static_file_present_resolution_receipt.v1",
        "meta": meta,
        "sample_rows": list(proposal.sample_rows),
    }
    _write_json(json_path, payload)
    _write_csv(csv_path, proposal.target_rows)
    _write_sql(
        sql_path,
        artifact_ids=proposal.targeted_artifact_ids,
        static_run_ids=proposal.targeted_static_run_ids,
        meta=meta,
    )
    _write_run_ids(txt_path, proposal.targeted_static_run_ids)
    return {
        "json": str(json_path),
        "csv": str(csv_path),
        "sql": str(sql_path),
        "run_ids": str(txt_path),
    }


def apply_static_file_present_resolution(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    proposal: StaticFilePresentResolutionProposal,
) -> StaticFilePresentResolutionApplyResult:
    deleted = _delete_artifact_ids(run_sql_rowcount, proposal.targeted_artifact_ids)
    return StaticFilePresentResolutionApplyResult(
        deleted_count=deleted,
        total_rows_after=_count_artifact_registry_rows(run_sql),
        static_dangling_after=_count_static_dangling_rows(run_sql),
    )


__all__ = [
    "TARGET_COVERAGE_CLASS",
    "TARGET_STAGED_ACTION",
    "StaticFilePresentResolutionApplyResult",
    "StaticFilePresentResolutionProposal",
    "apply_static_file_present_resolution",
    "build_static_file_present_resolution_proposal",
    "validate_static_file_present_resolution_proposal",
    "write_static_file_present_resolution_receipts",
]
