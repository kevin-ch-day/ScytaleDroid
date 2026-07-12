"""Receipt-first prune for reviewed file-present detached static registry rows.

This is intentionally narrower than the generic dangling registry prune.  It
targets only static ``artifact_registry`` rows that are already classified by
the file-present detached audit as stale registry ledger rows.  It never
deletes host files and never touches static analysis result tables.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .artifact_registry_static_file_present_detached import (
    collect_static_file_present_detached_report,
)

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]

_STEM_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
PRIOR_VERSION_ACTION = "STAGE_PRIOR_VERSION_RETENTION_REVIEW"
IDENTITY_GAP_ACTION = "STAGE_IDENTITY_GAP_OR_HISTORICAL_REVIEW"
ACTION_COVERAGE_CLASSES = {
    PRIOR_VERSION_ACTION: "SUPERSEDED_BY_NEWER_CANONICAL_VERSION",
    IDENTITY_GAP_ACTION: "PACKAGE_HAS_CANONICAL_DIFFERENT_VERSION",
}


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, "", 0, "0", "false", "False", "FALSE"):
        return False
    return bool(value)


def _parse_utc(value: Any) -> datetime | None:
    text = _norm_text(value)
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y%m%dT%H%M%SZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _sanitize_receipt_stem(stem: str) -> str:
    s = str(stem or "").strip() or "artifact_registry_static_file_present_review_prune"
    return _STEM_SAFE.sub("_", s)[:200]


def _count_artifact_registry_rows(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS c FROM artifact_registry",
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_static_file_present_review_prune.total_count",
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
        query_name="artifact_registry_static_file_present_review_prune.static_dangling_count",
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
                query_name="artifact_registry_static_file_present_review_prune.delete_batch",
            )
        )
    return deleted


@dataclass(frozen=True)
class StaticFilePresentReviewPruneProposal:
    total_rows_before: int
    static_dangling_before: int
    targeted_row_count: int
    targeted_distinct_static_run_ids: int
    targeted_distinct_packages: int
    targeted_artifact_ids: tuple[int, ...]
    targeted_static_run_ids: tuple[int, ...]
    selected_staged_actions: tuple[str, ...]
    min_age_days: int
    cutoff_utc: str
    artifact_type_counts: dict[str, int]
    path_family_counts: dict[str, int]
    package_counts: dict[str, int]
    staged_action_counts: dict[str, int]
    coverage_class_counts: dict[str, int]
    oldest_created_at_utc: str | None
    newest_created_at_utc: str | None
    all_host_files_present: bool
    all_file_present_detached: bool
    all_action_coverage_consistent: bool
    all_missing_static_run: bool
    all_older_than_cutoff: bool
    expected_count_match: bool | None
    sample_rows: tuple[dict[str, Any], ...]
    target_rows: tuple[dict[str, Any], ...]
    exact_sql_predicate: str
    apply_delete_sql: str


@dataclass(frozen=True)
class StaticFilePresentReviewPruneApplyResult:
    deleted_count: int
    total_rows_after: int
    static_dangling_after: int


def build_static_file_present_review_prune_proposal(
    run_sql: RunSql,
    *,
    repo_root: Path,
    allow_prior_version: bool = False,
    allow_identity_gap: bool = False,
    min_age_days: int = 30,
    expected_count: int | None = None,
    now_utc: datetime | None = None,
) -> StaticFilePresentReviewPruneProposal:
    selected_actions: list[str] = []
    if allow_prior_version:
        selected_actions.append(PRIOR_VERSION_ACTION)
    if allow_identity_gap:
        selected_actions.append(IDENTITY_GAP_ACTION)
    now = (now_utc or datetime.now(UTC)).astimezone(UTC)
    cutoff = now - timedelta(days=max(0, int(min_age_days)))

    report = collect_static_file_present_detached_report(run_sql, repo_root=repo_root)
    rows = [dict(row) for row in (report.get("file_present_detached_rows") or []) if isinstance(row, Mapping)]
    targeted: list[dict[str, Any]] = []
    for row in rows:
        action = _norm_text(row.get("staged_review_action"))
        if action not in selected_actions:
            continue
        created = _parse_utc(row.get("created_at_utc"))
        if created is None or created > cutoff:
            continue
        targeted.append(row)
    targeted.sort(key=lambda row: (str(row.get("created_at_utc") or ""), int(row.get("artifact_id") or 0)))

    total_rows_before = _count_artifact_registry_rows(run_sql)
    static_dangling_before = _count_static_dangling_rows(run_sql)
    artifact_type_counts = Counter(_norm_text(row.get("artifact_type")) or "(blank)" for row in targeted)
    path_family_counts = Counter(_norm_text(row.get("host_path_family")) or "(blank)" for row in targeted)
    package_counts = Counter(_norm_text(row.get("inferred_package_name")) or "(unknown)" for row in targeted)
    staged_action_counts = Counter(_norm_text(row.get("staged_review_action")) or "(blank)" for row in targeted)
    coverage_class_counts = Counter(_norm_text(row.get("canonical_coverage_class")) or "(blank)" for row in targeted)
    artifact_ids = tuple(int(row.get("artifact_id") or 0) for row in targeted)
    static_run_ids = tuple(sorted({int(row.get("resolved_static_run_id")) for row in targeted if row.get("resolved_static_run_id") is not None}))
    created_values = [str(row.get("created_at_utc")) for row in targeted if row.get("created_at_utc")]

    def _action_coverage_ok(row: Mapping[str, Any]) -> bool:
        action = _norm_text(row.get("staged_review_action"))
        return _norm_text(row.get("canonical_coverage_class")) == ACTION_COVERAGE_CLASSES.get(action, "")

    sample_rows = tuple(
        {
            "artifact_id": row.get("artifact_id"),
            "resolved_static_run_id": row.get("resolved_static_run_id"),
            "artifact_type": row.get("artifact_type"),
            "inferred_package_name": row.get("inferred_package_name"),
            "inferred_version_code": row.get("inferred_version_code"),
            "canonical_coverage_class": row.get("canonical_coverage_class"),
            "staged_review_action": row.get("staged_review_action"),
            "created_at_utc": row.get("created_at_utc"),
            "host_path": row.get("host_path"),
        }
        for row in targeted[:12]
    )
    return StaticFilePresentReviewPruneProposal(
        total_rows_before=total_rows_before,
        static_dangling_before=static_dangling_before,
        targeted_row_count=len(targeted),
        targeted_distinct_static_run_ids=len(static_run_ids),
        targeted_distinct_packages=len(package_counts),
        targeted_artifact_ids=artifact_ids,
        targeted_static_run_ids=static_run_ids,
        selected_staged_actions=tuple(selected_actions),
        min_age_days=max(0, int(min_age_days)),
        cutoff_utc=cutoff.strftime("%Y-%m-%d %H:%M:%S"),
        artifact_type_counts=dict(sorted(artifact_type_counts.items())),
        path_family_counts=dict(sorted(path_family_counts.items())),
        package_counts=dict(sorted(package_counts.items())),
        staged_action_counts=dict(sorted(staged_action_counts.items())),
        coverage_class_counts=dict(sorted(coverage_class_counts.items())),
        oldest_created_at_utc=min(created_values) if created_values else None,
        newest_created_at_utc=max(created_values) if created_values else None,
        all_host_files_present=all(row.get("host_path_exists") is True for row in targeted),
        all_file_present_detached=all(_norm_text(row.get("primary_reason")) == "file_present_db_detached" for row in targeted),
        all_action_coverage_consistent=all(_action_coverage_ok(row) for row in targeted),
        all_missing_static_run=all(_norm_bool(row.get("missing_static_run")) for row in targeted),
        all_older_than_cutoff=all((_parse_utc(row.get("created_at_utc")) or now) <= cutoff for row in targeted),
        expected_count_match=(len(targeted) == int(expected_count)) if expected_count is not None else None,
        sample_rows=sample_rows,
        target_rows=tuple(targeted),
        exact_sql_predicate=(
            "artifact_registry row is static dangling/file-present detached; "
            f"staged_review_action IN {tuple(selected_actions)!r}; "
            f"created_at_utc <= {cutoff.strftime('%Y-%m-%d %H:%M:%S')!r}; "
            "host file retained; artifact_registry row only"
        ),
        apply_delete_sql="DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)",
    )


def validate_static_file_present_review_prune_proposal(
    proposal: StaticFilePresentReviewPruneProposal,
    *,
    expected_count: int | None = None,
) -> None:
    if not proposal.selected_staged_actions:
        raise ValueError("no reviewed file-present staged actions were selected")
    if proposal.targeted_row_count <= 0:
        raise ValueError("no reviewed file-present static registry prune candidates")
    if expected_count is not None and proposal.targeted_row_count != int(expected_count):
        raise ValueError(
            f"expected {int(expected_count)} target rows but proposal found {proposal.targeted_row_count}"
        )
    if not proposal.all_host_files_present:
        raise ValueError("proposal includes at least one row whose host file is not present")
    if not proposal.all_file_present_detached:
        raise ValueError("proposal includes at least one row not classified as file_present_db_detached")
    if not proposal.all_action_coverage_consistent:
        raise ValueError("proposal includes at least one row whose action/coverage class is inconsistent")
    if not proposal.all_missing_static_run:
        raise ValueError("proposal includes at least one row that is not missing its static run")
    if not proposal.all_older_than_cutoff:
        raise ValueError("proposal includes at least one row newer than the selected age cutoff")
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
        "-- ScytaleDroid artifact_registry reviewed file-present detached prune receipt",
        f"-- generated_utc: {meta.get('generated_utc')}",
        f"-- targeted_row_count: {meta.get('targeted_row_count')}",
        f"-- targeted_distinct_static_run_ids: {meta.get('targeted_distinct_static_run_ids')}",
        f"-- selected_staged_actions: {meta.get('selected_staged_actions')}",
        f"-- cutoff_utc: {meta.get('cutoff_utc')}",
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


def write_static_file_present_review_prune_receipts(
    receipt_dir: Path,
    *,
    stem: str,
    proposal: StaticFilePresentReviewPruneProposal,
    apply_requested: bool,
    apply_result: StaticFilePresentReviewPruneApplyResult | None = None,
) -> dict[str, str]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_receipt_stem(stem)
    json_path = receipt_dir / f"{base}.json"
    csv_path = receipt_dir / f"{base}.csv"
    sql_path = receipt_dir / f"{base}.sql"
    stamp = base.removeprefix("artifact_registry_static_file_present_review_prune_")
    txt_path = receipt_dir / f"artifact_registry_static_file_present_review_prune_run_ids_{stamp}.txt"

    meta: dict[str, Any] = {
        "generated_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "apply_requested": bool(apply_requested),
        "total_artifact_registry_rows_before": proposal.total_rows_before,
        "static_dangling_rows_before": proposal.static_dangling_before,
        "targeted_row_count": proposal.targeted_row_count,
        "targeted_distinct_static_run_ids": proposal.targeted_distinct_static_run_ids,
        "targeted_distinct_packages": proposal.targeted_distinct_packages,
        "selected_staged_actions": list(proposal.selected_staged_actions),
        "min_age_days": proposal.min_age_days,
        "cutoff_utc": proposal.cutoff_utc,
        "artifact_type_counts": proposal.artifact_type_counts,
        "path_family_counts": proposal.path_family_counts,
        "package_counts": proposal.package_counts,
        "staged_action_counts": proposal.staged_action_counts,
        "coverage_class_counts": proposal.coverage_class_counts,
        "oldest_created_at_utc": proposal.oldest_created_at_utc,
        "newest_created_at_utc": proposal.newest_created_at_utc,
        "all_host_files_present": proposal.all_host_files_present,
        "all_file_present_detached": proposal.all_file_present_detached,
        "all_action_coverage_consistent": proposal.all_action_coverage_consistent,
        "all_missing_static_run": proposal.all_missing_static_run,
        "all_older_than_cutoff": proposal.all_older_than_cutoff,
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
        "format": "scytaledroid.artifact_registry_static_file_present_review_prune_receipt.v1",
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


def apply_static_file_present_review_prune(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    proposal: StaticFilePresentReviewPruneProposal,
) -> StaticFilePresentReviewPruneApplyResult:
    deleted = _delete_artifact_ids(run_sql_rowcount, proposal.targeted_artifact_ids)
    return StaticFilePresentReviewPruneApplyResult(
        deleted_count=deleted,
        total_rows_after=_count_artifact_registry_rows(run_sql),
        static_dangling_after=_count_static_dangling_rows(run_sql),
    )


__all__ = [
    "IDENTITY_GAP_ACTION",
    "PRIOR_VERSION_ACTION",
    "StaticFilePresentReviewPruneApplyResult",
    "StaticFilePresentReviewPruneProposal",
    "apply_static_file_present_review_prune",
    "build_static_file_present_review_prune_proposal",
    "validate_static_file_present_review_prune_proposal",
    "write_static_file_present_review_prune_receipts",
]
