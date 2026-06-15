"""Receipt-first prune helpers for detached static ``artifact_registry`` rows.

This workflow is intentionally narrow:

- only ``artifact_registry`` rows
- only ``static`` rows
- only rows already classified by the static dangling audit as detached buckets
- no file deletes
- no writes to static/session/evidence tables
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

from .artifact_registry_static_dangling import collect_artifact_registry_static_dangling_report

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]

_STEM_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_INCLUDED_REASONS: tuple[str, ...] = ("truly_detached",)
ALLOWED_INCLUDED_REASONS: tuple[str, ...] = ("truly_detached", "legacy_mirror_only_file_missing")


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _norm_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, "", 0, "0", "false", "False", "FALSE"):
        return False
    return bool(value)


def _sanitize_receipt_stem(stem: str) -> str:
    s = str(stem or "").strip() or "artifact_registry_static_prune"
    return _STEM_SAFE.sub("_", s)[:200]


def count_artifact_registry_rows(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS c FROM artifact_registry",
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_static_prune.total_count",
    ) or {}
    if isinstance(row, Mapping):
        return int(row.get("c") or 0)
    return 0


def count_static_dangling_rows(run_sql: RunSql) -> int:
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
        query_name="artifact_registry_static_prune.static_dangling_count",
    ) or {}
    if isinstance(row, Mapping):
        return int(row.get("c") or 0)
    return 0


def count_dynamic_dangling_rows(run_sql: RunSql) -> int:
    row = run_sql(
        """
        SELECT COUNT(*) AS c
        FROM v_artifact_registry_integrity
        WHERE run_type = 'dynamic'
          AND link_state = 'dangling_dynamic_run'
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_static_prune.dynamic_dangling_count",
    ) or {}
    if isinstance(row, Mapping):
        return int(row.get("c") or 0)
    return 0


def _delete_artifact_ids(run_sql_rowcount: RunSqlRowcount, artifact_ids: Sequence[int], *, chunk_size: int = 200) -> int:
    deleted = 0
    ids = list(int(x) for x in artifact_ids)
    for i in range(0, len(ids), chunk_size):
        batch = ids[i : i + chunk_size]
        placeholders = ",".join(["%s"] * len(batch))
        deleted += int(
            run_sql_rowcount(
                f"DELETE FROM artifact_registry WHERE artifact_id IN ({placeholders})",
                tuple(batch),
                query_name="artifact_registry_static_prune.delete_batch",
            )
        )
    return deleted


def _normalize_included_reasons(include_primary_reasons: Sequence[str] | None) -> tuple[str, ...]:
    reasons = tuple(dict.fromkeys(_norm_text(reason) for reason in (include_primary_reasons or DEFAULT_INCLUDED_REASONS) if _norm_text(reason)))
    if not reasons:
        return DEFAULT_INCLUDED_REASONS
    invalid = [reason for reason in reasons if reason not in ALLOWED_INCLUDED_REASONS]
    if invalid:
        raise ValueError(
            "unsupported static prune reason(s): "
            + ", ".join(sorted(invalid))
            + " (allowed: "
            + ", ".join(ALLOWED_INCLUDED_REASONS)
            + ")"
        )
    return reasons


@dataclass(frozen=True)
class StaticPruneProposal:
    total_rows_before: int
    static_dangling_before: int
    dynamic_dangling_before: int
    targeted_row_count: int
    targeted_distinct_static_run_ids: int
    targeted_static_run_ids: tuple[int, ...]
    targeted_artifact_ids: tuple[int, ...]
    included_primary_reasons: tuple[str, ...]
    reason_counts: dict[str, int]
    artifact_type_counts: dict[str, int]
    path_family_counts: dict[str, int]
    oldest_created_at_utc: str | None
    newest_created_at_utc: str | None
    all_missing_static_run: bool
    all_target_files_missing: bool
    all_missing_canonical_refs: bool
    all_missing_legacy_runs_overlap: bool
    canonical_db_residue_count: int
    legacy_runs_overlap_count: int
    host_file_present_count: int
    sample_rows: tuple[dict[str, Any], ...]
    target_rows: tuple[dict[str, Any], ...]
    exact_sql_predicate: str
    apply_delete_sql: str
    expected_count_match: bool | None


@dataclass(frozen=True)
class StaticPruneApplyResult:
    deleted_count: int
    total_rows_after: int
    static_dangling_after: int
    dynamic_dangling_after: int


def build_static_prune_proposal(
    run_sql: RunSql,
    *,
    repo_root: Path,
    include_primary_reasons: Sequence[str] | None = None,
    expected_count: int | None = None,
) -> StaticPruneProposal:
    included_reasons = _normalize_included_reasons(include_primary_reasons)
    report = collect_artifact_registry_static_dangling_report(run_sql, repo_root=repo_root)
    rows = [dict(row) for row in (report.get("static_dangling_rows") or []) if isinstance(row, Mapping)]
    targeted = [row for row in rows if _norm_text_or_none(row.get("primary_reason")) in included_reasons]
    targeted.sort(key=lambda row: (str(row.get("created_at_utc") or ""), int(row.get("artifact_id") or 0)))

    total_rows_before = count_artifact_registry_rows(run_sql)
    static_dangling_before = count_static_dangling_rows(run_sql)
    dynamic_dangling_before = count_dynamic_dangling_rows(run_sql)
    artifact_type_counts = Counter(_norm_text_or_none(row.get("artifact_type")) or "(blank)" for row in targeted)
    path_family_counts = Counter(_norm_text_or_none(row.get("host_path_family")) or "(blank)" for row in targeted)
    reason_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in targeted)
    targeted_static_run_ids = tuple(sorted({int(row.get("resolved_static_run_id")) for row in targeted if row.get("resolved_static_run_id") is not None}))
    targeted_artifact_ids = tuple(int(row.get("artifact_id") or 0) for row in targeted)
    created_values = [str(row.get("created_at_utc")) for row in targeted if row.get("created_at_utc")]
    canonical_residue_count = sum(1 for row in targeted if _norm_bool(row.get("canonical_db_reference_present")))
    legacy_overlap_count = sum(1 for row in targeted if _norm_bool(row.get("legacy_runs_row_present")))
    host_file_present_count = sum(1 for row in targeted if row.get("host_path_exists") is True)

    exact_sql_predicate = (
        "run_type = 'static' AND link_state = 'dangling_static_run' "
        f"AND primary_reason IN ({', '.join(repr(reason) for reason in included_reasons)}) "
        "AND missing_static_run = 1 AND canonical_db_reference_present = 0 "
        "AND host_path_exists = 0"
    )
    apply_delete_sql = "DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)"
    sample_rows = tuple(
        {
            "artifact_id": row.get("artifact_id"),
            "resolved_static_run_id": row.get("resolved_static_run_id"),
            "artifact_type": row.get("artifact_type"),
            "host_path_family": row.get("host_path_family"),
            "created_at_utc": row.get("created_at_utc"),
            "host_path": row.get("host_path"),
            "status_reason": row.get("status_reason"),
        }
        for row in targeted[:12]
    )
    return StaticPruneProposal(
        total_rows_before=total_rows_before,
        static_dangling_before=static_dangling_before,
        dynamic_dangling_before=dynamic_dangling_before,
        targeted_row_count=len(targeted),
        targeted_distinct_static_run_ids=len(targeted_static_run_ids),
        targeted_static_run_ids=targeted_static_run_ids,
        targeted_artifact_ids=targeted_artifact_ids,
        included_primary_reasons=included_reasons,
        reason_counts=dict(sorted(reason_counts.items())),
        artifact_type_counts=dict(sorted(artifact_type_counts.items())),
        path_family_counts=dict(sorted(path_family_counts.items())),
        oldest_created_at_utc=min(created_values) if created_values else None,
        newest_created_at_utc=max(created_values) if created_values else None,
        all_missing_static_run=all(_norm_bool(row.get("missing_static_run")) for row in targeted),
        all_target_files_missing=all(row.get("host_path_exists") is False for row in targeted),
        all_missing_canonical_refs=all(not _norm_bool(row.get("canonical_db_reference_present")) for row in targeted),
        all_missing_legacy_runs_overlap=all(not _norm_bool(row.get("legacy_runs_row_present")) for row in targeted),
        canonical_db_residue_count=canonical_residue_count,
        legacy_runs_overlap_count=legacy_overlap_count,
        host_file_present_count=host_file_present_count,
        sample_rows=sample_rows,
        target_rows=tuple(targeted),
        exact_sql_predicate=exact_sql_predicate,
        apply_delete_sql=apply_delete_sql,
        expected_count_match=(len(targeted) == int(expected_count)) if expected_count is not None else None,
    )


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
        "-- ScytaleDroid artifact_registry static prune receipt",
        f"-- generated_utc: {meta.get('generated_utc')}",
        f"-- targeted_row_count: {meta.get('targeted_row_count')}",
        f"-- targeted_distinct_static_run_ids: {meta.get('targeted_distinct_static_run_ids')}",
        f"-- included_primary_reasons: {meta.get('included_primary_reasons')}",
        f"-- exact_sql_predicate: {meta.get('exact_sql_predicate')}",
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


def write_static_prune_receipts(
    receipt_dir: Path,
    *,
    stem: str,
    proposal: StaticPruneProposal,
    apply_requested: bool,
    apply_result: StaticPruneApplyResult | None = None,
) -> dict[str, str]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_receipt_stem(stem)
    json_path = receipt_dir / f"{base}.json"
    csv_path = receipt_dir / f"{base}.csv"
    sql_path = receipt_dir / f"{base}.sql"
    stamp = base.removeprefix("artifact_registry_static_prune_")
    txt_path = receipt_dir / f"artifact_registry_static_prune_run_ids_{stamp}.txt"

    payload = {
        "format": "scytaledroid.artifact_registry_static_prune_receipt.v1",
        "meta": {
            "generated_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
            "apply_requested": bool(apply_requested),
            "total_artifact_registry_rows_before": proposal.total_rows_before,
            "static_dangling_rows_before": proposal.static_dangling_before,
            "dynamic_dangling_rows_before": proposal.dynamic_dangling_before,
            "targeted_row_count": proposal.targeted_row_count,
            "targeted_distinct_static_run_ids": proposal.targeted_distinct_static_run_ids,
            "included_primary_reasons": list(proposal.included_primary_reasons),
            "reason_counts": proposal.reason_counts,
            "artifact_type_counts": proposal.artifact_type_counts,
            "path_family_counts": proposal.path_family_counts,
            "oldest_created_at_utc": proposal.oldest_created_at_utc,
            "newest_created_at_utc": proposal.newest_created_at_utc,
            "exact_sql_predicate": proposal.exact_sql_predicate,
            "apply_delete_sql": proposal.apply_delete_sql,
            "all_missing_static_run": proposal.all_missing_static_run,
            "all_target_files_missing": proposal.all_target_files_missing,
            "all_missing_canonical_refs": proposal.all_missing_canonical_refs,
            "all_missing_legacy_runs_overlap": proposal.all_missing_legacy_runs_overlap,
            "canonical_db_residue_count": proposal.canonical_db_residue_count,
            "legacy_runs_overlap_count": proposal.legacy_runs_overlap_count,
            "host_file_present_count": proposal.host_file_present_count,
            "expected_count_match": proposal.expected_count_match,
        },
        "sample_rows": list(proposal.sample_rows),
        "artifact_rows": list(proposal.target_rows),
        "target_static_run_ids": list(proposal.targeted_static_run_ids),
    }
    if apply_result is not None:
        payload["apply_result"] = {
            "deleted_count": apply_result.deleted_count,
            "total_artifact_registry_rows_after": apply_result.total_rows_after,
            "static_dangling_rows_after": apply_result.static_dangling_after,
            "dynamic_dangling_rows_after": apply_result.dynamic_dangling_after,
        }
    _write_json(json_path, payload)
    _write_csv(csv_path, proposal.target_rows)
    _write_sql(
        sql_path,
        artifact_ids=proposal.targeted_artifact_ids,
        static_run_ids=proposal.targeted_static_run_ids,
        meta=payload["meta"],
    )
    _write_run_ids(txt_path, proposal.targeted_static_run_ids)
    return {
        "json": str(json_path.resolve()),
        "csv": str(csv_path.resolve()),
        "sql": str(sql_path.resolve()),
        "run_ids": str(txt_path.resolve()),
    }


def validate_static_prune_proposal(proposal: StaticPruneProposal, *, expected_count: int | None = None) -> None:
    if expected_count is not None and proposal.targeted_row_count != int(expected_count):
        raise ValueError(
            f"static prune proposal refused: expected {expected_count} targeted rows, found {proposal.targeted_row_count}"
        )
    if not proposal.all_missing_static_run:
        raise ValueError("static prune proposal refused: target set includes rows that do not assert missing_static_run")
    if not proposal.all_target_files_missing:
        raise ValueError("static prune proposal refused: target set includes host files still present on disk")
    if not proposal.all_missing_canonical_refs:
        raise ValueError("static prune proposal refused: target set still overlaps canonical static DB references")
    if not proposal.all_missing_legacy_runs_overlap:
        raise ValueError("static prune proposal refused: target set still overlaps legacy runs rows")


def apply_static_prune(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    proposal: StaticPruneProposal,
) -> StaticPruneApplyResult:
    deleted = _delete_artifact_ids(run_sql_rowcount, proposal.targeted_artifact_ids)
    return StaticPruneApplyResult(
        deleted_count=deleted,
        total_rows_after=count_artifact_registry_rows(run_sql),
        static_dangling_after=count_static_dangling_rows(run_sql),
        dynamic_dangling_after=count_dynamic_dangling_rows(run_sql),
    )


__all__ = [
    "ALLOWED_INCLUDED_REASONS",
    "DEFAULT_INCLUDED_REASONS",
    "StaticPruneApplyResult",
    "StaticPruneProposal",
    "apply_static_prune",
    "build_static_prune_proposal",
    "count_artifact_registry_rows",
    "count_dynamic_dangling_rows",
    "count_static_dangling_rows",
    "validate_static_prune_proposal",
    "write_static_prune_receipts",
]
