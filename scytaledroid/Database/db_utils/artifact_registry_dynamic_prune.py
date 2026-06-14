"""Receipt-first prune helpers for fully detached dynamic ``artifact_registry`` rows.

This workflow is intentionally narrow:

- only ``artifact_registry`` rows
- only ``dynamic`` rows
- only rows already classified as ``truly_detached`` by the dynamic dangling audit
- no file deletes
- no writes to any dynamic/static/session/evidence tables
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

from .artifact_registry_dynamic_dangling import collect_artifact_registry_dynamic_dangling_report

RunSql = Callable[..., Any]
RunSqlRowcount = Callable[..., int]

_STEM_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


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
    s = str(stem or "").strip() or "artifact_registry_dynamic_prune"
    return _STEM_SAFE.sub("_", s)[:200]


def count_artifact_registry_rows(run_sql: RunSql) -> int:
    row = run_sql(
        "SELECT COUNT(*) AS c FROM artifact_registry",
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_dynamic_prune.total_count",
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
        query_name="artifact_registry_dynamic_prune.static_dangling_count",
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
        query_name="artifact_registry_dynamic_prune.dynamic_dangling_count",
    ) or {}
    if isinstance(row, Mapping):
        return int(row.get("c") or 0)
    return 0


def collect_link_state_parity(run_sql: RunSql) -> dict[str, int]:
    row = run_sql(
        """
        SELECT
          SUM(CASE WHEN ar.run_type='dynamic' AND ((ar.dynamic_run_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM dynamic_sessions ds WHERE ds.dynamic_run_id = ar.dynamic_run_id
              )) OR (ar.dynamic_run_id IS NULL AND TRIM(COALESCE(ar.run_id,''))<>'' AND EXISTS (
                SELECT 1 FROM dynamic_sessions ds WHERE ds.dynamic_run_id = ar.run_id
              ))) THEN 1 ELSE 0 END) AS dynamic_linked_legacy,
          SUM(CASE WHEN v.run_type='dynamic' AND v.link_state='linked' THEN 1 ELSE 0 END) AS dynamic_linked_typed,
          SUM(CASE WHEN ar.run_type='dynamic' AND NOT ((ar.dynamic_run_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM dynamic_sessions ds WHERE ds.dynamic_run_id = ar.dynamic_run_id
              )) OR (ar.dynamic_run_id IS NULL AND TRIM(COALESCE(ar.run_id,''))<>'' AND EXISTS (
                SELECT 1 FROM dynamic_sessions ds WHERE ds.dynamic_run_id = ar.run_id
              ))) THEN 1 ELSE 0 END) AS dynamic_dangling_legacy,
          SUM(CASE WHEN v.run_type='dynamic' AND v.link_state='dangling_dynamic_run' THEN 1 ELSE 0 END) AS dynamic_dangling_typed,
          SUM(CASE WHEN ar.run_type='static' AND ((ar.static_run_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM static_analysis_runs sar WHERE sar.id = ar.static_run_id
              )) OR (ar.static_run_id IS NULL AND ar.run_id REGEXP '^[0-9]+$' AND EXISTS (
                SELECT 1 FROM static_analysis_runs sar WHERE sar.id = CAST(ar.run_id AS UNSIGNED)
              ))) THEN 1 ELSE 0 END) AS static_linked_legacy,
          SUM(CASE WHEN v.run_type='static' AND v.link_state='linked' THEN 1 ELSE 0 END) AS static_linked_typed,
          SUM(CASE WHEN ar.run_type='static' AND NOT ((ar.static_run_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM static_analysis_runs sar WHERE sar.id = ar.static_run_id
              )) OR (ar.static_run_id IS NULL AND ar.run_id REGEXP '^[0-9]+$' AND EXISTS (
                SELECT 1 FROM static_analysis_runs sar WHERE sar.id = CAST(ar.run_id AS UNSIGNED)
              ))) THEN 1 ELSE 0 END) AS static_dangling_legacy,
          SUM(CASE WHEN v.run_type='static' AND v.link_state='dangling_static_run' THEN 1 ELSE 0 END) AS static_dangling_typed
        FROM artifact_registry ar
        CROSS JOIN v_artifact_registry_integrity v
        WHERE ar.artifact_id = v.artifact_id
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="artifact_registry_dynamic_prune.parity_counts",
    ) or {}
    return {
        "dynamic_linked_legacy": int(row.get("dynamic_linked_legacy") or 0),
        "dynamic_linked_typed": int(row.get("dynamic_linked_typed") or 0),
        "dynamic_dangling_legacy": int(row.get("dynamic_dangling_legacy") or 0),
        "dynamic_dangling_typed": int(row.get("dynamic_dangling_typed") or 0),
        "static_linked_legacy": int(row.get("static_linked_legacy") or 0),
        "static_linked_typed": int(row.get("static_linked_typed") or 0),
        "static_dangling_legacy": int(row.get("static_dangling_legacy") or 0),
        "static_dangling_typed": int(row.get("static_dangling_typed") or 0),
    }


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
                query_name="artifact_registry_dynamic_prune.delete_batch",
            )
        )
    return deleted


@dataclass(frozen=True)
class DynamicPruneProposal:
    total_rows_before: int
    dynamic_dangling_before: int
    static_dangling_before: int
    targeted_row_count: int
    targeted_distinct_dynamic_run_ids: int
    targeted_run_ids: tuple[str, ...]
    targeted_artifact_ids: tuple[int, ...]
    reason_counts: dict[str, int]
    artifact_type_counts: dict[str, int]
    path_root_counts: dict[str, int]
    oldest_created_at_utc: str | None
    newest_created_at_utc: str | None
    all_truly_detached: bool
    all_dynamic_run_id_populated: bool
    all_missing_dynamic_sessions: bool
    all_missing_dynamic_db_refs: bool
    all_target_files_missing: bool
    malformed_dynamic_run_id_count: int
    unknown_needs_review_count: int
    sample_rows: tuple[dict[str, Any], ...]
    target_rows: tuple[dict[str, Any], ...]
    exact_sql_predicate: str
    apply_delete_sql: str
    expected_count_match: bool
    expected_run_count_match: bool


@dataclass(frozen=True)
class DynamicPruneApplyResult:
    deleted_count: int
    total_rows_after: int
    dynamic_dangling_after: int
    static_dangling_after: int
    parity_after: dict[str, int]


def build_dynamic_prune_proposal(
    run_sql: RunSql,
    *,
    repo_root: Path,
    expected_count: int = 750,
    expected_run_count: int = 30,
) -> DynamicPruneProposal:
    report = collect_artifact_registry_dynamic_dangling_report(run_sql, repo_root=repo_root)
    rows = [dict(row) for row in (report.get("dynamic_dangling_rows") or []) if isinstance(row, Mapping)]
    targeted = [row for row in rows if _norm_text_or_none(row.get("primary_reason")) == "truly_detached"]
    targeted.sort(key=lambda row: (str(row.get("created_at_utc") or ""), int(row.get("artifact_id") or 0)))

    total_rows_before = count_artifact_registry_rows(run_sql)
    dynamic_dangling_before = count_dynamic_dangling_rows(run_sql)
    static_dangling_before = count_static_dangling_rows(run_sql)
    artifact_type_counts = Counter(_norm_text_or_none(row.get("artifact_type")) or "(blank)" for row in targeted)
    path_root_counts = Counter(_norm_text_or_none(row.get("host_workspace_prefix")) or "(blank)" for row in targeted)
    reason_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in targeted)
    targeted_run_ids = tuple(sorted({_norm_text_or_none(row.get("resolved_dynamic_run_id")) or "" for row in targeted}))
    targeted_artifact_ids = tuple(int(row.get("artifact_id") or 0) for row in targeted)
    created_values = [str(row.get("created_at_utc")) for row in targeted if row.get("created_at_utc")]
    malformed_count = sum(1 for row in rows if _norm_bool(row.get("malformed_dynamic_run_id")))
    unknown_count = sum(1 for row in rows if _norm_bool(row.get("unknown_needs_review")))
    all_dynamic_run_id_populated = all(
        _norm_text_or_none(row.get("dynamic_run_id")) and _norm_text_or_none(row.get("resolved_dynamic_run_id"))
        for row in targeted
    )
    all_missing_dynamic_sessions = all(not _norm_bool(row.get("has_dynamic_session")) for row in targeted)
    all_missing_dynamic_db_refs = all(not _norm_bool(row.get("has_any_dynamic_db_reference")) for row in targeted)
    all_target_files_missing = all(row.get("host_path_exists") is False for row in targeted)
    all_truly_detached = len(targeted) == len(rows) and all(
        _norm_text_or_none(row.get("primary_reason")) == "truly_detached" for row in rows
    )
    exact_sql_predicate = (
        "run_type = 'dynamic' AND link_state = 'dangling_dynamic_run' "
        "AND dynamic_run_id IS NOT NULL AND resolved_dynamic_run_id IS NOT NULL "
        "AND primary_reason = 'truly_detached' "
        "AND has_dynamic_session = 0 AND has_any_dynamic_db_reference = 0 "
        "AND host_path_exists = 0"
    )
    apply_delete_sql = "DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)"
    sample_rows = tuple(
        {
            "artifact_id": row.get("artifact_id"),
            "resolved_dynamic_run_id": row.get("resolved_dynamic_run_id"),
            "artifact_type": row.get("artifact_type"),
            "created_at_utc": row.get("created_at_utc"),
            "host_workspace_prefix": row.get("host_workspace_prefix"),
            "host_path": row.get("host_path"),
            "status_reason": row.get("status_reason"),
        }
        for row in targeted[:12]
    )
    return DynamicPruneProposal(
        total_rows_before=total_rows_before,
        dynamic_dangling_before=dynamic_dangling_before,
        static_dangling_before=static_dangling_before,
        targeted_row_count=len(targeted),
        targeted_distinct_dynamic_run_ids=len(targeted_run_ids),
        targeted_run_ids=targeted_run_ids,
        targeted_artifact_ids=targeted_artifact_ids,
        reason_counts=dict(sorted(reason_counts.items())),
        artifact_type_counts=dict(sorted(artifact_type_counts.items())),
        path_root_counts=dict(sorted(path_root_counts.items())),
        oldest_created_at_utc=min(created_values) if created_values else None,
        newest_created_at_utc=max(created_values) if created_values else None,
        all_truly_detached=all_truly_detached,
        all_dynamic_run_id_populated=all_dynamic_run_id_populated,
        all_missing_dynamic_sessions=all_missing_dynamic_sessions,
        all_missing_dynamic_db_refs=all_missing_dynamic_db_refs,
        all_target_files_missing=all_target_files_missing,
        malformed_dynamic_run_id_count=malformed_count,
        unknown_needs_review_count=unknown_count,
        sample_rows=sample_rows,
        target_rows=tuple(targeted),
        exact_sql_predicate=exact_sql_predicate,
        apply_delete_sql=apply_delete_sql,
        expected_count_match=len(targeted) == int(expected_count),
        expected_run_count_match=len(targeted_run_ids) == int(expected_run_count),
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


def _write_sql(path: Path, *, artifact_ids: Sequence[int], run_ids: Sequence[str], meta: Mapping[str, Any]) -> None:
    lines = [
        "-- ScytaleDroid artifact_registry dynamic prune receipt",
        f"-- generated_utc: {meta.get('generated_utc')}",
        f"-- targeted_row_count: {meta.get('targeted_row_count')}",
        f"-- targeted_distinct_dynamic_run_ids: {meta.get('targeted_distinct_dynamic_run_ids')}",
        f"-- exact_sql_predicate: {meta.get('exact_sql_predicate')}",
        "-- delete scope: artifact_registry only",
        "-- no files deleted; no dynamic/static/session tables touched",
        "",
        "-- targeted dynamic_run_id values:",
    ]
    for run_id in run_ids:
        lines.append(f"--   {run_id}")
    lines.append("")
    for i in range(0, len(artifact_ids), 200):
        batch = ",".join(str(int(x)) for x in artifact_ids[i : i + 200])
        lines.append(f"DELETE FROM artifact_registry WHERE artifact_id IN ({batch});")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_run_ids(path: Path, run_ids: Sequence[str]) -> None:
    text = "\n".join(run_ids)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_dynamic_prune_receipts(
    receipt_dir: Path,
    *,
    stem: str,
    proposal: DynamicPruneProposal,
    apply_requested: bool,
    apply_result: DynamicPruneApplyResult | None = None,
) -> dict[str, str]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_receipt_stem(stem)
    json_path = receipt_dir / f"{base}.json"
    csv_path = receipt_dir / f"{base}.csv"
    sql_path = receipt_dir / f"{base}.sql"
    stamp = base.removeprefix("artifact_registry_dynamic_prune_")
    txt_path = receipt_dir / f"artifact_registry_dynamic_prune_run_ids_{stamp}.txt"

    payload = {
        "format": "scytaledroid.artifact_registry_dynamic_prune_receipt.v1",
        "meta": {
            "generated_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
            "apply_requested": bool(apply_requested),
            "total_artifact_registry_rows_before": proposal.total_rows_before,
            "dynamic_dangling_rows_before": proposal.dynamic_dangling_before,
            "static_dangling_rows_before": proposal.static_dangling_before,
            "targeted_row_count": proposal.targeted_row_count,
            "targeted_distinct_dynamic_run_ids": proposal.targeted_distinct_dynamic_run_ids,
            "reason_counts": proposal.reason_counts,
            "artifact_type_counts": proposal.artifact_type_counts,
            "path_root_counts": proposal.path_root_counts,
            "oldest_created_at_utc": proposal.oldest_created_at_utc,
            "newest_created_at_utc": proposal.newest_created_at_utc,
            "exact_sql_predicate": proposal.exact_sql_predicate,
            "apply_delete_sql": proposal.apply_delete_sql,
            "all_truly_detached": proposal.all_truly_detached,
            "all_dynamic_run_id_populated": proposal.all_dynamic_run_id_populated,
            "all_missing_dynamic_sessions": proposal.all_missing_dynamic_sessions,
            "all_missing_dynamic_db_refs": proposal.all_missing_dynamic_db_refs,
            "all_target_files_missing": proposal.all_target_files_missing,
            "malformed_dynamic_run_id_count": proposal.malformed_dynamic_run_id_count,
            "unknown_needs_review_count": proposal.unknown_needs_review_count,
            "expected_count_match": proposal.expected_count_match,
            "expected_run_count_match": proposal.expected_run_count_match,
        },
        "sample_rows": list(proposal.sample_rows),
        "artifact_rows": list(proposal.target_rows),
        "target_dynamic_run_ids": list(proposal.targeted_run_ids),
    }
    if apply_result is not None:
        payload["apply_result"] = {
            "deleted_count": apply_result.deleted_count,
            "total_artifact_registry_rows_after": apply_result.total_rows_after,
            "dynamic_dangling_rows_after": apply_result.dynamic_dangling_after,
            "static_dangling_rows_after": apply_result.static_dangling_after,
            "parity_after": apply_result.parity_after,
        }
    _write_json(json_path, payload)
    _write_csv(csv_path, proposal.target_rows)
    _write_sql(
        sql_path,
        artifact_ids=proposal.targeted_artifact_ids,
        run_ids=proposal.targeted_run_ids,
        meta=payload["meta"],
    )
    _write_run_ids(txt_path, proposal.targeted_run_ids)
    return {
        "json": str(json_path.resolve()),
        "csv": str(csv_path.resolve()),
        "sql": str(sql_path.resolve()),
        "run_ids": str(txt_path.resolve()),
    }


def validate_dynamic_prune_proposal(proposal: DynamicPruneProposal, *, expected_count: int, expected_run_count: int) -> None:
    if proposal.targeted_row_count != int(expected_count):
        raise ValueError(
            f"dynamic prune proposal refused: expected {expected_count} targeted rows, found {proposal.targeted_row_count}"
        )
    if proposal.targeted_distinct_dynamic_run_ids != int(expected_run_count):
        raise ValueError(
            "dynamic prune proposal refused: expected "
            f"{expected_run_count} dynamic run ids, found {proposal.targeted_distinct_dynamic_run_ids}"
        )
    if not proposal.all_truly_detached:
        raise ValueError("dynamic prune proposal refused: target cohort is not uniformly truly_detached")
    if not proposal.all_dynamic_run_id_populated:
        raise ValueError("dynamic prune proposal refused: one or more target rows have blank dynamic_run_id")
    if not proposal.all_missing_dynamic_sessions:
        raise ValueError("dynamic prune proposal refused: one or more target rows map to dynamic_sessions")
    if not proposal.all_missing_dynamic_db_refs:
        raise ValueError("dynamic prune proposal refused: one or more target rows still map to dynamic evidence tables")
    if not proposal.all_target_files_missing:
        raise ValueError("dynamic prune proposal refused: one or more target files still exist on disk")
    if proposal.malformed_dynamic_run_id_count != 0:
        raise ValueError("dynamic prune proposal refused: malformed dynamic_run_id rows are present")
    if proposal.unknown_needs_review_count != 0:
        raise ValueError("dynamic prune proposal refused: unknown_needs_review rows are present")


def apply_dynamic_prune(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    proposal: DynamicPruneProposal,
    expected_dynamic_linked_after: int = 3109,
) -> DynamicPruneApplyResult:
    deleted = _delete_artifact_ids(run_sql_rowcount, proposal.targeted_artifact_ids)
    total_after = count_artifact_registry_rows(run_sql)
    dynamic_after = count_dynamic_dangling_rows(run_sql)
    static_after = count_static_dangling_rows(run_sql)
    parity_after = collect_link_state_parity(run_sql)

    if deleted != proposal.targeted_row_count:
        raise RuntimeError(
            f"deleted row count mismatch: expected {proposal.targeted_row_count}, got {deleted}"
        )
    if total_after != (proposal.total_rows_before - proposal.targeted_row_count):
        raise RuntimeError(
            "artifact_registry total mismatch after prune: "
            f"expected {proposal.total_rows_before - proposal.targeted_row_count}, got {total_after}"
        )
    if dynamic_after != 0:
        raise RuntimeError(f"dynamic dangling rows remain after prune: {dynamic_after}")
    if static_after != proposal.static_dangling_before:
        raise RuntimeError(
            f"static dangling rows changed unexpectedly: before {proposal.static_dangling_before}, after {static_after}"
        )
    if parity_after["dynamic_linked_legacy"] != expected_dynamic_linked_after or parity_after["dynamic_linked_typed"] != expected_dynamic_linked_after:
        raise RuntimeError(
            "dynamic linked parity changed unexpectedly: "
            f"{parity_after['dynamic_linked_legacy']} / {parity_after['dynamic_linked_typed']}"
        )
    if not (
        parity_after["dynamic_linked_legacy"] == parity_after["dynamic_linked_typed"]
        and parity_after["dynamic_dangling_legacy"] == parity_after["dynamic_dangling_typed"]
        and parity_after["static_linked_legacy"] == parity_after["static_linked_typed"]
        and parity_after["static_dangling_legacy"] == parity_after["static_dangling_typed"]
    ):
        raise RuntimeError("legacy-vs-typed parity diverged after dynamic prune")

    return DynamicPruneApplyResult(
        deleted_count=deleted,
        total_rows_after=total_after,
        dynamic_dangling_after=dynamic_after,
        static_dangling_after=static_after,
        parity_after=parity_after,
    )


__all__ = [
    "DynamicPruneApplyResult",
    "DynamicPruneProposal",
    "apply_dynamic_prune",
    "build_dynamic_prune_proposal",
    "collect_link_state_parity",
    "validate_dynamic_prune_proposal",
    "write_dynamic_prune_receipts",
]
