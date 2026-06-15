"""Receipt-first prune helpers for candidate static legacy-overlap sessions.

This workflow stays narrow:

- only ``artifact_registry`` rows
- only ``static`` dangling rows
- only session stamps already classified as candidate retirement sessions
- no file deletes
- no writes to legacy mirror or canonical static tables
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

from .artifact_registry_static_prune import (
    count_artifact_registry_rows,
    count_dynamic_dangling_rows,
    count_static_dangling_rows,
)
from .artifact_registry_static_session_retirement import collect_static_session_retirement_report

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
    s = str(stem or "").strip() or "artifact_registry_static_session_prune"
    return _STEM_SAFE.sub("_", s)[:200]


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
                query_name="artifact_registry_static_session_prune.delete_batch",
            )
        )
    return deleted


@dataclass(frozen=True)
class StaticSessionPruneProposal:
    total_rows_before: int
    static_dangling_before: int
    dynamic_dangling_before: int
    targeted_row_count: int
    targeted_session_count: int
    targeted_run_count: int
    targeted_artifact_ids: tuple[int, ...]
    targeted_static_run_ids: tuple[int, ...]
    targeted_session_stamps: tuple[str, ...]
    candidate_actions: dict[str, str]
    reason_counts: dict[str, int]
    artifact_type_counts: dict[str, int]
    path_family_counts: dict[str, int]
    legacy_payload_total_rows: int
    file_present_count: int
    file_missing_count: int
    canonical_db_residue_count: int
    malformed_or_unknown_count: int
    oldest_created_at_utc: str | None
    newest_created_at_utc: str | None
    target_rows: tuple[dict[str, Any], ...]
    sample_rows: tuple[dict[str, Any], ...]
    exact_sql_predicate: str
    apply_delete_sql: str
    expected_count_match: bool | None


@dataclass(frozen=True)
class StaticSessionPruneApplyResult:
    deleted_count: int
    total_rows_after: int
    static_dangling_after: int
    dynamic_dangling_after: int


def build_static_session_prune_proposal(
    run_sql: RunSql,
    *,
    repo_root: Path,
    session_stamps: Sequence[str],
    expected_count: int | None = None,
) -> StaticSessionPruneProposal:
    selected_sessions = tuple(dict.fromkeys(_norm_text(s) for s in session_stamps if _norm_text(s)))
    if not selected_sessions:
        raise ValueError("static session prune proposal requires at least one session_stamp")

    report = collect_static_session_retirement_report(run_sql, repo_root=repo_root)
    sessions = [
        dict(row)
        for row in (report.get("legacy_session_retirement_sessions") or [])
        if isinstance(row, Mapping)
    ]
    runs = [
        dict(row)
        for row in (report.get("legacy_session_retirement_runs") or [])
        if isinstance(row, Mapping)
    ]
    dangling_rows = [
        dict(row)
        for row in (report.get("_dangling_rows") or [])
        if isinstance(row, Mapping)
    ]

    session_lookup = {_norm_text(row.get("session_stamp")): row for row in sessions}
    missing_sessions = [session for session in selected_sessions if session not in session_lookup]
    if missing_sessions:
        raise ValueError("unknown static session_stamp(s): " + ", ".join(sorted(missing_sessions)))

    selected_run_ids = {
        int(row.get("run_id"))
        for row in runs
        if _norm_text(row.get("session_stamp")) in selected_sessions and row.get("run_id") is not None
    }
    if not isinstance(report.get("_dangling_rows"), list):
        raise ValueError("static session prune proposal requires uncapped dangling-row detail")
    detailed_rows = []
    for row in dangling_rows:
        session_stamp = _norm_text(row.get("session_stamp"))
        run_id = row.get("resolved_static_run_id")
        try:
            resolved_run_id = int(run_id)
        except (TypeError, ValueError):
            continue
        if session_stamp in selected_sessions and resolved_run_id in selected_run_ids:
            detailed_rows.append(dict(row))
    detailed_rows.sort(key=lambda row: (str(row.get("created_at_utc") or ""), int(row.get("artifact_id") or 0)))

    total_rows_before = count_artifact_registry_rows(run_sql)
    static_dangling_before = count_static_dangling_rows(run_sql)
    dynamic_dangling_before = count_dynamic_dangling_rows(run_sql)
    reason_counts = Counter(_norm_text_or_none(row.get("primary_reason")) or "unknown" for row in detailed_rows)
    artifact_type_counts = Counter(_norm_text_or_none(row.get("artifact_type")) or "(blank)" for row in detailed_rows)
    path_family_counts = Counter(_norm_text_or_none(row.get("host_path_family")) or "(blank)" for row in detailed_rows)
    created_values = [str(row.get("created_at_utc")) for row in detailed_rows if row.get("created_at_utc")]
    targeted_artifact_ids = tuple(int(row.get("artifact_id") or 0) for row in detailed_rows)
    candidate_actions = {session: _norm_text(session_lookup[session].get("recommended_action")) for session in selected_sessions}
    legacy_payload_total_rows = sum(
        int(session_lookup[session].get("legacy_payload_total_rows") or 0)
        for session in selected_sessions
    )
    file_present_count = sum(1 for row in detailed_rows if row.get("host_path_exists") is True)
    file_missing_count = sum(1 for row in detailed_rows if row.get("host_path_exists") is False)
    canonical_db_residue_count = sum(1 for row in detailed_rows if _norm_bool(row.get("canonical_db_reference_present")))
    malformed_or_unknown_count = sum(
        1
        for row in detailed_rows
        if _norm_text(row.get("primary_reason")) in {"malformed_static_run_id", "unknown_needs_review"}
    )
    exact_sql_predicate = (
        "run_type = 'static' AND link_state = 'dangling_static_run' "
        f"AND session_stamp IN ({', '.join(repr(session) for session in selected_sessions)}) "
        "AND legacy_runs_row_present = 1 AND host_path_exists = 0"
    )
    apply_delete_sql = "DELETE FROM artifact_registry WHERE artifact_id IN (<targeted artifact_id set>)"
    sample_rows = tuple(
        {
            "artifact_id": row.get("artifact_id"),
            "session_stamp": row.get("session_stamp"),
            "resolved_static_run_id": row.get("resolved_static_run_id"),
            "package": row.get("package"),
            "artifact_type": row.get("artifact_type"),
            "host_path_family": row.get("host_path_family"),
            "created_at_utc": row.get("created_at_utc"),
            "host_path": row.get("host_path"),
        }
        for row in detailed_rows[:12]
    )
    return StaticSessionPruneProposal(
        total_rows_before=total_rows_before,
        static_dangling_before=static_dangling_before,
        dynamic_dangling_before=dynamic_dangling_before,
        targeted_row_count=len(detailed_rows),
        targeted_session_count=len(selected_sessions),
        targeted_run_count=len(selected_run_ids),
        targeted_artifact_ids=targeted_artifact_ids,
        targeted_static_run_ids=tuple(sorted(selected_run_ids)),
        targeted_session_stamps=selected_sessions,
        candidate_actions=candidate_actions,
        reason_counts=dict(sorted(reason_counts.items())),
        artifact_type_counts=dict(sorted(artifact_type_counts.items())),
        path_family_counts=dict(sorted(path_family_counts.items())),
        legacy_payload_total_rows=legacy_payload_total_rows,
        file_present_count=file_present_count,
        file_missing_count=file_missing_count,
        canonical_db_residue_count=canonical_db_residue_count,
        malformed_or_unknown_count=malformed_or_unknown_count,
        oldest_created_at_utc=min(created_values) if created_values else None,
        newest_created_at_utc=max(created_values) if created_values else None,
        target_rows=tuple(detailed_rows),
        sample_rows=sample_rows,
        exact_sql_predicate=exact_sql_predicate,
        apply_delete_sql=apply_delete_sql,
        expected_count_match=(len(detailed_rows) == int(expected_count)) if expected_count is not None else None,
    )


def validate_static_session_prune_proposal(proposal: StaticSessionPruneProposal, *, expected_count: int | None = None) -> None:
    if expected_count is not None and proposal.targeted_row_count != int(expected_count):
        raise ValueError(
            f"static session prune proposal refused: expected {expected_count} targeted rows, found {proposal.targeted_row_count}"
        )
    invalid_sessions = sorted(
        session for session, action in proposal.candidate_actions.items() if not action.startswith("candidate_")
    )
    if invalid_sessions:
        raise ValueError(
            "static session prune proposal refused: selected session(s) are not candidate retirement sessions: "
            + ", ".join(invalid_sessions)
        )
    if proposal.file_present_count:
        raise ValueError("static session prune proposal refused: target set includes host files still present on disk")
    if proposal.canonical_db_residue_count:
        raise ValueError("static session prune proposal refused: target set still overlaps canonical static DB references")
    if proposal.malformed_or_unknown_count:
        raise ValueError("static session prune proposal refused: target set includes malformed or unknown rows")


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


def _write_sql(path: Path, *, artifact_ids: Sequence[int], session_stamps: Sequence[str], meta: Mapping[str, Any]) -> None:
    lines = [
        "-- ScytaleDroid artifact_registry static session prune receipt",
        f"-- generated_utc: {meta.get('generated_utc')}",
        f"-- targeted_row_count: {meta.get('targeted_row_count')}",
        f"-- targeted_session_stamps: {meta.get('targeted_session_stamps')}",
        f"-- exact_sql_predicate: {meta.get('exact_sql_predicate')}",
        "-- delete scope: artifact_registry only",
        "-- no files deleted; no legacy mirror tables deleted",
        "",
        "-- targeted session_stamp values:",
    ]
    for stamp in session_stamps:
        lines.append(f"--   {stamp}")
    lines.append("")
    for i in range(0, len(artifact_ids), 200):
        batch = ",".join(str(int(x)) for x in artifact_ids[i : i + 200])
        lines.append(f"DELETE FROM artifact_registry WHERE artifact_id IN ({batch});")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_session_stamps(path: Path, session_stamps: Sequence[str]) -> None:
    text = "\n".join(session_stamps)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_static_session_prune_receipts(
    receipt_dir: Path,
    *,
    stem: str,
    proposal: StaticSessionPruneProposal,
    apply_requested: bool,
    apply_result: StaticSessionPruneApplyResult | None = None,
) -> dict[str, str]:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_receipt_stem(stem)
    json_path = receipt_dir / f"{base}.json"
    csv_path = receipt_dir / f"{base}.csv"
    sql_path = receipt_dir / f"{base}.sql"
    stamp = base.removeprefix("artifact_registry_static_session_prune_")
    txt_path = receipt_dir / f"artifact_registry_static_session_prune_sessions_{stamp}.txt"

    payload: dict[str, Any] = {
        "format": "scytaledroid.artifact_registry_static_session_prune_receipt.v1",
        "meta": {
            "generated_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
            "apply_requested": bool(apply_requested),
            "total_artifact_registry_rows_before": proposal.total_rows_before,
            "static_dangling_rows_before": proposal.static_dangling_before,
            "dynamic_dangling_rows_before": proposal.dynamic_dangling_before,
            "targeted_row_count": proposal.targeted_row_count,
            "targeted_session_count": proposal.targeted_session_count,
            "targeted_run_count": proposal.targeted_run_count,
            "targeted_session_stamps": list(proposal.targeted_session_stamps),
            "targeted_static_run_ids": list(proposal.targeted_static_run_ids),
            "candidate_actions": proposal.candidate_actions,
            "reason_counts": proposal.reason_counts,
            "artifact_type_counts": proposal.artifact_type_counts,
            "path_family_counts": proposal.path_family_counts,
            "legacy_payload_total_rows": proposal.legacy_payload_total_rows,
            "file_present_count": proposal.file_present_count,
            "file_missing_count": proposal.file_missing_count,
            "canonical_db_residue_count": proposal.canonical_db_residue_count,
            "malformed_or_unknown_count": proposal.malformed_or_unknown_count,
            "oldest_created_at_utc": proposal.oldest_created_at_utc,
            "newest_created_at_utc": proposal.newest_created_at_utc,
            "exact_sql_predicate": proposal.exact_sql_predicate,
            "apply_delete_sql": proposal.apply_delete_sql,
            "expected_count_match": proposal.expected_count_match,
        },
        "sample_rows": list(proposal.sample_rows),
        "artifact_rows": list(proposal.target_rows),
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
    _write_sql(sql_path, artifact_ids=proposal.targeted_artifact_ids, session_stamps=proposal.targeted_session_stamps, meta=payload["meta"])
    _write_session_stamps(txt_path, proposal.targeted_session_stamps)
    return {
        "json": str(json_path.resolve()),
        "csv": str(csv_path.resolve()),
        "sql": str(sql_path.resolve()),
        "sessions": str(txt_path.resolve()),
    }


def apply_static_session_prune(
    run_sql: RunSql,
    run_sql_rowcount: RunSqlRowcount,
    *,
    proposal: StaticSessionPruneProposal,
) -> StaticSessionPruneApplyResult:
    deleted = _delete_artifact_ids(run_sql_rowcount, proposal.targeted_artifact_ids)
    return StaticSessionPruneApplyResult(
        deleted_count=deleted,
        total_rows_after=count_artifact_registry_rows(run_sql),
        static_dangling_after=count_static_dangling_rows(run_sql),
        dynamic_dangling_after=count_dynamic_dangling_rows(run_sql),
    )


__all__ = [
    "StaticSessionPruneApplyResult",
    "StaticSessionPruneProposal",
    "apply_static_session_prune",
    "build_static_session_prune_proposal",
    "validate_static_session_prune_proposal",
    "write_static_session_prune_receipts",
]
