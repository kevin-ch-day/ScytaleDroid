"""Read-only proposal report for remaining static dangling legacy-overlap sessions.

This module does not delete rows. It turns the remaining static dangling rows
that still overlap legacy ``runs`` into a session-scoped retirement queue so a
later prune can be reviewed deliberately.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .artifact_registry_static_dangling import collect_artifact_registry_static_dangling_report
from .artifact_registry_static_legacy_overlap import collect_static_legacy_overlap_report

RunSql = Callable[..., Any]

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "legacy_session_retirement_sessions.csv",
    "legacy_session_retirement_candidates.csv",
    "legacy_session_retirement_runs.csv",
    "legacy_session_retirement_samples.csv",
)


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


def _infer_package_from_host_path(host_path: Any) -> str | None:
    path = _norm_text_or_none(host_path)
    if not path:
        return None
    name = Path(path.replace("\\", "/")).name
    for marker in ("-full-", "-base-", "-profile-"):
        if marker in name:
            package = name.split(marker, 1)[0].strip()
            return package or None
    return None


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


def _session_action(file_present_rows: int, run_count: int) -> str:
    return _session_action_with_context(file_present_rows, run_count, package_mismatch_rows=0)


def _session_action_with_context(file_present_rows: int, run_count: int, *, package_mismatch_rows: int) -> str:
    if package_mismatch_rows > 0:
        return "blocked_package_mismatch_review"
    if file_present_rows > 0:
        return "blocked_file_present_review"
    if run_count <= 12:
        return "candidate_small_session_retirement_review"
    return "candidate_large_session_retirement_review"


def _session_priority(action: str, run_count: int, registry_rows: int) -> tuple[int, int, int]:
    if action == "candidate_small_session_retirement_review":
        return (0, run_count, registry_rows)
    if action == "candidate_large_session_retirement_review":
        return (1, run_count, registry_rows)
    if action == "blocked_file_present_review":
        return (2, run_count, registry_rows)
    return (3, run_count, registry_rows)


def collect_static_session_retirement_report(
    run_sql: RunSql,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    dangling = collect_artifact_registry_static_dangling_report(run_sql, repo_root=repo_root)
    legacy = collect_static_legacy_overlap_report(run_sql)

    overlap_run_lookup: dict[int, dict[str, Any]] = {}
    for row in legacy.get("legacy_overlap_runs") or []:
        if not isinstance(row, Mapping):
            continue
        run_id = row.get("run_id")
        try:
            overlap_run_lookup[int(run_id)] = dict(row)
        except (TypeError, ValueError):
            continue

    session_summary_lookup: dict[str, dict[str, Any]] = {}
    for row in legacy.get("legacy_overlap_sessions") or []:
        if not isinstance(row, Mapping):
            continue
        session_summary_lookup[_norm_text(row.get("session_stamp"))] = dict(row)

    session_rows: dict[str, dict[str, Any]] = {}
    run_rows: dict[int, dict[str, Any]] = {}
    sample_rows: list[dict[str, Any]] = []
    detailed_overlap_rows: list[dict[str, Any]] = []

    for row in dangling.get("static_dangling_rows") or []:
        if not isinstance(row, Mapping):
            continue
        if not _norm_bool(row.get("legacy_runs_row_present")):
            continue
        run_id = row.get("resolved_static_run_id")
        try:
            resolved_run_id = int(run_id)
        except (TypeError, ValueError):
            continue
        run_info = overlap_run_lookup.get(resolved_run_id, {})
        session_stamp = _norm_text_or_none(run_info.get("session_stamp")) or "(unknown)"
        package_name = _norm_text_or_none(run_info.get("package")) or _norm_text_or_none(row.get("meta_package_name")) or "(unknown)"
        artifact_path_package = _infer_package_from_host_path(row.get("host_path"))
        package_mismatch = bool(
            artifact_path_package
            and package_name != "(unknown)"
            and artifact_path_package.lower() != package_name.lower()
        )
        primary_reason = _norm_text_or_none(row.get("primary_reason")) or "unknown"
        file_exists = row.get("host_path_exists")

        session_group = session_rows.setdefault(
            session_stamp,
            {
                "session_stamp": session_stamp,
                "overlap_registry_rows": 0,
                "overlap_run_ids": 0,
                "distinct_packages": 0,
                "file_present_registry_rows": 0,
                "file_missing_registry_rows": 0,
                "unknown_file_state_registry_rows": 0,
                "package_mismatch_registry_rows": 0,
                "metrics_rows": int((session_summary_lookup.get(session_stamp) or {}).get("metrics_rows") or 0),
                "buckets_rows": int((session_summary_lookup.get(session_stamp) or {}).get("buckets_rows") or 0),
                "contributor_rows": int((session_summary_lookup.get(session_stamp) or {}).get("contributor_rows") or 0),
                "finding_rows": int((session_summary_lookup.get(session_stamp) or {}).get("finding_rows") or 0),
                "legacy_payload_total_rows": 0,
                "created_at_min_utc": row.get("created_at_utc"),
                "created_at_max_utc": row.get("created_at_utc"),
                "primary_reason_counts_json": "",
                "path_family_counts_json": "",
                "top_packages_csv": "",
                "recommended_action": "",
                "priority_bucket": "",
                "candidate_rank": None,
            },
        )
        run_group = run_rows.setdefault(
            resolved_run_id,
            {
                "run_id": resolved_run_id,
                "session_stamp": session_stamp,
                "package": package_name,
                "registry_rows": 0,
                "file_present_registry_rows": 0,
                "file_missing_registry_rows": 0,
                "unknown_file_state_registry_rows": 0,
                "package_mismatch_registry_rows": 0,
                "primary_reason_counts_json": "",
                "path_family_counts_json": "",
                "metrics_rows": int(run_info.get("metrics_rows") or 0),
                "buckets_rows": int(run_info.get("buckets_rows") or 0),
                "contributor_rows": int(run_info.get("contributor_rows") or 0),
                "finding_rows": int(run_info.get("finding_rows") or 0),
                "created_at_min_utc": row.get("created_at_utc"),
                "created_at_max_utc": row.get("created_at_utc"),
            },
        )
        session_group["overlap_registry_rows"] = int(session_group["overlap_registry_rows"]) + 1
        run_group["registry_rows"] = int(run_group["registry_rows"]) + 1
        if file_exists is True:
            session_group["file_present_registry_rows"] = int(session_group["file_present_registry_rows"]) + 1
            run_group["file_present_registry_rows"] = int(run_group["file_present_registry_rows"]) + 1
        elif file_exists is False:
            session_group["file_missing_registry_rows"] = int(session_group["file_missing_registry_rows"]) + 1
            run_group["file_missing_registry_rows"] = int(run_group["file_missing_registry_rows"]) + 1
        else:
            session_group["unknown_file_state_registry_rows"] = int(session_group["unknown_file_state_registry_rows"]) + 1
            run_group["unknown_file_state_registry_rows"] = int(run_group["unknown_file_state_registry_rows"]) + 1
        if package_mismatch:
            session_group["package_mismatch_registry_rows"] = int(session_group["package_mismatch_registry_rows"]) + 1
            run_group["package_mismatch_registry_rows"] = int(run_group["package_mismatch_registry_rows"]) + 1

        created_at = _norm_text_or_none(row.get("created_at_utc"))
        if created_at:
            if not session_group.get("created_at_min_utc") or created_at < str(session_group.get("created_at_min_utc")):
                session_group["created_at_min_utc"] = created_at
            if not session_group.get("created_at_max_utc") or created_at > str(session_group.get("created_at_max_utc")):
                session_group["created_at_max_utc"] = created_at
            if not run_group.get("created_at_min_utc") or created_at < str(run_group.get("created_at_min_utc")):
                run_group["created_at_min_utc"] = created_at
            if not run_group.get("created_at_max_utc") or created_at > str(run_group.get("created_at_max_utc")):
                run_group["created_at_max_utc"] = created_at

        session_reason_counts = session_group.setdefault("_reason_counts", Counter())
        session_reason_counts[primary_reason] += 1
        session_path_counts = session_group.setdefault("_path_counts", Counter())
        session_path_counts[_norm_text_or_none(row.get("host_path_family")) or "(blank)"] += 1
        session_packages = session_group.setdefault("_packages", Counter())
        session_packages[package_name] += 1
        session_run_ids = session_group.setdefault("_run_ids", set())
        session_run_ids.add(resolved_run_id)

        run_reason_counts = run_group.setdefault("_reason_counts", Counter())
        run_reason_counts[primary_reason] += 1
        run_path_counts = run_group.setdefault("_path_counts", Counter())
        run_path_counts[_norm_text_or_none(row.get("host_path_family")) or "(blank)"] += 1

        if len(sample_rows) < 100:
            sample_rows.append(
                {
                    "artifact_id": row.get("artifact_id"),
                    "session_stamp": session_stamp,
                    "run_id": resolved_run_id,
                    "package": package_name,
                    "artifact_path_package": artifact_path_package,
                    "legacy_package_mismatch": package_mismatch,
                    "primary_reason": primary_reason,
                    "host_path_exists": file_exists,
                    "host_path_family": row.get("host_path_family"),
                    "created_at_utc": row.get("created_at_utc"),
                    "host_path": row.get("host_path"),
                }
            )
        detailed_overlap_rows.append(
            {
                **dict(row),
                "session_stamp": session_stamp,
                "package": package_name,
                "artifact_path_package": artifact_path_package,
                "legacy_package_mismatch": package_mismatch,
                "run_id": resolved_run_id,
            }
        )

    sessions_out: list[dict[str, Any]] = []
    for _, row in session_rows.items():
        run_ids = row.pop("_run_ids", set())
        package_counts = row.pop("_packages", Counter())
        reason_counts = row.pop("_reason_counts", Counter())
        path_counts = row.pop("_path_counts", Counter())
        row["overlap_run_ids"] = len(run_ids)
        row["distinct_packages"] = len(package_counts)
        row["legacy_payload_total_rows"] = (
            int(row.get("metrics_rows") or 0)
            + int(row.get("buckets_rows") or 0)
            + int(row.get("contributor_rows") or 0)
            + int(row.get("finding_rows") or 0)
        )
        row["primary_reason_counts_json"] = json.dumps(dict(sorted(reason_counts.items())), sort_keys=True)
        row["path_family_counts_json"] = json.dumps(dict(sorted(path_counts.items())), sort_keys=True)
        row["top_packages_csv"] = ",".join(package for package, _ in package_counts.most_common(8))
        row["recommended_action"] = _session_action_with_context(
            int(row.get("file_present_registry_rows") or 0),
            int(row.get("overlap_run_ids") or 0),
            package_mismatch_rows=int(row.get("package_mismatch_registry_rows") or 0),
        )
        row["priority_bucket"] = row["recommended_action"].replace("_review", "")
        sessions_out.append(row)

    sessions_out.sort(
        key=lambda row: _session_priority(
            _norm_text(row.get("recommended_action")),
            int(row.get("overlap_run_ids") or 0),
            int(row.get("overlap_registry_rows") or 0),
        )
        + (_norm_text(row.get("session_stamp")),)
    )
    for index, row in enumerate(sessions_out, start=1):
        row["candidate_rank"] = index

    runs_out: list[dict[str, Any]] = []
    for _, row in run_rows.items():
        reason_counts = row.pop("_reason_counts", Counter())
        path_counts = row.pop("_path_counts", Counter())
        row["primary_reason_counts_json"] = json.dumps(dict(sorted(reason_counts.items())), sort_keys=True)
        row["path_family_counts_json"] = json.dumps(dict(sorted(path_counts.items())), sort_keys=True)
        row["legacy_payload_total_rows"] = (
            int(row.get("metrics_rows") or 0)
            + int(row.get("buckets_rows") or 0)
            + int(row.get("contributor_rows") or 0)
            + int(row.get("finding_rows") or 0)
        )
        runs_out.append(row)
    runs_out.sort(key=lambda row: (_norm_text(row.get("session_stamp")), int(row.get("run_id") or 0)))

    candidates = [row for row in sessions_out if _norm_text(row.get("recommended_action")).startswith("candidate_")]
    blocked = [row for row in sessions_out if _norm_text(row.get("recommended_action")).startswith("blocked_")]

    summary = {
        "legacy_overlap_registry_rows": sum(int(row.get("overlap_registry_rows") or 0) for row in sessions_out),
        "legacy_overlap_session_count": len(sessions_out),
        "legacy_overlap_run_count": len(runs_out),
        "candidate_session_count": len(candidates),
        "blocked_session_count": len(blocked),
        "candidate_registry_rows": sum(int(row.get("overlap_registry_rows") or 0) for row in candidates),
        "blocked_registry_rows": sum(int(row.get("overlap_registry_rows") or 0) for row in blocked),
        "package_mismatch_registry_rows": sum(int(row.get("package_mismatch_registry_rows") or 0) for row in sessions_out),
        "package_mismatch_session_count": sum(
            1 for row in sessions_out if int(row.get("package_mismatch_registry_rows") or 0) > 0
        ),
        "recommended_candidate_order": [str(row.get("session_stamp") or "") for row in candidates[:12]],
        "blocked_sessions": [str(row.get("session_stamp") or "") for row in blocked[:12]],
    }

    return {
        "summary": summary,
        "legacy_session_retirement_sessions": sessions_out,
        "legacy_session_retirement_candidates": candidates,
        "legacy_session_retirement_runs": runs_out,
        "legacy_session_retirement_samples": sample_rows,
        "_dangling_rows": detailed_overlap_rows,
    }


def write_static_session_retirement_bundle(report: Mapping[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, payload in (
        ("summary.json", report.get("summary") or {}),
        ("legacy_session_retirement_sessions.csv", report.get("legacy_session_retirement_sessions") or []),
        ("legacy_session_retirement_candidates.csv", report.get("legacy_session_retirement_candidates") or []),
        ("legacy_session_retirement_runs.csv", report.get("legacy_session_retirement_runs") or []),
        ("legacy_session_retirement_samples.csv", report.get("legacy_session_retirement_samples") or []),
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
    "collect_static_session_retirement_report",
    "write_static_session_retirement_bundle",
]
