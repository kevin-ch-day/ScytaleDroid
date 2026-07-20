"""Read-only correlation report for blocked static legacy-overlap sessions.

These sessions are blocked from registry-only prune because at least one
``artifact_registry`` row still points at an existing host file.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .artifact_registry_static_session_retirement import collect_static_session_retirement_report

RunSql = Callable[..., Any]

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "blocked_sessions.csv",
    "blocked_file_present_rows.csv",
    "blocked_package_rollup.csv",
    "blocked_path_family_rollup.csv",
)


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


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


def collect_static_blocked_file_presence_report(
    run_sql: RunSql,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    report = collect_static_session_retirement_report(run_sql, repo_root=repo_root)
    session_rows = [
        dict(row)
        for row in (report.get("legacy_session_retirement_sessions") or [])
        if isinstance(row, Mapping)
    ]
    blocked_sessions = [
        row
        for row in session_rows
        if _norm_text(row.get("recommended_action")).startswith("blocked_")
    ]
    blocked_session_names = {_norm_text(row.get("session_stamp")) for row in blocked_sessions}

    detailed_rows = [
        dict(row)
        for row in (report.get("_dangling_rows") or [])
        if isinstance(row, Mapping) and _norm_text(row.get("session_stamp")) in blocked_session_names
    ]
    file_present_rows = [
        row
        for row in detailed_rows
        if row.get("host_path_exists") is True
    ]
    file_present_rows.sort(
        key=lambda row: (
            _norm_text(row.get("session_stamp")),
            _norm_text(row.get("package")),
            _norm_text(row.get("host_path")),
        )
    )

    package_rollups: list[dict[str, Any]] = []
    package_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in file_present_rows:
        package_groups[(_norm_text(row.get("session_stamp")), _norm_text(row.get("package")))].append(row)
    for (session_stamp, package_name), rows in sorted(package_groups.items()):
        path_families = Counter(_norm_text_or_none(row.get("host_path_family")) or "(blank)" for row in rows)
        artifact_types = Counter(_norm_text_or_none(row.get("artifact_type")) or "(blank)" for row in rows)
        package_rollups.append(
            {
                "session_stamp": session_stamp,
                "package": package_name,
                "file_present_rows": len(rows),
                "distinct_run_ids": len({int(row.get("run_id")) for row in rows if row.get("run_id") is not None}),
                "path_families_csv": ",".join(sorted(path_families)),
                "artifact_types_csv": ",".join(sorted(artifact_types)),
                "sample_host_path": _norm_text_or_none(rows[0].get("host_path")),
            }
        )

    path_family_rollups: list[dict[str, Any]] = []
    path_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in file_present_rows:
        path_groups[(
            _norm_text(row.get("session_stamp")),
            _norm_text_or_none(row.get("host_path_family")) or "(blank)",
        )].append(row)
    for (session_stamp, path_family), rows in sorted(path_groups.items()):
        packages = Counter(_norm_text_or_none(row.get("package")) or "(blank)" for row in rows)
        path_family_rollups.append(
            {
                "session_stamp": session_stamp,
                "host_path_family": path_family,
                "file_present_rows": len(rows),
                "distinct_packages": len(packages),
                "top_packages_csv": ",".join(pkg for pkg, _ in packages.most_common(8)),
            }
        )

    summary = {
        "blocked_session_count": len(blocked_sessions),
        "blocked_sessions": [_norm_text(row.get("session_stamp")) for row in blocked_sessions],
        "blocked_file_present_row_count": len(file_present_rows),
        "blocked_registry_row_count": sum(int(row.get("overlap_registry_rows") or 0) for row in blocked_sessions),
        "blocked_file_missing_row_count": sum(int(row.get("file_missing_registry_rows") or 0) for row in blocked_sessions),
        "distinct_packages_with_present_files": len({(_norm_text(row.get("session_stamp")), _norm_text(row.get("package"))) for row in file_present_rows}),
        "distinct_path_families_with_present_files": len({_norm_text_or_none(row.get("host_path_family")) or "(blank)" for row in file_present_rows}),
    }
    return {
        "summary": summary,
        "blocked_sessions": blocked_sessions,
        "blocked_file_present_rows": file_present_rows,
        "blocked_package_rollup": package_rollups,
        "blocked_path_family_rollup": path_family_rollups,
    }


def write_static_blocked_file_presence_bundle(report: Mapping[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, payload in (
        ("summary.json", report.get("summary") or {}),
        ("blocked_sessions.csv", report.get("blocked_sessions") or []),
        ("blocked_file_present_rows.csv", report.get("blocked_file_present_rows") or []),
        ("blocked_package_rollup.csv", report.get("blocked_package_rollup") or []),
        ("blocked_path_family_rollup.csv", report.get("blocked_path_family_rollup") or []),
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
    "collect_static_blocked_file_presence_report",
    "write_static_blocked_file_presence_bundle",
]
