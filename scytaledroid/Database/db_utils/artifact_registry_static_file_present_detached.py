"""Read-only review report for file-present detached static registry rows.

These rows are dangling from ``static_analysis_runs`` but still point at files
that exist on disk. That makes them unsuitable for registry prune by the
normal detached-row cleanup path. This report produces the staged review queue
needed before any future relink/export/prune decision.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .artifact_registry_static_dangling import collect_artifact_registry_static_dangling_report

RunSql = Callable[..., Any]

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "file_present_detached_rows.csv",
    "file_present_detached_runs.csv",
    "file_present_detached_packages.csv",
    "file_present_detached_path_families.csv",
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


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _first_text(*values: Any) -> str | None:
    for value in values:
        text = _norm_text_or_none(value)
        if text:
            return text
    return None


def _extract_json_identity(host_path: Any) -> dict[str, Any]:
    path_text = _norm_text_or_none(host_path)
    if not path_text:
        return {}
    path = Path(path_text)
    if path.suffix.lower() != ".json" or not path.is_file():
        return {}
    payload = _read_json(path)
    if not payload:
        return {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}
    app = payload.get("app") if isinstance(payload.get("app"), Mapping) else {}
    run_identity = payload.get("run_identity") if isinstance(payload.get("run_identity"), Mapping) else {}
    hashes = payload.get("hashes") if isinstance(payload.get("hashes"), Mapping) else {}
    return {
        "json_package_name": _first_text(
            payload.get("package_name"),
            payload.get("package"),
            metadata.get("package_name"),
            metadata.get("normalized_package_name"),
            metadata.get("manifest_package_name"),
            app.get("package"),
            run_identity.get("package_name"),
        ),
        "json_display_name": _first_text(
            payload.get("display_name"),
            payload.get("app_label"),
            metadata.get("app_label"),
            app.get("label"),
            app.get("display_name"),
        ),
        "json_version_name": _first_text(
            payload.get("version_name"),
            metadata.get("version_name"),
            app.get("version_name"),
            run_identity.get("version_name"),
        ),
        "json_version_code": _first_text(
            payload.get("version_code"),
            metadata.get("version_code"),
            app.get("version_code"),
            run_identity.get("version_code"),
        ),
        "json_base_apk_sha256": _first_text(
            payload.get("base_apk_sha256"),
            payload.get("apk_sha256"),
            payload.get("sha256"),
            metadata.get("base_apk_sha256"),
            metadata.get("sha256"),
            app.get("base_apk_sha256"),
            hashes.get("sha256"),
        ),
        "json_session_stamp": _first_text(
            payload.get("session_stamp"),
            payload.get("session_label"),
            metadata.get("session_stamp"),
            metadata.get("session_label"),
            run_identity.get("session_stamp"),
        ),
    }


def _review_class_for_run(row: Mapping[str, Any]) -> str:
    row_count = int(row.get("row_count") or 0)
    artifact_types = set(filter(None, _norm_text(row.get("artifact_types_csv")).split(",")))
    if _norm_bool(row.get("core_bundle_complete")):
        return "REVIEW_PRESENT_COMPLETE_CORE_BUNDLE"
    if artifact_types == {"static_report"}:
        return "REVIEW_PRESENT_REPORT_ONLY"
    if row_count > 1:
        return "REVIEW_PRESENT_PARTIAL_BUNDLE"
    return "REVIEW_PRESENT_SINGLE_FILE"


def _collect_canonical_static_coverage(run_sql: RunSql) -> dict[str, list[dict[str, Any]]]:
    rows = run_sql(
        """
        SELECT
          sar.id AS static_run_id,
          LOWER(a.package_name) AS package_name_lc,
          a.package_name,
          av.version_code,
          av.version_name,
          sar.base_apk_sha256,
          sar.artifact_set_hash,
          sar.session_stamp,
          sar.created_at,
          sar.status,
          sar.run_class,
          sar.identity_valid
        FROM static_analysis_runs sar
        LEFT JOIN app_versions av
          ON av.id = sar.app_version_id
        LEFT JOIN apps a
          ON a.id = av.app_id
        WHERE sar.status = 'COMPLETED'
          AND sar.run_class = 'CANONICAL'
          AND sar.identity_valid = 1
          AND a.package_name IS NOT NULL
        ORDER BY sar.created_at DESC, sar.id DESC
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="artifact_registry_static_file_present_detached.canonical_coverage",
    ) or []
    by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        package_lc = _norm_text(row.get("package_name_lc")).lower()
        if package_lc:
            by_package[package_lc].append(dict(row))
    return by_package


def _coverage_for_identity(
    *,
    package_name: str | None,
    version_code: str | None,
    base_apk_sha256: str | None,
    canonical_by_package: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    package_lc = _norm_text(package_name).lower()
    version_code_text = _norm_text_or_none(version_code)
    sha = _norm_text(base_apk_sha256).lower()
    if not package_lc:
        return {
            "canonical_coverage_class": "UNKNOWN_PACKAGE_IDENTITY",
            "canonical_match_static_run_id": None,
            "canonical_match_session_stamp": None,
            "canonical_match_version_code": None,
            "canonical_match_version_name": None,
            "canonical_match_base_apk_sha256": None,
        }
    candidates = list(canonical_by_package.get(package_lc) or [])
    if not candidates:
        return {
            "canonical_coverage_class": "NO_CANONICAL_PACKAGE_MATCH",
            "canonical_match_static_run_id": None,
            "canonical_match_session_stamp": None,
            "canonical_match_version_code": None,
            "canonical_match_version_name": None,
            "canonical_match_base_apk_sha256": None,
        }

    def _match_payload(row: Mapping[str, Any], coverage_class: str) -> dict[str, Any]:
        return {
            "canonical_coverage_class": coverage_class,
            "canonical_match_static_run_id": row.get("static_run_id"),
            "canonical_match_session_stamp": row.get("session_stamp"),
            "canonical_match_version_code": row.get("version_code"),
            "canonical_match_version_name": row.get("version_name"),
            "canonical_match_base_apk_sha256": row.get("base_apk_sha256"),
        }

    if sha:
        for row in candidates:
            if _norm_text(row.get("base_apk_sha256")).lower() == sha:
                return _match_payload(row, "COVERED_BY_CANONICAL_SAME_HASH")
    if version_code_text:
        for row in candidates:
            if _norm_text(row.get("version_code")) == version_code_text:
                return _match_payload(row, "COVERED_BY_CANONICAL_SAME_VERSION")
    latest = candidates[0]
    latest_version_code = _norm_text_or_none(latest.get("version_code"))
    if version_code_text and latest_version_code:
        try:
            if int(latest_version_code) > int(version_code_text):
                return _match_payload(latest, "SUPERSEDED_BY_NEWER_CANONICAL_VERSION")
        except ValueError:
            pass
    return _match_payload(latest, "PACKAGE_HAS_CANONICAL_DIFFERENT_VERSION")


def _staged_action_for_coverage(coverage_class: Any) -> str:
    cls = _norm_text(coverage_class)
    if cls == "COVERED_BY_CANONICAL_SAME_HASH":
        return "STAGE_EXACT_HASH_REGISTRY_RESOLUTION_REVIEW"
    if cls == "COVERED_BY_CANONICAL_SAME_VERSION":
        return "STAGE_SAME_VERSION_COVERAGE_REVIEW"
    if cls == "SUPERSEDED_BY_NEWER_CANONICAL_VERSION":
        return "STAGE_PRIOR_VERSION_RETENTION_REVIEW"
    if cls == "PACKAGE_HAS_CANONICAL_DIFFERENT_VERSION":
        return "STAGE_IDENTITY_GAP_OR_HISTORICAL_REVIEW"
    if cls == "NO_CANONICAL_PACKAGE_MATCH":
        return "STAGE_NO_CANONICAL_PACKAGE_MATCH_REVIEW"
    return "STAGE_UNKNOWN_IDENTITY_REVIEW"


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


def collect_static_file_present_detached_report(
    run_sql: RunSql,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    dangling = collect_artifact_registry_static_dangling_report(run_sql, repo_root=repo_root)
    canonical_by_package = _collect_canonical_static_coverage(run_sql)
    run_lookup = {
        str(row.get("resolved_static_run_id") or ""): dict(row)
        for row in (dangling.get("static_dangling_runs") or [])
        if isinstance(row, Mapping)
    }
    row_records: list[dict[str, Any]] = []
    for row in dangling.get("static_dangling_rows") or []:
        if not isinstance(row, Mapping):
            continue
        if _norm_text(row.get("primary_reason")) != "file_present_db_detached":
            continue
        run_id = str(row.get("resolved_static_run_id") or "")
        run_row = run_lookup.get(run_id, {})
        json_identity = _extract_json_identity(row.get("host_path"))
        package_name = _first_text(
            row.get("meta_package_name"),
            run_row.get("recovered_package_name"),
            json_identity.get("json_package_name"),
        )
        version_code = _first_text(
            run_row.get("recovered_version_code"),
            json_identity.get("json_version_code"),
        )
        version_name = _first_text(
            run_row.get("recovered_version_name"),
            json_identity.get("json_version_name"),
        )
        base_apk_sha256 = _first_text(
            run_row.get("recovered_base_apk_sha256"),
            json_identity.get("json_base_apk_sha256"),
        )
        row_records.append(
            {
                **dict(row),
                **json_identity,
                "review_class": _review_class_for_run(run_row),
                "review_action": "review_export_or_relink_before_registry_prune",
                "recovered_package_name": run_row.get("recovered_package_name"),
                "recovered_display_name": run_row.get("recovered_display_name"),
                "recovered_version_name": run_row.get("recovered_version_name"),
                "recovered_version_code": run_row.get("recovered_version_code"),
                "recovered_base_apk_sha256": run_row.get("recovered_base_apk_sha256"),
                "recovered_run_manifest_exists": run_row.get("recovered_run_manifest_exists"),
                "run_core_bundle_complete": run_row.get("core_bundle_complete"),
                "run_row_count": run_row.get("row_count"),
                "inferred_package_name": package_name,
                "inferred_version_name": version_name,
                "inferred_version_code": version_code,
                "inferred_base_apk_sha256": base_apk_sha256,
            }
        )

    run_identity_fallbacks: dict[str, dict[str, str | None]] = {}
    grouped_for_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in row_records:
        grouped_for_identity[str(row.get("resolved_static_run_id") or "")].append(row)
    for run_id, group_rows in grouped_for_identity.items():
        run_identity_fallbacks[run_id] = {
            "package_name": _first_text(*(row.get("inferred_package_name") for row in group_rows)),
            "version_name": _first_text(*(row.get("inferred_version_name") for row in group_rows)),
            "version_code": _first_text(*(row.get("inferred_version_code") for row in group_rows)),
            "base_apk_sha256": _first_text(*(row.get("inferred_base_apk_sha256") for row in group_rows)),
        }

    rows_out: list[dict[str, Any]] = []
    for row in row_records:
        fallback = run_identity_fallbacks.get(str(row.get("resolved_static_run_id") or ""), {})
        package_name = _first_text(row.get("inferred_package_name"), fallback.get("package_name"))
        version_name = _first_text(row.get("inferred_version_name"), fallback.get("version_name"))
        version_code = _first_text(row.get("inferred_version_code"), fallback.get("version_code"))
        base_apk_sha256 = _first_text(row.get("inferred_base_apk_sha256"), fallback.get("base_apk_sha256"))
        coverage = _coverage_for_identity(
            package_name=package_name,
            version_code=version_code,
            base_apk_sha256=base_apk_sha256,
            canonical_by_package=canonical_by_package,
        )
        staged_action = _staged_action_for_coverage(coverage.get("canonical_coverage_class"))
        rows_out.append(
            {
                **row,
                **coverage,
                "staged_review_action": staged_action,
                "registry_resolution_candidate": coverage.get("canonical_coverage_class") == "COVERED_BY_CANONICAL_SAME_HASH",
                "run_identity_fallback_used": (
                    not _norm_text_or_none(row.get("inferred_base_apk_sha256"))
                    and _norm_text_or_none(base_apk_sha256) is not None
                ),
                "inferred_package_name": package_name,
                "inferred_version_name": version_name,
                "inferred_version_code": version_code,
                "inferred_base_apk_sha256": base_apk_sha256,
            }
        )

    runs_out: list[dict[str, Any]] = []
    grouped_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows_out:
        grouped_rows[str(row.get("resolved_static_run_id") or "")].append(row)
    for run_id, group_rows in sorted(grouped_rows.items(), key=lambda item: (item[1][0].get("created_at_utc") or "", item[0])):
        run_row = run_lookup.get(run_id, {})
        packages = Counter(_norm_text_or_none(row.get("inferred_package_name")) or "(unknown)" for row in group_rows)
        path_families = Counter(_norm_text_or_none(row.get("host_path_family")) or "(blank)" for row in group_rows)
        artifact_types = Counter(_norm_text_or_none(row.get("artifact_type")) or "(blank)" for row in group_rows)
        coverage_classes = Counter(_norm_text_or_none(row.get("canonical_coverage_class")) or "(blank)" for row in group_rows)
        staged_actions = Counter(_norm_text_or_none(row.get("staged_review_action")) or "(blank)" for row in group_rows)
        review_class = _review_class_for_run(run_row)
        runs_out.append(
            {
                "resolved_static_run_id": run_id,
                "file_present_rows": len(group_rows),
                "review_class": review_class,
                "review_action": "review_export_or_relink_before_registry_prune",
                "top_package": packages.most_common(1)[0][0] if packages else "(unknown)",
                "distinct_packages": len(packages),
                "path_families_csv": ",".join(sorted(path_families)),
                "artifact_types_csv": ",".join(sorted(artifact_types)),
                "canonical_coverage_classes_csv": ",".join(sorted(coverage_classes)),
                "staged_review_actions_csv": ",".join(sorted(staged_actions)),
                "created_at_min_utc": min(str(row.get("created_at_utc") or "") for row in group_rows),
                "created_at_max_utc": max(str(row.get("created_at_utc") or "") for row in group_rows),
                "recovered_run_manifest_exists": run_row.get("recovered_run_manifest_exists"),
                "core_bundle_complete": run_row.get("core_bundle_complete"),
                "recovered_package_name": run_row.get("recovered_package_name"),
                "recovered_display_name": run_row.get("recovered_display_name"),
                "recovered_version_name": run_row.get("recovered_version_name"),
                "recovered_version_code": run_row.get("recovered_version_code"),
                "recovered_base_apk_sha256": run_row.get("recovered_base_apk_sha256"),
            }
        )

    package_rollup: list[dict[str, Any]] = []
    package_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows_out:
        package_groups[_norm_text_or_none(row.get("inferred_package_name")) or "(unknown)"].append(row)
    for package_name, group_rows in sorted(package_groups.items(), key=lambda item: (-len(item[1]), item[0])):
        package_rollup.append(
            {
                "package_name": package_name,
                "file_present_rows": len(group_rows),
                "registry_resolution_candidate_rows": sum(1 for row in group_rows if _norm_bool(row.get("registry_resolution_candidate"))),
                "distinct_static_run_ids": len({_norm_text(row.get("resolved_static_run_id")) for row in group_rows}),
                "distinct_versions": len({
                    (
                        _norm_text_or_none(row.get("inferred_version_code")) or "",
                        _norm_text_or_none(row.get("inferred_version_name")) or "",
                    )
                    for row in group_rows
                }),
                "review_classes_csv": ",".join(sorted({_norm_text(row.get("review_class")) for row in group_rows})),
                "canonical_coverage_classes_csv": ",".join(sorted({_norm_text(row.get("canonical_coverage_class")) for row in group_rows})),
                "staged_review_actions_csv": ",".join(sorted({_norm_text(row.get("staged_review_action")) for row in group_rows})),
                "path_families_csv": ",".join(sorted({_norm_text(row.get("host_path_family")) for row in group_rows})),
                "sample_host_path": group_rows[0].get("host_path"),
            }
        )

    path_family_rollup = [
        {"host_path_family": family, "file_present_rows": count}
        for family, count in sorted(
            Counter(_norm_text_or_none(row.get("host_path_family")) or "(blank)" for row in rows_out).items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]
    review_class_counts = Counter(_norm_text(row.get("review_class")) for row in rows_out)
    canonical_coverage_counts = Counter(_norm_text(row.get("canonical_coverage_class")) for row in rows_out)
    staged_action_counts = Counter(_norm_text(row.get("staged_review_action")) for row in rows_out)
    session_counts = Counter(_norm_text_or_none(row.get("json_session_stamp")) or _norm_text_or_none(row.get("meta_session_stamp")) or "(unknown)" for row in rows_out)
    summary = {
        "file_present_detached_row_count": len(rows_out),
        "file_present_detached_run_count": len(runs_out),
        "distinct_inferred_package_count": len(package_groups),
        "rows_with_json_identity": sum(1 for row in rows_out if _norm_text_or_none(row.get("json_package_name"))),
        "rows_using_run_identity_fallback": sum(1 for row in rows_out if _norm_bool(row.get("run_identity_fallback_used"))),
        "runs_with_complete_core_bundle": sum(1 for row in runs_out if _norm_bool(row.get("core_bundle_complete"))),
        "runs_with_recovered_manifest_context": sum(1 for row in runs_out if _norm_bool(row.get("recovered_run_manifest_exists"))),
        "registry_resolution_candidate_rows": sum(1 for row in rows_out if _norm_bool(row.get("registry_resolution_candidate"))),
        "review_class_counts": dict(sorted(review_class_counts.items())),
        "canonical_coverage_counts": dict(sorted(canonical_coverage_counts.items())),
        "staged_review_action_counts": dict(sorted(staged_action_counts.items())),
        "top_session_stamps": [
            {"session_stamp": session, "file_present_rows": count}
            for session, count in session_counts.most_common(12)
        ],
        "path_family_counts": {row["host_path_family"]: row["file_present_rows"] for row in path_family_rollup},
        "safe_prune_rows": 0,
        "reason": "host files exist; review/export or relink before any registry-only prune",
    }
    return {
        "summary": summary,
        "file_present_detached_rows": rows_out,
        "file_present_detached_runs": runs_out,
        "file_present_detached_packages": package_rollup,
        "file_present_detached_path_families": path_family_rollup,
    }


def write_static_file_present_detached_bundle(report: Mapping[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, payload in (
        ("summary.json", report.get("summary") or {}),
        ("file_present_detached_rows.csv", report.get("file_present_detached_rows") or []),
        ("file_present_detached_runs.csv", report.get("file_present_detached_runs") or []),
        ("file_present_detached_packages.csv", report.get("file_present_detached_packages") or []),
        ("file_present_detached_path_families.csv", report.get("file_present_detached_path_families") or []),
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
    "collect_static_file_present_detached_report",
    "write_static_file_present_detached_bundle",
]
