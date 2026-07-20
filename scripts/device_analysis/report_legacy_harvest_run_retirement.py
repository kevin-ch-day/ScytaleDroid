#!/usr/bin/env python3
"""Read-only legacy harvest run-folder retirement report."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from scripts.device_analysis.report_apk_inventory_model import (
        DEFAULT_COLD_ROOT,
        _index_canonical_store,
        _load_apk_library,
        _load_latest_cold_audit,
        _read_json,
        _summarize_legacy_dependencies,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution path
    from report_apk_inventory_model import (
        DEFAULT_COLD_ROOT,
        _index_canonical_store,
        _load_apk_library,
        _load_latest_cold_audit,
        _read_json,
        _summarize_legacy_dependencies,
    )


RunSql = Callable[..., Any]


def build_report(
    *,
    data_root: Path,
    output_root: Path | None = None,
    cold_root: Path = DEFAULT_COLD_ROOT,
    stamp: str | None = None,
    write_outputs: bool = True,
    run_sql: RunSql | None = None,
) -> dict[str, object]:
    data_root = data_root.expanduser()
    repo_root = data_root.parent
    stamp = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = output_root or repo_root / "output" / "audit" / "legacy_harvest_run_retirement" / stamp
    canonical = _index_canonical_store(data_root=data_root, cold_root=cold_root)
    library = _load_apk_library(data_root=data_root, canonical=canonical)
    storage_rows = _summarize_legacy_dependencies(data_root=data_root, library_shas=library["library_shas"], canonical=canonical)
    observed = _session_observed_hashes(data_root)
    cold_audit = _load_latest_cold_audit(repo_root / "output" / "audit" / "apk_cold_promotion")
    session_labels = [str(row["session_label"]) for row in storage_rows]
    db_rows, db_status = collect_db_references(session_labels, run_sql=run_sql)
    db_by_session = {str(row["session_label"]): row for row in db_rows}
    rows: list[dict[str, object]] = []
    reference_rows: list[dict[str, object]] = []
    for row in storage_rows:
        session = str(row["session_label"])
        db_ref = db_by_session.get(session, _empty_reference_row(session, source_status=db_status))
        protection = _protection_flags(observed.get(session, set()), cold_audit["classes_by_sha"])
        merged_ref = _merge_reference_flags(db_ref, protection)
        reference_rows.append(merged_ref)
        enriched = _merge_reference_row(row, merged_ref, protection, db_status=db_status)
        rows.append(enriched)
    archive_candidates = [row for row in rows if str(row["retirement_class"]).startswith("ARCHIVE_CANDIDATE")]
    blocked = [row for row in rows if row not in archive_candidates]
    summary = {
        "schema_version": "legacy_harvest_run_retirement_v2",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": data_root.as_posix(),
        "session_count": len(rows),
        "db_reference_status": db_status,
        "archive_candidate_count": len(archive_candidates),
        "archive_candidate_storage_safe_db_clear": sum(
            1 for row in archive_candidates if row["retirement_class"] == "ARCHIVE_CANDIDATE_STORAGE_SAFE_DB_CLEAR"
        ),
        "archive_candidate_provenance_only": sum(
            1 for row in archive_candidates if row["retirement_class"] == "ARCHIVE_CANDIDATE_PROVENANCE_ONLY"
        ),
        "sessions_with_regular_apks": sum(1 for row in rows if int(row["regular_apks"] or 0) > 0),
        "sessions_with_broken_apk_symlinks": sum(1 for row in rows if int(row["broken_apk_symlinks"] or 0) > 0),
        "sessions_with_unindexed_observed_artifacts": sum(1 for row in rows if row["all_apk_artifacts_indexed_in_apk_library"] == "no"),
        "referenced_by_static": sum(1 for row in rows if row["referenced_by_static"] == "yes"),
        "referenced_by_dynamic": sum(1 for row in rows if row["referenced_by_dynamic"] == "yes"),
        "referenced_by_active_dynamic_lineage": sum(1 for row in rows if row["referenced_by_active_dynamic_lineage"] == "yes"),
        "referenced_by_paper_freeze": sum(1 for row in rows if row["referenced_by_paper_freeze"] == "yes"),
        "referenced_by_current_research_dataset_beta": sum(
            1 for row in rows if row["referenced_by_current_research_dataset_beta"] == "yes"
        ),
        "referenced_by_current_installed_build": sum(1 for row in rows if row["referenced_by_current_installed_build"] == "yes"),
        "referenced_by_reports_or_exports": sum(1 for row in rows if row["referenced_by_reports_or_exports"] == "yes"),
        "retirement_class_counts": dict(Counter(str(row["retirement_class"]) for row in rows)),
        "note": "Read-only report. Archive candidates still require operator review; no folders were archived or deleted.",
    }
    outputs = {
        "summary_json": output_root / "summary.json",
        "runs_csv": output_root / "legacy_runs.csv",
        "db_references_csv": output_root / "db_references.csv",
        "archive_candidates_csv": output_root / "archive_candidates.csv",
        "blocked_csv": output_root / "blocked.csv",
    }
    if write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        outputs["summary_json"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _write_csv(outputs["runs_csv"], rows)
        _write_csv(outputs["db_references_csv"], reference_rows)
        _write_csv(outputs["archive_candidates_csv"], archive_candidates)
        _write_csv(outputs["blocked_csv"], blocked)
    return {"summary": summary, "outputs": {key: value.as_posix() for key, value in outputs.items()}, "rows": rows, "blocked": blocked}


def collect_db_references(session_labels: list[str], *, run_sql: RunSql | None = None) -> tuple[list[dict[str, object]], str]:
    if not session_labels:
        return [], "no_sessions"
    runner = run_sql or _load_run_sql()
    if runner is None:
        return [_empty_reference_row(session, source_status="db_unavailable") for session in session_labels], "db_unavailable"
    rows: list[dict[str, object]] = []
    for session in session_labels:
        try:
            rows.append(_collect_one_db_reference(session, runner))
        except Exception as exc:
            rows.append(_empty_reference_row(session, source_status=f"db_error:{type(exc).__name__}"))
    status = "db_checked" if any(row["source_status"] == "db_checked" for row in rows) else "db_checked_with_errors"
    return rows, status


def _collect_one_db_reference(session: str, run_sql: RunSql) -> dict[str, object]:
    flags = _empty_reference_row(session, source_status="db_checked")
    static_count = _count_query(
        run_sql,
        """
        SELECT COUNT(*) AS n
        FROM static_analysis_runs
        WHERE session_stamp = %s OR session_label = %s
        """,
        (session, session),
    )
    static_link_count = _count_query(
        run_sql,
        """
        SELECT COUNT(*) AS n
        FROM harvest_sessions hs
        JOIN harvest_apk_observations hao ON hao.harvest_session_id = hs.harvest_session_id
        JOIN static_analysis_runs sar ON sar.apk_set_id = hao.apk_set_id
        WHERE hs.session_label = %s
        """,
        (session,),
    )
    artifact_static_count = _count_query(
        run_sql,
        """
        SELECT COUNT(*) AS n
        FROM artifact_registry
        WHERE run_type = 'static'
          AND (session_stamp = %s OR host_path LIKE %s OR meta_json LIKE %s)
        """,
        (session, _session_like(session), _json_like(session)),
    )
    artifact_dynamic_count = _count_query(
        run_sql,
        """
        SELECT COUNT(*) AS n
        FROM artifact_registry
        WHERE run_type = 'dynamic'
          AND (session_stamp = %s OR host_path LIKE %s OR meta_json LIKE %s)
        """,
        (session, _session_like(session), _json_like(session)),
    )
    any_report_count = _count_query(
        run_sql,
        """
        SELECT COUNT(*) AS n
        FROM artifact_registry
        WHERE session_stamp = %s OR host_path LIKE %s OR meta_json LIKE %s
        """,
        (session, _session_like(session), _json_like(session)),
    )
    flags.update(
        {
            "static_reference_count": static_count + static_link_count + artifact_static_count,
            "dynamic_reference_count": artifact_dynamic_count,
            "report_export_reference_count": any_report_count,
            "referenced_by_static": _yn(static_count + static_link_count + artifact_static_count),
            "referenced_by_dynamic": _yn(artifact_dynamic_count),
            "referenced_by_reports_or_exports": _yn(any_report_count),
        }
    )
    return flags


def _load_run_sql() -> RunSql | None:
    if "pytest" in sys.argv[:1] or "PYTEST_CURRENT_TEST" in os.environ:
        return None
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core.db_queries import run_sql
    except Exception:
        return None
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        return None
    return run_sql


def _count_query(run_sql: RunSql, query: str, params: tuple[object, ...]) -> int:
    try:
        row = run_sql(query, params, fetch="one_dict", query_name="legacy_harvest_run_retirement.reference_count")
    except Exception:
        return 0
    try:
        return int((row or {}).get("n") or 0)
    except Exception:
        return 0


def _session_like(session: str) -> str:
    return f"%/runs/{session}/%"


def _json_like(session: str) -> str:
    return f"%{session}%"


def _empty_reference_row(session: str, *, source_status: str) -> dict[str, object]:
    unknown = "unknown" if source_status != "db_checked" else "no"
    return {
        "session_label": session,
        "source_status": source_status,
        "referenced_by_static": unknown,
        "referenced_by_dynamic": unknown,
        "referenced_by_active_dynamic_lineage": "unknown",
        "referenced_by_paper_freeze": "unknown",
        "referenced_by_current_research_dataset_beta": "unknown",
        "referenced_by_current_installed_build": "unknown",
        "referenced_by_reports_or_exports": unknown,
        "static_reference_count": 0,
        "dynamic_reference_count": 0,
        "report_export_reference_count": 0,
    }


def _session_observed_hashes(data_root: Path) -> dict[str, set[str]]:
    observed: dict[str, set[str]] = defaultdict(set)
    for manifest in sorted((data_root / "device_apks").glob("*/runs/*/**/harvest_package_manifest.json")):
        parts = manifest.parts
        if "runs" not in parts:
            continue
        idx = parts.index("runs")
        if idx + 1 >= len(parts):
            continue
        session = parts[idx + 1]
        payload = _read_json(manifest)
        execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
        for item in execution.get("observed_artifacts") or []:
            if not isinstance(item, dict):
                continue
            sha = str(item.get("sha256") or "").strip().lower()
            if len(sha) == 64:
                observed[session].add(sha)
    return observed


def _protection_flags(shas: set[str], classes_by_sha: Mapping[str, str]) -> dict[str, object]:
    classes = Counter(classes_by_sha.get(sha, "") for sha in shas)
    return {
        "referenced_by_paper_freeze": _yn(classes.get("KEEP_HOT_SELECTED_PAPER_TARGET", 0)),
        "referenced_by_current_research_dataset_beta": _yn(classes.get("KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA", 0)),
        "referenced_by_current_installed_build": _yn(classes.get("KEEP_HOT_CURRENT_INSTALLED_BUILD", 0)),
        "referenced_by_active_dynamic_lineage": _yn(classes.get("KEEP_HOT_ACTIVE_DYNAMIC_LINEAGE", 0)),
        "paper_freeze_artifact_count": classes.get("KEEP_HOT_SELECTED_PAPER_TARGET", 0),
        "current_research_dataset_beta_artifact_count": classes.get("KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA", 0),
        "current_installed_artifact_count": classes.get("KEEP_HOT_CURRENT_INSTALLED_BUILD", 0),
        "active_dynamic_lineage_artifact_count": classes.get("KEEP_HOT_ACTIVE_DYNAMIC_LINEAGE", 0),
    }


def _merge_reference_flags(db_ref: Mapping[str, object], protection: Mapping[str, object]) -> dict[str, object]:
    row = {**db_ref, **protection}
    if db_ref.get("referenced_by_dynamic") == "yes" or protection.get("referenced_by_active_dynamic_lineage") == "yes":
        row["referenced_by_dynamic"] = "yes"
    elif db_ref.get("referenced_by_dynamic") == "unknown":
        row["referenced_by_dynamic"] = "unknown"
    else:
        row["referenced_by_dynamic"] = "no"
    return row


def _merge_reference_row(
    storage_row: Mapping[str, object],
    db_ref: Mapping[str, object],
    protection: Mapping[str, object],
    *,
    db_status: str,
) -> dict[str, object]:
    row = {**storage_row, **db_ref, **protection}
    retirement_class, reason, safe = _retirement_decision(row, db_status=db_status)
    row["retirement_class"] = retirement_class
    row["reason"] = reason
    row["safe_to_archive_later"] = safe
    row["indexed_artifact_count"] = int(row.get("observed_sha_count") or 0) if row.get("all_apk_artifacts_indexed_in_apk_library") == "yes" else 0
    row["unindexed_artifact_count"] = (
        0 if row.get("all_apk_artifacts_indexed_in_apk_library") == "yes" else int(row.get("observed_sha_count") or 0)
    )
    return row


def _retirement_decision(row: Mapping[str, object], *, db_status: str) -> tuple[str, str, str]:
    if int(row.get("regular_apks") or 0) > 0:
        return "RETAIN_HAS_REGULAR_APKS", "regular APK payloads remain in legacy run folder", "no"
    if int(row.get("broken_apk_symlinks") or 0) > 0:
        return "RETAIN_METADATA_INCOMPLETE", "broken APK symlinks remain in legacy run folder", "no"
    if row.get("referenced_by_dynamic") == "yes":
        return "RETAIN_ACTIVE_DYNAMIC_REFERENCE", "DB/read-model or active dynamic lineage references this session", "no"
    if row.get("referenced_by_static") == "yes":
        return "RETAIN_ACTIVE_STATIC_REFERENCE", "DB/read-model references static artifacts or runs for this session", "no"
    if row.get("referenced_by_paper_freeze") == "yes":
        return "RETAIN_PAPER_FREEZE_REFERENCE", "observed artifacts are protected by paper-freeze target status", "no"
    if row.get("referenced_by_current_research_dataset_beta") == "yes":
        return "RETAIN_CURRENT_RESEARCH_DATASET_BETA", "observed artifacts are protected by current Research Dataset Beta status", "no"
    if row.get("referenced_by_current_installed_build") == "yes":
        return "RETAIN_CURRENT_INSTALLED_BUILD", "observed artifacts are protected by current installed/current-build status", "no"
    if row.get("referenced_by_reports_or_exports") == "yes":
        return "RETAIN_REPORT_EXPORT_REFERENCE", "artifact registry reports or exports still reference this session", "no"
    if row.get("all_apk_artifacts_indexed_in_apk_library") == "no" or row.get("all_apk_bytes_available_hot_or_cold") == "no":
        return "RETAIN_METADATA_INCOMPLETE", "observed artifacts are unindexed or byte-unavailable", "no"
    if any(row.get(key) == "unknown" for key in (
        "referenced_by_static",
        "referenced_by_dynamic",
        "referenced_by_reports_or_exports",
    )):
        return "BLOCKED_UNKNOWN_DB_REFERENCE", f"DB reference state is not fully known ({db_status})", "no"
    if int(row.get("observed_sha_count") or 0) == 0:
        return "ARCHIVE_CANDIDATE_PROVENANCE_ONLY", "no observed APK bytes and no active DB references found", "yes"
    return "ARCHIVE_CANDIDATE_STORAGE_SAFE_DB_CLEAR", "storage safe and DB/read-model references clear", "yes"


def _yn(count: int) -> str:
    return "yes" if int(count or 0) > 0 else "no"


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--cold-root", type=Path, default=DEFAULT_COLD_ROOT)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = build_report(data_root=args.data_root, output_root=args.output_root, cold_root=args.cold_root, stamp=args.stamp)
    if args.json:
        print(json.dumps({"summary": report["summary"], "outputs": report["outputs"]}, indent=2, sort_keys=True))
    else:
        print("Legacy harvest run retirement report")
        print(f"  Summary : {report['outputs']['summary_json']}")
        print(f"  Sessions: {report['summary']['session_count']}")
        print(f"  Storage-safe later: {report['summary']['storage_safe_to_archive_later']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
