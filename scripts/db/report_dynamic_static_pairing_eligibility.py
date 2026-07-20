#!/usr/bin/env python3
"""Read-only dynamic/static paired-analysis eligibility report.

Classifies dynamic sessions by whether they already have exact canonical static
coverage, could become paired after a safe link preview, need exact static
analysis from available bytes, require reharvest, or are historical identities
without local bytes.

No DDL, DML, filesystem writes, static runs, or dynamic links are made.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument("--package", dest="package_name", help="Limit to one package name.")
    parser.add_argument(
        "--limit",
        type=int,
        default=5000,
        help="Maximum dynamic sessions to classify (default 5000).",
    )
    parser.add_argument(
        "--old-root-policy",
        choices=("restore", "unrecoverable"),
        default="unrecoverable",
        help=(
            "How to classify exact gaps whose recorded storage root is missing. "
            "Default: unrecoverable."
        ),
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help=(
            "Write a read-only audit bundle under output/audit/dynamic_static_pairing_eligibility. "
            "No DB rows or APK files are changed."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Report output directory when --write-report is used.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_queries.sql_typed_reads import (
            resolved_dynamic_session_static_run_id,
        )
        from scytaledroid.Database.db_scripts.dynamic_static_alignment_report import (
            HASH_EQ_DS_SAR,
            SAR_QUALIFYING_SQL,
            sql_worklist,
        )
        from scytaledroid.StaticAnalysis.cli.flows.exact_target import (
            assess_exact_target_readiness,
        )
        from scytaledroid.StaticAnalysis.core.repository import group_artifacts

        from scripts.db import report_dynamic_static_recovery_plan as recovery
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    dynamic_rows = _fetch_dynamic_sessions(
        core_q,
        package_name=args.package_name,
        limit=max(1, min(int(args.limit), 5000)),
        hash_eq_ds_sar=HASH_EQ_DS_SAR,
        sar_qualifying_sql=SAR_QUALIFYING_SQL,
        resolved_static_run_expr=resolved_dynamic_session_static_run_id("ds"),
    )
    recovery_actions = _build_recovery_action_map(
        core_q,
        sql_worklist=sql_worklist,
        assess_exact_target_readiness=assess_exact_target_readiness,
        group_artifacts=group_artifacts,
        recovery_action=recovery._recovery_action,
        package_name=args.package_name,
        old_root_policy=args.old_root_policy,
    )

    sessions: list[dict[str, Any]] = []
    for row in dynamic_rows:
        package = str(row.get("package_name") or "").strip().lower()
        base_hash = _norm_sha(row.get("base_apk_sha256"))
        recovery_action = recovery_actions.get((package, base_hash))
        classification = _classify_session(row, recovery_action=recovery_action)
        dataset_use = _dataset_use_for_session(row, classification=classification)
        sessions.append(
            {
                "dynamic_run_id": row.get("dynamic_run_id"),
                "package_name": package,
                "version_code": row.get("version_code"),
                "version_name": row.get("version_name"),
                "base_apk_sha256": base_hash or None,
                "static_run_id": row.get("static_run_id"),
                "started_at_utc": _stringify(row.get("started_at_utc")),
                "status": row.get("status"),
                "valid_dataset_run": row.get("valid_dataset_run"),
                "countable": row.get("countable"),
                "technical_validity_state": row.get("technical_validity_state"),
                "quota_state": row.get("quota_state"),
                "cohort_eligibility_state": row.get("cohort_eligibility_state"),
                "cohort_paper_eligible": row.get("cohort_paper_eligible"),
                "low_signal": row.get("low_signal"),
                "paired_exact_static": bool(row.get("linked_exact_static")),
                "exact_static_available": bool(row.get("unlinked_exact_static_available")),
                "recovery_action": recovery_action,
                "classification": classification,
                "recommended_dataset_use": dataset_use,
            }
        )

    packages = _package_summary(sessions)
    payload = {
        "report_type": "dynamic_static_pairing_eligibility",
        "schema_version": "1",
        "filters": {
            "package_name": args.package_name,
            "limit": max(1, min(int(args.limit), 5000)),
            "old_root_policy": args.old_root_policy,
        },
        "summary": _summary(sessions),
        "packages": packages,
        "sessions": sessions,
        "notes": [
            "This report is read-only; it does not update dynamic_sessions.static_run_id.",
            "Exact paired analysis requires a completed canonical identity-valid static run for the same base_apk_sha256.",
            "Rows classified historical_identity_only, restore_required, or unrecoverable_without_archive need external APK bytes before exact static analysis can run.",
            "recommended_dataset_use prefers normalized governance from v_dynamic_run_context_v1 when available.",
        ],
    }
    if args.write_report or args.output_dir:
        output_dir = (
            Path(args.output_dir)
            if args.output_dir
            else Path("output/audit/dynamic_static_pairing_eligibility") / _utc_stamp()
        )
        payload["output_files"] = _write_report_bundle(payload, output_dir=output_dir)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    _print_text(payload)
    return 0


def _fetch_dynamic_sessions(
    core_q: Any,
    *,
    package_name: str | None,
    limit: int,
    hash_eq_ds_sar: str,
    sar_qualifying_sql: str,
    resolved_static_run_expr: str,
) -> list[dict[str, Any]]:
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(ds.package_name)) = %s"
        params.append(str(package_name).strip().lower())
    params.append(limit)
    base_select = f"""
        SELECT
          ds.dynamic_run_id,
          LOWER(TRIM(ds.package_name)) AS package_name,
          ds.version_code,
          ds.version_name,
          LOWER(TRIM(ds.base_apk_sha256)) AS base_apk_sha256,
          {resolved_static_run_expr} AS static_run_id,
          ds.status,
          {{valid_dataset_run_expr}} AS valid_dataset_run,
          {{countable_expr}} AS countable,
          {{technical_validity_state_expr}} AS technical_validity_state,
          {{quota_state_expr}} AS quota_state,
          {{cohort_eligibility_state_expr}} AS cohort_eligibility_state,
          {{cohort_paper_eligible_expr}} AS cohort_paper_eligible,
          {{low_signal_expr}} AS low_signal,
          ds.started_at_utc,
          CASE
            WHEN {resolved_static_run_expr} IS NOT NULL
             AND EXISTS (
               SELECT 1
               FROM static_analysis_runs sar
                WHERE sar.id = {resolved_static_run_expr}
                  AND {hash_eq_ds_sar}
                  AND {sar_qualifying_sql}
              )
            THEN 1 ELSE 0
          END AS linked_exact_static,
          CASE
            WHEN {resolved_static_run_expr} IS NULL
             AND ds.base_apk_sha256 IS NOT NULL
             AND TRIM(ds.base_apk_sha256) <> ''
             AND EXISTS (
               SELECT 1
               FROM static_analysis_runs sar
               WHERE {hash_eq_ds_sar}
                 AND {sar_qualifying_sql}
             )
            THEN 1 ELSE 0
          END AS unlinked_exact_static_available
        FROM dynamic_sessions ds
        {{run_context_join}}
        WHERE 1=1
          {package_filter}
        ORDER BY ds.started_at_utc DESC, ds.dynamic_run_id
        LIMIT %s
    """
    queries = [
        (
            base_select.format(
                valid_dataset_run_expr="ctx.valid_dataset_run",
                countable_expr="ctx.countable",
                technical_validity_state_expr="ctx.technical_validity_state",
                quota_state_expr="ctx.quota_state",
                cohort_eligibility_state_expr="ctx.cohort_eligibility_state",
                cohort_paper_eligible_expr="ctx.cohort_paper_eligible",
                low_signal_expr="ctx.low_signal",
                run_context_join="LEFT JOIN v_dynamic_run_context_v1 ctx ON ctx.dynamic_run_id = ds.dynamic_run_id",
            ),
            "report_dynamic_static_pairing_eligibility.dynamic_sessions.run_context",
        ),
        (
            base_select.format(
                valid_dataset_run_expr="ds.valid_dataset_run",
                countable_expr="ds.countable",
                technical_validity_state_expr="NULL",
                quota_state_expr="NULL",
                cohort_eligibility_state_expr="NULL",
                cohort_paper_eligible_expr="NULL",
                low_signal_expr="NULL",
                run_context_join="",
            ),
            "report_dynamic_static_pairing_eligibility.dynamic_sessions",
        ),
    ]
    last_exc: Exception | None = None
    for sql, query_name in queries:
        try:
            return list(
                core_q.run_sql(
                    sql,
                    tuple(params),
                    fetch="all",
                    dictionary=True,
                    query_name=query_name,
                )
                or []
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue
    if last_exc is not None:
        raise last_exc
    return []


def _build_recovery_action_map(
    core_q: Any,
    *,
    sql_worklist: Any,
    assess_exact_target_readiness: Any,
    group_artifacts: Any,
    recovery_action: Any,
    package_name: str | None,
    old_root_policy: str,
) -> dict[tuple[str, str], str]:
    rows = list(
        core_q.run_sql(
            sql_worklist(5000),
            (),
            fetch="all",
            dictionary=True,
            query_name="report_dynamic_static_pairing_eligibility.worklist",
        )
        or []
    )
    if package_name:
        pkg_lc = str(package_name).strip().lower()
        rows = [row for row in rows if str(row.get("package_name") or "").lower() == pkg_lc]
    groups = tuple(group_artifacts())
    actions: dict[tuple[str, str], str] = {}
    for row in rows:
        package = str(row.get("package_name") or "").strip().lower()
        base_hash = _norm_sha(row.get("base_apk_sha256"))
        if not package or not base_hash:
            continue
        readiness = assess_exact_target_readiness(
            apk_id=row.get("apk_id"),
            base_apk_sha256=base_hash,
            package_name=package,
            dynamic_runs=_safe_int(row.get("dynamic_runs")),
            groups=groups,
        ).as_dict()
        actions[(package, base_hash)] = recovery_action(
            readiness,
            static_exact_coverage=0,
            old_root_policy=old_root_policy,
        )
    return actions


def _classify_session(row: dict[str, Any], *, recovery_action: str | None) -> str:
    if bool(row.get("linked_exact_static")):
        return "paired_exact_static"
    if bool(row.get("unlinked_exact_static_available")):
        return "unpaired_exact_static_available"

    base_hash = _norm_sha(row.get("base_apk_sha256"))
    if not base_hash:
        return "dynamic_only_valid"

    if recovery_action in {"historical_identity_only", "unrecoverable_without_archive"}:
        return "historical_identity_only"
    if recovery_action in {"restore_old_root", "restore_from_archive"}:
        return "unpaired_restore_required"
    if recovery_action == "explicit_reharvest":
        return "unpaired_reharvest_required"
    if recovery_action in {
        "analyze_exact_static_available",
        "rehydrate_canonical_store",
        "restore_from_current_store",
    }:
        return "unpaired_static_missing_but_bytes_available"
    return "dynamic_only_valid"


def _dataset_use_for_classification(classification: str) -> str:
    return {
        "paired_exact_static": "strict_static_dynamic_pair",
        "unpaired_exact_static_available": "strict_static_dynamic_pair_after_link_preview",
        "historical_identity_only": "exclude_from_paired_analysis_missing_artifact",
        "unpaired_unrecoverable_without_archive": "exclude_from_paired_analysis_missing_artifact",
        "unpaired_restore_required": "exclude_from_paired_analysis_missing_artifact",
        "unpaired_reharvest_required": "reharvest_candidate",
        "unpaired_static_missing_but_bytes_available": "static_analysis_candidate",
        "dynamic_only_valid": "dynamic_only",
    }.get(classification, "dynamic_only")


def _dataset_use_for_session(row: dict[str, Any], *, classification: str) -> str:
    technical_state = _norm_text(row.get("technical_validity_state")).upper()
    quota_state = _norm_text(row.get("quota_state")).upper()

    if technical_state == "TECH_INVALID":
        return "exclude_invalid_dynamic"
    if technical_state == "TECH_LEGACY_UNKNOWN" or quota_state == "QUOTA_LEGACY_UNKNOWN":
        return "exclude_legacy_dynamic_unknown"

    if classification == "paired_exact_static":
        if quota_state == "QUOTA_VALID":
            return "strict_static_dynamic_pair"
        if quota_state == "SUPPLEMENTAL_VALID":
            return "paired_static_dynamic_supplemental_only"
    if classification == "unpaired_exact_static_available":
        if quota_state == "QUOTA_VALID":
            return "strict_static_dynamic_pair_after_link_preview"
        if quota_state == "SUPPLEMENTAL_VALID":
            return "paired_static_dynamic_supplemental_after_link_preview"

    return _dataset_use_for_classification(classification)


def _package_summary(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packages: dict[str, dict[str, Any]] = {}
    for row in sessions:
        package = str(row.get("package_name") or "")
        bucket = packages.setdefault(
            package,
            {
                "package_name": package,
                "dynamic_sessions": 0,
                "paired_exact_static": 0,
                "unpaired_exact_static_available": 0,
                "historical_identity_only": 0,
                "unrecoverable_without_archive": 0,
                "restore_required": 0,
                "reharvest_required": 0,
                "bytes_available_but_static_missing": 0,
                "dynamic_only_valid": 0,
                "strict_quota_valid_pairs": 0,
                "strict_supplemental_pairs": 0,
                "invalid_dynamic": 0,
                "legacy_dynamic_unknown": 0,
            },
        )
        classification = str(row.get("classification") or "")
        dataset_use = str(row.get("recommended_dataset_use") or "")
        bucket["dynamic_sessions"] += 1
        if classification == "paired_exact_static":
            bucket["paired_exact_static"] += 1
        elif classification == "unpaired_exact_static_available":
            bucket["unpaired_exact_static_available"] += 1
        elif classification == "unpaired_unrecoverable_without_archive":
            bucket["unrecoverable_without_archive"] += 1
        elif classification == "historical_identity_only":
            bucket["historical_identity_only"] += 1
        elif classification == "unpaired_restore_required":
            bucket["restore_required"] += 1
        elif classification == "unpaired_reharvest_required":
            bucket["reharvest_required"] += 1
        elif classification == "unpaired_static_missing_but_bytes_available":
            bucket["bytes_available_but_static_missing"] += 1
        else:
            bucket["dynamic_only_valid"] += 1
        if dataset_use in {"strict_static_dynamic_pair", "strict_static_dynamic_pair_after_link_preview"}:
            bucket["strict_quota_valid_pairs"] += 1
        elif dataset_use in {"paired_static_dynamic_supplemental_only", "paired_static_dynamic_supplemental_after_link_preview"}:
            bucket["strict_supplemental_pairs"] += 1
        elif dataset_use == "exclude_invalid_dynamic":
            bucket["invalid_dynamic"] += 1
        elif dataset_use == "exclude_legacy_dynamic_unknown":
            bucket["legacy_dynamic_unknown"] += 1
    for bucket in packages.values():
        bucket["recommended_dataset_use"] = _package_dataset_use(bucket)
    return sorted(
        packages.values(),
        key=lambda item: (-int(item["dynamic_sessions"]), str(item["package_name"])),
    )


def _package_dataset_use(bucket: dict[str, Any]) -> str:
    if int(bucket.get("legacy_dynamic_unknown") or 0) > 0:
        return "exclude_legacy_dynamic_unknown"
    if int(bucket.get("invalid_dynamic") or 0) > 0:
        return "exclude_invalid_dynamic"
    if int(bucket.get("historical_identity_only") or 0) > 0:
        return "exclude_from_paired_analysis_missing_artifact"
    if int(bucket.get("unrecoverable_without_archive") or 0) > 0:
        return "exclude_from_paired_analysis_missing_artifact"
    if int(bucket.get("restore_required") or 0) > 0:
        return "exclude_from_paired_analysis_missing_artifact"
    if int(bucket.get("reharvest_required") or 0) > 0:
        return "reharvest_candidate"
    if int(bucket.get("bytes_available_but_static_missing") or 0) > 0:
        return "static_analysis_candidate"
    if int(bucket.get("strict_supplemental_pairs") or 0) > 0:
        return "paired_static_dynamic_supplemental_only"
    if int(bucket.get("unpaired_exact_static_available") or 0) > 0:
        return "strict_static_dynamic_pair_after_link_preview"
    if int(bucket.get("paired_exact_static") or 0) > 0:
        return "strict_static_dynamic_pair"
    return "dynamic_only"


def _summary(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    classifications: dict[str, int] = {}
    dataset_uses: dict[str, int] = {}
    for row in sessions:
        classification = str(row.get("classification") or "unknown")
        dataset_use = str(row.get("recommended_dataset_use") or "unknown")
        classifications[classification] = classifications.get(classification, 0) + 1
        dataset_uses[dataset_use] = dataset_uses.get(dataset_use, 0) + 1
    return {
        "dynamic_sessions": len(sessions),
        "classifications": classifications,
        "dataset_uses": dataset_uses,
        "paired_exact_static": classifications.get("paired_exact_static", 0),
        "strict_pairing_blocked": len(sessions) - classifications.get("paired_exact_static", 0),
    }


def _print_text(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    print("=== Dynamic/static pairing eligibility ===")
    print(f"  dynamic_sessions: {summary['dynamic_sessions']}")
    print(f"  paired_exact_static: {summary['paired_exact_static']}")
    print(f"  strict_pairing_blocked: {summary['strict_pairing_blocked']}")
    print("  classifications:")
    for key, value in sorted(summary["classifications"].items()):
        print(f"    {key}: {value}")
    print("  dataset_uses:")
    for key, value in sorted(summary["dataset_uses"].items()):
        print(f"    {key}: {value}")
    print()
    print("=== Packages ===")
    if not payload["packages"]:
        print("  (empty)")
    for row in payload["packages"]:
        print(
            f"  {row['package_name']} | dynamic={row['dynamic_sessions']} "
            f"paired={row['paired_exact_static']} "
            f"linkable={row['unpaired_exact_static_available']} "
            f"historical={row['historical_identity_only']} "
            f"unrecoverable={row['unrecoverable_without_archive']} "
            f"restore={row['restore_required']} "
            f"reharvest={row['reharvest_required']} "
            f"bytes_ready_static_missing={row['bytes_available_but_static_missing']} "
            f"use={row['recommended_dataset_use']}"
        )
    print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")
    if payload.get("output_files"):
        print()
        print("=== Report bundle ===")
        for label, path in sorted(payload["output_files"].items()):
            print(f"  {label}: {path}")


def _write_report_bundle(payload: dict[str, Any], *, output_dir: Path) -> dict[str, str]:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "summary_json": output_dir / "summary.json",
        "packages_csv": output_dir / "packages.csv",
        "sessions_csv": output_dir / "sessions.csv",
        "historical_identity_only_csv": output_dir / "historical_identity_only.csv",
        "reharvest_candidates_csv": output_dir / "reharvest_candidates.csv",
        "static_analysis_candidates_csv": output_dir / "static_analysis_candidates.csv",
    }
    serializable_payload = dict(payload)
    serializable_payload["output_files"] = {key: str(path) for key, path in files.items()}
    atomic_write_text(
        files["summary_json"],
        json.dumps(serializable_payload, indent=2, sort_keys=True, default=str) + "\n",
    )
    _write_csv(files["packages_csv"], payload.get("packages") or [])
    sessions = list(payload.get("sessions") or [])
    _write_csv(files["sessions_csv"], sessions)
    _write_csv(
        files["historical_identity_only_csv"],
        [
            row
            for row in sessions
            if str(row.get("classification") or "")
            in {"historical_identity_only", "unpaired_unrecoverable_without_archive"}
        ],
    )
    _write_csv(
        files["reharvest_candidates_csv"],
        [
            row
            for row in sessions
            if str(row.get("classification") or "") == "unpaired_reharvest_required"
        ],
    )
    _write_csv(
        files["static_analysis_candidates_csv"],
        [
            row
            for row in sessions
            if str(row.get("classification") or "")
            in {"unpaired_exact_static_available", "unpaired_static_missing_but_bytes_available"}
        ],
    )
    return {key: str(path) for key, path in files.items()}


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    from scytaledroid.Utils.IO.atomic_write import atomic_write_text

    if not rows:
        atomic_write_text(path, "")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})
    atomic_write_text(path, buffer.getvalue())


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, sort_keys=True, default=str)
    return value


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _norm_sha(value: Any) -> str:
    return str(value or "").strip().lower()


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


if __name__ == "__main__":
    raise SystemExit(main())
