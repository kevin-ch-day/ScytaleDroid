#!/usr/bin/env python3
"""Read-only package/version/hash/install-set lineage and coverage report.

This report treats harvest runs as provenance, not identity.  It groups observed
APK base hashes by package/version, then annotates each identity with:

* local byte availability through the recorded harvest path or canonical SHA store
* receipt-backed install-set coverage when available
* canonical static-analysis coverage for the exact base hash
* dynamic-session coverage and exact static gaps

No DDL, DML, filesystem writes, receipts, static runs, or dynamic links are made.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.Database.db_queries.sql_typed_reads import resolved_dynamic_session_static_run_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument(
        "--package",
        dest="package_name",
        help="Limit to one package name.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum package summaries to print in text mode (default 25).",
    )
    parser.add_argument(
        "--hash-limit",
        type=int,
        default=8,
        help="Maximum hash rows per package in text mode (default 8).",
    )
    parser.add_argument(
        "--only-gaps",
        action="store_true",
        help="Only include packages with missing bytes, static gaps, or exact dynamic/static gaps.",
    )
    parser.add_argument(
        "--design-checks",
        action="store_true",
        help="Print read-only design posture checks for install-set and lineage semantics.",
    )
    parser.add_argument(
        "--drift-details",
        action="store_true",
        help="Print same-version/different-hash review details.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.DeviceAnalysis.services import artifact_store
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    base_rows = _fetch_base_rows(core_q, args.package_name)
    static_by_hash = _fetch_static_coverage(core_q)
    dynamic_by_hash = _fetch_dynamic_coverage(core_q)
    app_version_pairs = _fetch_app_version_pairs(core_q)
    install_sets_by_hash = _fetch_install_sets_by_hash(core_q, package_name=args.package_name)
    install_set_summary = _fetch_install_set_summary(core_q, package_name=args.package_name)
    design_checks = _design_checks(core_q, install_set_summary)
    drift_details = _fetch_same_version_hash_drift(core_q, package_name=args.package_name)

    package_map: dict[str, dict[str, Any]] = {}
    hash_rows: list[dict[str, Any]] = []
    for row in base_rows:
        pkg = str(row.get("package_name") or "").strip()
        sha = str(row.get("base_apk_sha256") or "").strip().lower()
        if not pkg or not sha:
            continue

        recorded = _recorded_abs_path(row)
        canonical = artifact_store.canonical_apk_path(sha)
        recorded_exists = bool(recorded and recorded.exists())
        canonical_exists = canonical.exists()
        bytes_available = recorded_exists or canonical_exists
        version_key = _version_key(row)
        app_version_present = (pkg.lower(), version_key[0], version_key[1]) in app_version_pairs
        static_cov = static_by_hash.get(sha, {})
        dynamic_cov = dynamic_by_hash.get(sha, {})
        install_cov = install_sets_by_hash.get(sha, {})
        static_qualifying = int(static_cov.get("canonical_completed_identity_valid") or 0)
        dynamic_sessions = int(dynamic_cov.get("dynamic_sessions") or 0)
        dynamic_unlinked = int(dynamic_cov.get("dynamic_unlinked_sessions") or 0)
        dynamic_linked = int(dynamic_cov.get("dynamic_linked_sessions") or 0)
        exact_dynamic_static_gap = dynamic_sessions > 0 and static_qualifying == 0

        availability_state = _availability_state(
            bytes_available=bytes_available,
            recorded_exists=recorded_exists,
            canonical_exists=canonical_exists,
            recorded_root_exists=_path_exists(row.get("data_root")),
            recorded_location_known=bool(row.get("local_rel_path")),
        )
        recommended_action = _recommended_action(
            bytes_available=bytes_available,
            static_qualifying=static_qualifying,
            dynamic_sessions=dynamic_sessions,
            dynamic_unlinked=dynamic_unlinked,
            availability_state=availability_state,
            app_version_present=app_version_present,
        )

        hrow = {
            "package_name": pkg,
            "display_name": row.get("display_name") or pkg,
            "version_code": row.get("version_code"),
            "version_name": row.get("version_name"),
            "base_apk_sha256": sha,
            "apk_id": row.get("apk_id"),
            "apk_set_id": install_cov.get("apk_set_id"),
            "artifact_set_hash": install_cov.get("artifact_set_hash"),
            "install_sets_seen": int(install_cov.get("install_sets_seen") or 0),
            "member_count": int(install_cov.get("member_count") or 0),
            "split_count": int(install_cov.get("split_count") or 0),
            "bytes_available": bytes_available,
            "availability_state": availability_state,
            "recorded_path_exists": recorded_exists,
            "canonical_store_exists": canonical_exists,
            "recorded_abs_path": recorded.as_posix() if recorded else None,
            "canonical_store_path": canonical.as_posix(),
            "storage_root_id": row.get("storage_root_id"),
            "storage_root_exists": _path_exists(row.get("data_root")),
            "storage_root": row.get("data_root"),
            "app_version_present": app_version_present,
            "static_runs": int(static_cov.get("static_runs") or 0),
            "static_canonical_completed_identity_valid": static_qualifying,
            "latest_static_run_id": static_cov.get("latest_static_run_id"),
            "latest_static_session": static_cov.get("latest_static_session"),
            "dynamic_sessions": dynamic_sessions,
            "dynamic_unlinked_sessions": dynamic_unlinked,
            "dynamic_linked_sessions": dynamic_linked,
            "exact_dynamic_static_gap": exact_dynamic_static_gap,
            "first_observed_at": _stringify(row.get("first_observed_at")),
            "last_observed_at": _stringify(row.get("last_observed_at")),
            "recommended_action": recommended_action,
        }
        hash_rows.append(hrow)

        pkg_bucket = package_map.setdefault(
            pkg,
            {
                "package_name": pkg,
                "display_name": row.get("display_name") or pkg,
                "versions_seen": set(),
                "hashes_seen": 0,
                "install_sets_seen": 0,
                "bytes_available": 0,
                "bytes_missing": 0,
                "static_covered_hashes": 0,
                "dynamic_covered_hashes": 0,
                "dynamic_sessions": 0,
                "dynamic_exact_static_linked": 0,
                "exact_dynamic_static_gaps": 0,
                "missing_bytes": 0,
                "app_version_missing_pairs": 0,
                "recommended_actions": set(),
                "hashes": [],
                "latest_observed_version_code": None,
                "latest_observed_at": None,
            },
        )
        pkg_bucket["versions_seen"].add(version_key)
        pkg_bucket["hashes_seen"] += 1
        pkg_bucket["install_sets_seen"] += int(install_cov.get("install_sets_seen") or 0)
        pkg_bucket["bytes_available"] += int(bytes_available)
        pkg_bucket["bytes_missing"] += int(not bytes_available)
        pkg_bucket["static_covered_hashes"] += int(static_qualifying > 0)
        pkg_bucket["dynamic_covered_hashes"] += int(dynamic_sessions > 0)
        pkg_bucket["dynamic_sessions"] += dynamic_sessions
        pkg_bucket["dynamic_exact_static_linked"] += dynamic_linked
        pkg_bucket["exact_dynamic_static_gaps"] += int(exact_dynamic_static_gap)
        pkg_bucket["missing_bytes"] += int(not bytes_available)
        pkg_bucket["app_version_missing_pairs"] += int(not app_version_present)
        pkg_bucket["recommended_actions"].add(recommended_action)
        pkg_bucket["hashes"].append(hrow)
        _update_latest_observed(pkg_bucket, hrow)

    packages = [_finalize_package(bucket) for bucket in package_map.values()]
    _annotate_lineage_review_actions(packages)
    if args.only_gaps:
        packages = [
            pkg
            for pkg in packages
            if pkg["missing_bytes"]
            or pkg["exact_dynamic_static_gaps"]
            or pkg["static_covered_hashes"] < pkg["hashes_seen"]
        ]
    packages.sort(
        key=lambda item: (
            -int(item["exact_dynamic_static_gaps"]),
            -int(item["missing_bytes"]),
            -int(item["hashes_seen"]),
            str(item["package_name"]),
        )
    )
    payload = {
        "summary": _summary(packages),
        "install_set_summary": install_set_summary,
        "design_checks": design_checks,
        "same_version_hash_drift": drift_details,
        "packages": packages,
        "notes": _notes(install_set_summary),
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    _print_text(
        payload,
        limit=max(args.limit, 0),
        hash_limit=max(args.hash_limit, 0),
        design_checks=args.design_checks,
        drift_details=args.drift_details,
    )
    return 0


def _fetch_base_rows(core_q: Any, package_name: str | None) -> list[dict[str, Any]]:
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(r.package_name)) = %s"
        params.append(str(package_name).strip().lower())
    return list(
        core_q.run_sql(
            f"""
            SELECT
              r.apk_id,
              LOWER(TRIM(r.package_name)) AS package_name,
              NULLIF(a.display_name, '') AS display_name,
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)) AS base_apk_sha256,
              MIN(r.harvested_at) AS first_observed_at,
              MAX(r.harvested_at) AS last_observed_at,
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            FROM android_apk_repository r
            LEFT JOIN apps a ON LOWER(TRIM(a.package_name)) = LOWER(TRIM(r.package_name))
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            WHERE r.sha256 IS NOT NULL
              AND COALESCE(r.is_split_member, 0) = 0
              {package_filter}
            GROUP BY
              r.apk_id,
              LOWER(TRIM(r.package_name)),
              NULLIF(a.display_name, ''),
              r.version_code,
              r.version_name,
              LOWER(TRIM(r.sha256)),
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root
            ORDER BY LOWER(TRIM(r.package_name)), CAST(r.version_code AS UNSIGNED), r.version_name, r.apk_id
            """,
            tuple(params),
            fetch="all",
            dictionary=True,
            query_name="report_apk_lineage.base_rows",
        )
        or []
    )


def _fetch_static_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS static_runs,
          SUM(CASE
                WHEN status='COMPLETED'
                 AND run_class='CANONICAL'
                 AND COALESCE(identity_valid,0)=1
                THEN 1 ELSE 0
              END) AS canonical_completed_identity_valid,
          MAX(id) AS latest_static_run_id,
          MAX(static_session_id) AS latest_static_session
        FROM static_analysis_runs
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_apk_lineage.static_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _fetch_dynamic_coverage(core_q: Any) -> dict[str, dict[str, Any]]:
    resolved_static_run_id = resolved_dynamic_session_static_run_id("ds")
    rows = core_q.run_sql(
        f"""
        SELECT
          LOWER(TRIM(ds.base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS dynamic_sessions,
          SUM(CASE WHEN {resolved_static_run_id} IS NULL THEN 1 ELSE 0 END) AS dynamic_unlinked_sessions,
          SUM(CASE
                WHEN sar.id IS NOT NULL
                 AND LOWER(TRIM(sar.base_apk_sha256)) = LOWER(TRIM(ds.base_apk_sha256))
                 AND sar.status = 'COMPLETED'
                 AND sar.run_class = 'CANONICAL'
                 AND COALESCE(sar.identity_valid, 0) = 1
                THEN 1 ELSE 0
               END) AS dynamic_linked_sessions
        FROM dynamic_sessions ds
        LEFT JOIN static_analysis_runs sar ON sar.id = {resolved_static_run_id}
        WHERE ds.base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(ds.base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="report_apk_lineage.dynamic_coverage",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _fetch_install_sets_by_hash(
    core_q: Any, *, package_name: str | None = None
) -> dict[str, dict[str, Any]]:
    if not _table_exists(core_q, "apk_sets"):
        return {}
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(package_name)) = %s"
        params.append(str(package_name).strip().lower())
    rows = core_q.run_sql(
        f"""
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS install_sets_seen,
          MIN(apk_set_id) AS apk_set_id,
          MIN(artifact_set_hash) AS artifact_set_hash,
          MAX(member_count) AS member_count,
          MAX(split_count) AS split_count
        FROM apk_sets
        WHERE base_apk_sha256 IS NOT NULL
          {package_filter}
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        tuple(params),
        fetch="all",
        dictionary=True,
        query_name="report_apk_lineage.install_sets_by_hash",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _fetch_app_version_pairs(core_q: Any) -> set[tuple[str, str, str]]:
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(a.package_name)) AS package_name,
          COALESCE(CAST(av.version_code AS CHAR), '') AS version_code,
          COALESCE(av.version_name, '') AS version_name
        FROM app_versions av
        JOIN apps a ON a.id = av.app_id
        """,
        fetch="all",
        dictionary=True,
        query_name="report_apk_lineage.app_version_pairs",
    ) or []
    return {
        (
            str(row.get("package_name") or "").lower(),
            str(row.get("version_code") or ""),
            str(row.get("version_name") or ""),
        )
        for row in rows
    }


def _fetch_install_set_summary(core_q: Any, *, package_name: str | None = None) -> dict[str, Any]:
    if not _table_exists(core_q, "apk_sets"):
        return {"available": False}
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "WHERE LOWER(TRIM(package_name)) = %s"
        params.append(str(package_name).strip().lower())
    row = core_q.run_sql(
        f"""
        SELECT
          COUNT(*) AS apk_sets,
          COALESCE(SUM(member_count), 0) AS declared_members,
          COALESCE(SUM(split_count), 0) AS declared_splits,
          SUM(CASE WHEN completeness_state='complete' THEN 1 ELSE 0 END) AS complete_sets
        FROM apk_sets
        {package_filter}
        """,
        tuple(params),
        fetch="one_dict",
        query_name="report_apk_lineage.install_set_summary",
    ) or {}
    coverage = {}
    if _table_exists(core_q, "v_apk_set_coverage_v1"):
        view_filter = ""
        view_params: list[Any] = []
        if package_name:
            view_filter = "WHERE LOWER(TRIM(package_name)) = %s"
            view_params.append(str(package_name).strip().lower())
        coverage = core_q.run_sql(
            f"""
            SELECT
              SUM(CASE WHEN has_canonical_static=1 THEN 1 ELSE 0 END) AS sets_with_canonical_static,
              SUM(CASE WHEN dynamic_sessions > 0 THEN 1 ELSE 0 END) AS sets_with_dynamic,
              SUM(CASE WHEN exact_dynamic_static_gap=1 THEN 1 ELSE 0 END) AS exact_dynamic_static_gaps,
              COALESCE(SUM(static_runs_linked_by_apk_set_id), 0) AS static_rows_linked_by_apk_set_id,
              COALESCE(SUM(dynamic_sessions_linked_by_apk_set_id), 0) AS dynamic_rows_linked_by_apk_set_id
            FROM v_apk_set_coverage_v1
            {view_filter}
            """,
            tuple(view_params),
            fetch="one_dict",
            query_name="report_apk_lineage.install_set_coverage_summary",
        ) or {}
    return {
        "available": True,
        "apk_sets": int(row.get("apk_sets") or 0),
        "declared_members": int(row.get("declared_members") or 0),
        "declared_splits": int(row.get("declared_splits") or 0),
        "complete_sets": int(row.get("complete_sets") or 0),
        "sets_with_canonical_static": int(coverage.get("sets_with_canonical_static") or 0),
        "sets_with_dynamic": int(coverage.get("sets_with_dynamic") or 0),
        "exact_dynamic_static_gaps": int(coverage.get("exact_dynamic_static_gaps") or 0),
        "static_rows_linked_by_apk_set_id": int(
            coverage.get("static_rows_linked_by_apk_set_id") or 0
        ),
        "dynamic_rows_linked_by_apk_set_id": int(
            coverage.get("dynamic_rows_linked_by_apk_set_id") or 0
        ),
    }


def _table_exists(core_q: Any, table_name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (table_name,),
        fetch="one_dict",
        query_name="report_apk_lineage.table_exists",
    )
    return int((row or {}).get("n") or 0) > 0


def _recorded_abs_path(row: dict[str, Any]) -> Path | None:
    raw = str(row.get("local_rel_path") or "").strip()
    if not raw:
        return None
    local = Path(raw).expanduser()
    if local.is_absolute():
        return local
    root = str(row.get("data_root") or "").strip()
    if root:
        return Path(root).expanduser() / local
    return Path.cwd() / local


def _path_exists(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and Path(text).expanduser().exists())


def _availability_state(
    *,
    bytes_available: bool,
    recorded_exists: bool,
    canonical_exists: bool,
    recorded_root_exists: bool,
    recorded_location_known: bool,
) -> str:
    if recorded_exists and canonical_exists:
        return "AVAILABLE_RECORDED_AND_CANONICAL"
    if canonical_exists:
        return "AVAILABLE_CANONICAL_ONLY"
    if recorded_exists:
        return "AVAILABLE_RECORDED_ONLY"
    if not recorded_location_known:
        return "MISSING_NO_RECORDED_LOCATION"
    if recorded_root_exists:
        return "MISSING_REHARVEST_REQUIRED"
    return "MISSING_RESTORABLE_ROOT"


def _recommended_action(
    *,
    bytes_available: bool,
    static_qualifying: int,
    dynamic_sessions: int,
    dynamic_unlinked: int,
    availability_state: str,
    app_version_present: bool,
) -> str:
    if not bytes_available:
        if availability_state == "MISSING_RESTORABLE_ROOT":
            return "restore_artifacts"
        return "explicit_reharvest_needed"
    if static_qualifying > 0 and dynamic_unlinked > 0:
        return "link_repair_preview_available"
    if static_qualifying == 0 and dynamic_sessions > 0:
        return "analyze_available_hash"
    if static_qualifying == 0:
        return "new_version_needs_static" if not app_version_present else "analyze_available_hash"
    return "covered"


def _version_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("version_code") or ""), str(row.get("version_name") or ""))


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _finalize_package(bucket: dict[str, Any]) -> dict[str, Any]:
    actions = sorted(str(item) for item in bucket.pop("recommended_actions"))
    versions = bucket.pop("versions_seen")
    bucket["versions_seen"] = len(versions)
    bucket["recommended_actions"] = actions
    bucket["recommended_action"] = _package_recommendation(actions)
    bucket["hashes"].sort(
        key=lambda item: (
            -int(item["exact_dynamic_static_gap"]),
            int(item["bytes_available"]),
            str(item.get("version_code") or ""),
            str(item.get("base_apk_sha256") or ""),
        )
    )
    return bucket


def _update_latest_observed(bucket: dict[str, Any], row: dict[str, Any]) -> None:
    observed_at = str(row.get("last_observed_at") or "")
    if not observed_at:
        return
    if bucket.get("latest_observed_at") is None or observed_at > str(bucket["latest_observed_at"]):
        bucket["latest_observed_at"] = observed_at
        bucket["latest_observed_version_code"] = row.get("version_code")


def _annotate_lineage_review_actions(packages: list[dict[str, Any]]) -> None:
    for pkg in packages:
        version_to_hashes: dict[tuple[str, str], set[str]] = {}
        hash_to_sets: dict[str, set[str]] = {}
        for row in pkg["hashes"]:
            version_to_hashes.setdefault(_version_key(row), set()).add(str(row["base_apk_sha256"]))
            artifact_hash = str(row.get("artifact_set_hash") or "")
            if artifact_hash:
                hash_to_sets.setdefault(str(row["base_apk_sha256"]), set()).add(artifact_hash)
        same_version_changed = any(len(hashes) > 1 for hashes in version_to_hashes.values())
        same_hash_split_changed = any(len(sets) > 1 for sets in hash_to_sets.values())
        pkg["same_version_hash_changed_review"] = same_version_changed
        pkg["same_base_hash_different_split_set_review"] = same_hash_split_changed
        if same_version_changed:
            _add_action(pkg, "same_version_hash_changed_review")
        if same_hash_split_changed:
            _add_action(pkg, "same_base_hash_different_split_set_review")


def _add_action(pkg: dict[str, Any], action: str) -> None:
    actions = list(pkg.get("recommended_actions") or [])
    if action not in actions:
        actions.append(action)
    pkg["recommended_actions"] = sorted(actions)
    pkg["recommended_action"] = _package_recommendation(pkg["recommended_actions"])


def _package_recommendation(actions: list[str]) -> str:
    priority = [
        "restore_artifacts",
        "explicit_reharvest_needed",
        "same_base_hash_different_split_set_review",
        "same_version_hash_changed_review",
        "analyze_available_hash",
        "new_version_needs_static",
        "link_repair_preview_available",
        "covered",
    ]
    for item in priority:
        if item in actions:
            return item
    return actions[0] if actions else "none"


def _summary(packages: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "packages": len(packages),
        "hashes_seen": sum(int(pkg["hashes_seen"]) for pkg in packages),
        "install_sets_seen": sum(int(pkg["install_sets_seen"]) for pkg in packages),
        "bytes_available": sum(int(pkg["bytes_available"]) for pkg in packages),
        "missing_bytes": sum(int(pkg["missing_bytes"]) for pkg in packages),
        "static_covered_hashes": sum(int(pkg["static_covered_hashes"]) for pkg in packages),
        "dynamic_covered_hashes": sum(int(pkg["dynamic_covered_hashes"]) for pkg in packages),
        "dynamic_sessions": sum(int(pkg["dynamic_sessions"]) for pkg in packages),
        "dynamic_exact_static_linked": sum(
            int(pkg["dynamic_exact_static_linked"]) for pkg in packages
        ),
        "exact_dynamic_static_gaps": sum(int(pkg["exact_dynamic_static_gaps"]) for pkg in packages),
        "app_version_missing_pairs": sum(int(pkg["app_version_missing_pairs"]) for pkg in packages),
    }


def _notes(install_set_summary: dict[str, Any]) -> list[str]:
    notes = [
        "Harvest run directories are provenance; package/version/base hash is the identity grain.",
        "apk_split_groups is package-level in the current schema, not an exact install-set table.",
    ]
    if install_set_summary.get("available"):
        notes.append(
            "apk_sets is available for receipt-backed install-set identity; use v_apk_set_coverage_v1 for set-level static/dynamic coverage."
        )
    else:
        notes.append(
            "artifact_set_hash exists on static_analysis_runs and dynamic_sessions, but there is no durable apk_sets/install_sets table yet."
        )
    return notes


def _design_checks(core_q: Any, install_set_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "apk_sets_exact_install_set_identity": (
            "yes_receipt_backed_current_scope" if install_set_summary.get("available") else "no_table"
        ),
        "artifact_set_hash_stable_rule": (
            "v1: sha256 over ordered member SHA256 list; base first, splits sorted by split_name/file name"
        ),
        "static_analysis_runs_apk_set_id_populated": _column_population(
            core_q, "static_analysis_runs", "apk_set_id"
        ),
        "dynamic_sessions_apk_set_id_populated": _column_population(
            core_q, "dynamic_sessions", "apk_set_id"
        ),
        "same_package_version_different_base_hash_detected": _same_version_hash_change_count(core_q),
        "same_base_hash_different_split_set_detected": _same_base_hash_split_change_count(core_q),
        "historical_repository_rows_retained_when_bytes_missing": "yes_identity_ledger",
        "canonical_sha_store_intended_stable_byte_source": "yes",
    }


def _column_population(core_q: Any, table: str, column: str) -> dict[str, int]:
    if not _table_exists(core_q, table):
        return {"table_exists": 0, "total": 0, "populated": 0}
    row = core_q.run_sql(
        f"""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN {column} IS NOT NULL THEN 1 ELSE 0 END) AS populated
        FROM {table}
        """,
        fetch="one_dict",
        query_name=f"report_apk_lineage.column_population.{table}.{column}",
    ) or {}
    return {
        "table_exists": 1,
        "total": int(row.get("total") or 0),
        "populated": int(row.get("populated") or 0),
    }


def _same_version_hash_change_count(core_q: Any) -> int:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM (
          SELECT LOWER(TRIM(package_name)) AS package_name,
                 COALESCE(CAST(version_code AS CHAR), '') AS version_code,
                 COUNT(DISTINCT LOWER(TRIM(sha256))) AS hashes
          FROM android_apk_repository
          WHERE sha256 IS NOT NULL
            AND COALESCE(is_split_member, 0) = 0
          GROUP BY LOWER(TRIM(package_name)), COALESCE(CAST(version_code AS CHAR), '')
          HAVING hashes > 1
        ) x
        """,
        fetch="one_dict",
        query_name="report_apk_lineage.same_version_hash_change_count",
    ) or {}
    return int(row.get("n") or 0)


def _same_base_hash_split_change_count(core_q: Any) -> int:
    if not _table_exists(core_q, "apk_sets"):
        return 0
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS n
        FROM (
          SELECT LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
                 COUNT(DISTINCT artifact_set_hash) AS sets
          FROM apk_sets
          GROUP BY LOWER(TRIM(base_apk_sha256))
          HAVING sets > 1
        ) x
        """,
        fetch="one_dict",
        query_name="report_apk_lineage.same_base_hash_split_change_count",
    ) or {}
    return int(row.get("n") or 0)


def _fetch_same_version_hash_drift(
    core_q: Any, *, package_name: str | None = None
) -> list[dict[str, Any]]:
    params: list[Any] = []
    package_filter = ""
    if package_name:
        package_filter = "AND LOWER(TRIM(r.package_name)) = %s"
        params.append(str(package_name).strip().lower())
    rows = core_q.run_sql(
        f"""
        SELECT
          LOWER(TRIM(r.package_name)) AS package_name,
          COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))) AS display_name,
          COALESCE(CAST(r.version_code AS CHAR), '') AS version_code,
          COALESCE(r.version_name, '') AS version_name,
          COUNT(DISTINCT LOWER(TRIM(r.sha256))) AS base_hash_count,
          GROUP_CONCAT(DISTINCT LOWER(TRIM(r.sha256)) ORDER BY LOWER(TRIM(r.sha256)) SEPARATOR ',')
            AS hashes,
          MIN(r.harvested_at) AS first_seen_at,
          MAX(r.harvested_at) AS last_seen_at
        FROM android_apk_repository r
        LEFT JOIN apps a ON LOWER(TRIM(a.package_name)) = LOWER(TRIM(r.package_name))
        WHERE r.sha256 IS NOT NULL
          AND COALESCE(r.is_split_member, 0) = 0
          {package_filter}
        GROUP BY
          LOWER(TRIM(r.package_name)),
          COALESCE(NULLIF(a.display_name, ''), LOWER(TRIM(r.package_name))),
          COALESCE(CAST(r.version_code AS CHAR), ''),
          COALESCE(r.version_name, '')
        HAVING base_hash_count > 1
        ORDER BY base_hash_count DESC, package_name, version_code
        """,
        tuple(params),
        fetch="all",
        dictionary=True,
        query_name="report_apk_lineage.same_version_hash_drift",
    ) or []
    static_coverage = _fetch_static_coverage(core_q)
    results: list[dict[str, Any]] = []
    from scytaledroid.DeviceAnalysis.services import artifact_store

    for row in rows:
        hashes = [h for h in str(row.get("hashes") or "").split(",") if h]
        bytes_available = 0
        static_covered = 0
        for sha in hashes:
            if artifact_store.canonical_apk_path(sha).exists():
                bytes_available += 1
            if int(static_coverage.get(sha, {}).get("canonical_completed_identity_valid") or 0) > 0:
                static_covered += 1
        results.append(
            {
                "package_name": row.get("package_name"),
                "display_name": row.get("display_name"),
                "version_code": row.get("version_code"),
                "version_name": row.get("version_name"),
                "base_hash_count": int(row.get("base_hash_count") or 0),
                "hashes": hashes,
                "first_seen_at": _stringify(row.get("first_seen_at")),
                "last_seen_at": _stringify(row.get("last_seen_at")),
                "bytes_available_count": bytes_available,
                "static_covered_count": static_covered,
                "recommended_action": "same_version_hash_changed_review",
            }
        )
    return results


def _print_text(
    payload: dict[str, Any],
    *,
    limit: int,
    hash_limit: int,
    design_checks: bool,
    drift_details: bool,
) -> None:
    summary = payload["summary"]
    print("=== APK package/version/hash/install-set lineage and coverage ===")
    for key in (
        "packages",
        "hashes_seen",
        "install_sets_seen",
        "bytes_available",
        "missing_bytes",
        "static_covered_hashes",
        "dynamic_covered_hashes",
        "dynamic_sessions",
        "dynamic_exact_static_linked",
        "exact_dynamic_static_gaps",
        "app_version_missing_pairs",
    ):
        print(f"  {key}: {summary[key]}")
    print()
    install_sets = payload.get("install_set_summary") or {}
    if install_sets.get("available"):
        print("=== Install Sets ===")
        for key in (
            "apk_sets",
            "complete_sets",
            "declared_members",
            "declared_splits",
            "sets_with_canonical_static",
            "sets_with_dynamic",
            "exact_dynamic_static_gaps",
            "static_rows_linked_by_apk_set_id",
            "dynamic_rows_linked_by_apk_set_id",
        ):
            print(f"  {key}: {install_sets[key]}")
        print()
    print("=== Packages ===")
    packages = payload["packages"][:limit] if limit else payload["packages"]
    if not packages:
        print("  (empty)")
    for pkg in packages:
        print(
            f"{pkg['package_name']} ({pkg['display_name']}) | versions={pkg['versions_seen']} "
            f"hashes={pkg['hashes_seen']} sets={pkg['install_sets_seen']} "
            f"bytes={pkg['bytes_available']}/{pkg['hashes_seen']} "
            f"static={pkg['static_covered_hashes']}/{pkg['hashes_seen']} "
            f"dynamic_hashes={pkg['dynamic_covered_hashes']}/{pkg['hashes_seen']} "
            f"dynamic_sessions={pkg['dynamic_sessions']} "
            f"linked={pkg['dynamic_exact_static_linked']} "
            f"exact_dynamic_static_gaps={pkg['exact_dynamic_static_gaps']} "
            f"latest_vCode={pkg.get('latest_observed_version_code') or 'unknown'} "
            f"latest_at={pkg.get('latest_observed_at') or 'unknown'} "
            f"action={pkg['recommended_action']}"
        )
        for row in pkg["hashes"][:hash_limit] if hash_limit else pkg["hashes"]:
            print(
                f"  vCode={row.get('version_code') or 'unknown'} "
                f"vName={row.get('version_name') or 'unknown'} "
                f"sha={str(row['base_apk_sha256'])[:16]}... "
                f"apk_set={row.get('apk_set_id') or 'none'} "
                f"members={row.get('member_count') or 0} "
                f"bytes={row['availability_state']} "
                f"static={row['static_canonical_completed_identity_valid']} "
                f"dynamic={row['dynamic_sessions']} "
                f"action={row['recommended_action']}"
            )
    if limit and len(payload["packages"]) > limit:
        print(f"  hint: showing {limit}/{len(payload['packages'])} package(s). Use --limit N or --json.")
    print()
    if design_checks:
        print("=== Design Checks ===")
        for key, value in payload["design_checks"].items():
            print(f"  {key}: {value}")
        print()
    if drift_details:
        print("=== Same Version / Different Base Hash Review ===")
        rows = payload.get("same_version_hash_drift") or []
        if not rows:
            print("  (empty)")
        for row in rows:
            hashes = ", ".join(str(h)[:12] + "..." for h in row.get("hashes", []))
            print(
                f"  {row.get('package_name')} ({row.get('display_name')}) | "
                f"vCode={row.get('version_code') or 'unknown'} "
                f"vName={row.get('version_name') or 'unknown'} "
                f"hashes={row.get('base_hash_count')} "
                f"bytes={row.get('bytes_available_count')}/{row.get('base_hash_count')} "
                f"static={row.get('static_covered_count')}/{row.get('base_hash_count')} "
                f"first={row.get('first_seen_at') or 'unknown'} "
                f"last={row.get('last_seen_at') or 'unknown'} "
                f"action={row.get('recommended_action')}"
            )
            print(f"    hashes: {hashes}")
        print()
    print("=== Notes ===")
    for note in payload["notes"]:
        print(f"  - {note}")


if __name__ == "__main__":
    raise SystemExit(main())
