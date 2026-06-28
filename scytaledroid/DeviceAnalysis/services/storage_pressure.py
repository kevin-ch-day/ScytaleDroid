"""Read-only audit helpers for APK storage pressure and thin-session eligibility.

This module does not mutate filesystem evidence or database state. It measures:

* run-tree APK payload pressure under ``data/device_apks/.../runs``
* canonical APK byte authority under ``data/store/apk/sha256/...``
* current-workspace candidates that can safely become thin-session symlinks
* DB lineage rows whose recorded paths are stale or historical-only
"""

from __future__ import annotations

import csv
import json
import os
import stat
from collections import Counter
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from io import StringIO
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.IO.atomic_write import atomic_write_text


def default_output_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "audit" / "storage"


def audit_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True)
class PressureRow:
    record_kind: str
    classification: str
    package_name: str | None
    version_code: str | None
    version_name: str | None
    sha256: str | None
    file_size: int | None
    reclaimable_bytes: int
    session_label: str | None
    device_serial: str | None
    local_rel_path: str | None
    absolute_path: str | None
    canonical_store_path: str | None
    storage_root: str | None
    storage_root_role: str | None
    recorded_path_exists: bool
    canonical_exists: bool
    is_symlink: bool
    db_identity_known: bool
    manifest_present: bool
    sidecar_present: bool
    hash_verified: bool
    install_set_present: bool
    install_set_state: str | None
    install_set_member_count: int
    install_set_split_count: int
    note: str | None = None


def generate_storage_pressure_audit(
    *,
    core_q: Any,
    data_root: Path | None = None,
    out_dir: Path | None = None,
    stamp: str | None = None,
    verify_candidates: bool = False,
) -> tuple[dict[str, Any], Path, Path]:
    audit = build_storage_pressure_audit(
        core_q=core_q,
        data_root=data_root,
        verify_candidates=verify_candidates,
    )
    json_path, csv_path = write_storage_pressure_audit(
        audit,
        out_dir=out_dir,
        stamp=stamp,
    )
    return audit, json_path, csv_path


def build_storage_pressure_audit(
    *,
    core_q: Any,
    data_root: Path | None = None,
    verify_candidates: bool = False,
) -> dict[str, Any]:
    from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage

    resolved_data_root = (data_root or artifact_store.data_root()).resolve()
    device_root = (resolved_data_root / "device_apks").resolve()
    canonical_root = (resolved_data_root / "store" / "apk" / "sha256").resolve()
    repo_root = resolved_data_root.parent.resolve()

    db_artifact_rows = _load_db_artifact_rows(core_q)
    storage_roots = _load_storage_roots(core_q)
    install_sets_by_sha = _load_install_set_summary_by_hash(core_q, lineage)
    install_set_table_summary = _load_install_set_table_summary(core_q, lineage)
    base_rows = lineage.fetch_base_rows(core_q, package_name=None)
    db_sha_set = {
        str(row.get("sha256") or "").strip().lower()
        for row in db_artifact_rows
        if str(row.get("sha256") or "").strip()
    }

    session_rows = _scan_session_pressure(
        device_root=device_root,
        repo_root=repo_root,
        canonical_root=canonical_root,
        db_sha_set=db_sha_set,
        install_sets_by_sha=install_sets_by_sha,
        verify_candidates=verify_candidates,
    )
    db_lineage_rows = _build_db_lineage_rows(
        db_artifact_rows=db_artifact_rows,
        current_device_root=device_root,
        canonical_root=canonical_root,
        install_sets_by_sha=install_sets_by_sha,
    )
    base_hash_summary = _build_base_hash_summary(
        base_rows=base_rows,
        canonical_root=canonical_root,
    )
    canonical_summary = _scan_canonical_store(canonical_root)
    inode_summary = _scan_inode_accounting(device_root=device_root, canonical_root=canonical_root)
    root_rows = _build_root_rows(
        storage_roots=storage_roots,
        current_device_root=device_root,
        db_lineage_rows=db_lineage_rows,
    )

    session_counter = Counter(row.classification for row in session_rows)
    lineage_counter = Counter(row.classification for row in db_lineage_rows)
    install_set_counter = Counter(
        str(info.get("completeness_state") or "unknown")
        for info in install_sets_by_sha.values()
    )

    session_regular_files = [row for row in session_rows if not row.is_symlink]
    session_regular_bytes = sum(int(row.file_size or 0) for row in session_regular_files)
    eligible_rows = [
        row for row in session_rows if row.classification in {"eligible_unverified", "eligible_verified"}
    ]
    eligible_verified_rows = [row for row in eligible_rows if row.classification == "eligible_verified"]
    eligible_unverified_rows = [row for row in eligible_rows if row.classification == "eligible_unverified"]
    blocked_missing_sidecar_rows = [row for row in session_rows if row.classification == "blocked_missing_sidecar"]
    blocked_missing_sidecar_bytes = sum(int(row.file_size or 0) for row in blocked_missing_sidecar_rows)
    session_hardlinked_to_canonical_files = _count_session_files_hardlinked_to_canonical(
        session_rows=session_rows,
        canonical_root=canonical_root,
    )
    session_distinct_from_canonical_files = len(eligible_rows) - session_hardlinked_to_canonical_files
    distinct_copy_physical_reclaimable_bytes = _sum_physical_reclaimable_bytes(
        session_rows=eligible_rows,
        canonical_root=canonical_root,
        require_distinct_from_canonical=True,
    )
    shared_inode_physical_reclaimable_bytes = _sum_physical_reclaimable_bytes(
        session_rows=eligible_rows,
        canonical_root=canonical_root,
        require_distinct_from_canonical=False,
    )
    status_counts = dict(sorted(session_counter.items()))
    lineage_counts = dict(sorted(lineage_counter.items()))

    summary = {
        "db_apk_artifact_rows": len(db_artifact_rows),
        "db_packages": len(
            {
                str(row.get("package_name") or "").strip().lower()
                for row in db_artifact_rows
                if str(row.get("package_name") or "").strip()
            }
        ),
        "base_apk_identities": int(base_hash_summary["base_apk_identities"]),
        "split_member_rows": int(sum(1 for row in db_artifact_rows if int(row.get("is_split_member") or 0) == 1)),
        "session_regular_apk_files": len(session_regular_files),
        "session_regular_apk_bytes": session_regular_bytes,
        "session_regular_apk_allocated_bytes": int(inode_summary["session_allocated_bytes"]),
        "session_symlink_apk_files": int(session_counter.get("already_thin_symlink", 0)),
        "canonical_apk_files": int(canonical_summary["canonical_apk_files"]),
        "canonical_apk_bytes": int(canonical_summary["canonical_apk_bytes"]),
        "canonical_apk_allocated_bytes": int(inode_summary["canonical_allocated_bytes"]),
        "eligible_verified_files": len(eligible_verified_rows),
        "eligible_verified_reclaimable_bytes": sum(int(row.reclaimable_bytes or 0) for row in eligible_verified_rows),
        "eligible_unverified_files": len(eligible_unverified_rows),
        "eligible_unverified_reclaimable_bytes": sum(
            int(row.reclaimable_bytes or 0) for row in eligible_unverified_rows
        ),
        "session_files_hardlinked_to_canonical": int(session_hardlinked_to_canonical_files),
        "session_files_distinct_from_canonical": int(session_distinct_from_canonical_files),
        "logical_reclaimable_bytes": sum(int(row.reclaimable_bytes or 0) for row in eligible_rows),
        "physical_reclaimable_bytes_estimate": int(distinct_copy_physical_reclaimable_bytes),
        "shared_inode_reclaimable_bytes_estimate": int(shared_inode_physical_reclaimable_bytes),
        "current_root_stale_rows": int(
            lineage_counter.get("recorded_path_stale_canonical_present", 0)
            + lineage_counter.get("recorded_path_stale_canonical_missing", 0)
        ),
        "current_root_stale_canonical_present_rows": int(
            lineage_counter.get("recorded_path_stale_canonical_present", 0)
        ),
        "current_root_stale_canonical_missing_rows": int(
            lineage_counter.get("recorded_path_stale_canonical_missing", 0)
        ),
        "old_root_historical_rows": int(
            lineage_counter.get("historical_identity_only", 0) + lineage_counter.get("blocked_old_root", 0)
        ),
        "base_hashes_with_bytes_available": int(base_hash_summary["base_hashes_with_bytes_available"]),
        "base_hashes_missing_bytes": int(base_hash_summary["base_hashes_missing_bytes"]),
        "install_sets_total": int(install_set_table_summary.get("install_sets_total") or 0),
        "install_sets_complete": int(install_set_table_summary.get("install_sets_complete") or 0),
        "install_sets_incomplete": int(install_set_table_summary.get("install_sets_incomplete") or 0),
        "base_hashes_with_install_sets": len(install_sets_by_sha),
    }

    return {
        "schema_version": "storage_pressure_audit_v1",
        "mode": "read_only",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "verify_mode": "candidates" if verify_candidates else "none",
        "data_root": resolved_data_root.as_posix(),
        "repo_root": repo_root.as_posix(),
        "device_apks_root": device_root.as_posix(),
        "canonical_store_root": canonical_root.as_posix(),
        "summary": summary,
        "status_counts": status_counts,
        "classification_counts": status_counts,
        "session_status_counts": status_counts,
        "db_lineage_counts": lineage_counts,
        "classification_help": {
            "eligible_unverified": "Current-workspace regular session file has sidecar, manifest, DB identity, and canonical blob; hash verification not requested.",
            "eligible_verified": "Current-workspace regular session file matches expected SHA-256 and canonical blob; safe thin-session candidate.",
            "already_thin_symlink": "Session path is already a symlink and no longer carries duplicate APK payload bytes.",
            "blocked_canonical_missing": "Session file exists, but canonical SHA-store blob is missing.",
            "blocked_hash_mismatch": "Session file or canonical blob did not hash to the expected SHA-256 under verification mode.",
            "blocked_missing_manifest": "Session file is missing harvest_package_manifest.json in its package evidence directory.",
            "blocked_missing_sidecar": "Session file is missing its adjacent .meta.json sidecar.",
            "blocked_identity_unknown": "Session file lacks a usable SHA-256 or does not map to a DB APK identity row.",
            "recorded_path_present": "DB lineage row still points at an existing recorded path.",
            "recorded_path_stale_canonical_present": "DB recorded path is stale, but canonical blob still exists locally.",
            "recorded_path_stale_canonical_missing": "DB recorded path is stale and canonical blob is also missing locally.",
            "blocked_old_root": "DB lineage row belongs to a non-current missing storage root, but a canonical blob exists locally.",
            "historical_identity_only": "DB lineage row belongs to a missing historical root and only the identity ledger remains.",
        },
        "roots": root_rows,
        "session_pressure": {
            "summary": dict(sorted(session_counter.items())),
            "rows": [asdict(row) for row in session_rows],
        },
        "db_lineage": {
            "summary": lineage_counts,
            "rows": [asdict(row) for row in db_lineage_rows],
        },
        "inode_accounting": inode_summary,
        "base_hash_summary": base_hash_summary,
        "install_set_summary": {
            "table_summary": install_set_table_summary,
            "states": dict(sorted(install_set_counter.items())),
            "by_base_hash": install_sets_by_sha,
        },
        "thin_session_rollout_gate": {
            "new_harvest_rollout_ready": int(install_set_table_summary.get("install_sets_incomplete") or 0) == 0,
            "recommended_scope": (
                "enable_new_harvest_only"
                if int(install_set_table_summary.get("install_sets_incomplete") or 0) == 0
                else "hold_until_install_sets_complete"
            ),
            "blocked_missing_sidecar_files": len(blocked_missing_sidecar_rows),
            "blocked_missing_sidecar_bytes": blocked_missing_sidecar_bytes,
            "already_thin_symlink_files": int(session_counter.get("already_thin_symlink", 0)),
            "install_sets_incomplete": int(install_set_table_summary.get("install_sets_incomplete") or 0),
            "logical_reclaimable_bytes": sum(int(row.reclaimable_bytes or 0) for row in eligible_rows),
            "physical_reclaimable_bytes_estimate": int(distinct_copy_physical_reclaimable_bytes),
            "session_files_hardlinked_to_canonical": int(session_hardlinked_to_canonical_files),
        },
        "notes": [
            "Harvest run directories are provenance layout; canonical SHA-256 store is byte authority when present.",
            "Session-copy pressure counts only regular *.apk files under data/device_apks/.../runs and excludes symlinks, sidecars, and manifests.",
            "Historical missing-root rows are reported separately from current-workspace reclaimable bytes.",
        ],
    }


def generate_thin_session_gate_report(
    *,
    data_root: Path | None = None,
    out_dir: Path | None = None,
    stamp: str | None = None,
    session_label: str | None = None,
    latest_session: bool = False,
) -> tuple[dict[str, Any], Path, Path]:
    report = build_thin_session_gate_report(
        data_root=data_root,
        session_label=session_label,
        latest_session=latest_session,
    )
    json_path, csv_path = write_thin_session_gate_report(
        report,
        out_dir=out_dir,
        stamp=stamp,
    )
    return report, json_path, csv_path


def build_thin_session_gate_report(
    *,
    data_root: Path | None = None,
    session_label: str | None = None,
    latest_session: bool = False,
) -> dict[str, Any]:
    resolved_data_root = (data_root or artifact_store.data_root()).resolve()
    device_root = (resolved_data_root / "device_apks").resolve()
    canonical_root = (resolved_data_root / "store" / "apk" / "sha256").resolve()
    repo_root = resolved_data_root.parent.resolve()

    session_dir = _resolve_selected_session_dir(
        device_root=device_root,
        session_label=session_label,
        latest_session=latest_session,
    )
    artifact_rows = [
        _build_session_gate_artifact_row(
            apk_path=apk_path,
            device_root=device_root,
            canonical_root=canonical_root,
        )
        for apk_path in _iter_session_apk_paths(session_dir)
    ]
    actual_apk_abs_paths = {str(row.get("absolute_path") or "") for row in artifact_rows}

    package_manifests = 0
    package_manifests_with_observed_artifacts = 0
    package_manifests_policy_or_empty = 0
    observed_artifacts = 0
    observed_with_canonical_store_path = 0
    observed_with_local_artifact_path = 0
    canonical_blobs_present = 0
    canonical_blobs_missing = 0
    local_artifact_path_points_to_session_path = 0
    manifest_rows: list[dict[str, Any]] = []

    for manifest_path in sorted(session_dir.rglob("harvest_package_manifest.json")):
        if not manifest_path.is_file():
            continue
        package_manifests += 1
        manifest_payload = _load_json(manifest_path)
        observed = _manifest_observed_artifacts(manifest_payload)
        observed_count = len(observed)
        if observed_count > 0:
            package_manifests_with_observed_artifacts += 1
        else:
            package_manifests_policy_or_empty += 1
        manifest_rows.append(
            {
                "manifest_path": _safe_relative(manifest_path, session_dir),
                "observed_artifacts": observed_count,
                "has_observed_artifacts": observed_count > 0,
            }
        )
        for entry in observed:
            observed_artifacts += 1
            local_rel = _text_or_none(entry.get("local_artifact_path"))
            canonical_text = _text_or_none(entry.get("canonical_store_path"))

            if local_rel:
                observed_with_local_artifact_path += 1
                local_abs = _resolve_local_artifact_path(device_root=device_root, local_artifact_path=local_rel)
                if (
                    local_abs is not None
                    and _path_within_root(local_abs, session_dir)
                    and local_abs.as_posix() in actual_apk_abs_paths
                ):
                    local_artifact_path_points_to_session_path += 1

            if canonical_text:
                observed_with_canonical_store_path += 1
                canonical_abs = _resolve_declared_path(repo_root=repo_root, rel_or_abs=canonical_text)
                if canonical_abs is not None and canonical_abs.exists():
                    canonical_blobs_present += 1
                else:
                    canonical_blobs_missing += 1
            else:
                canonical_blobs_missing += 1

    apk_paths_total = len(artifact_rows)
    regular_apk_files = sum(1 for row in artifact_rows if not bool(row.get("is_symlink")))
    symlink_apk_files = sum(1 for row in artifact_rows if bool(row.get("is_symlink")))
    sidecars = sum(1 for row in artifact_rows if bool(row.get("sidecar_present")))
    missing_sidecars = apk_paths_total - sidecars
    missing_manifests_for_apk_paths = sum(1 for row in artifact_rows if not bool(row.get("manifest_present")))
    symlink_targets_inside_canonical_store = sum(
        1 for row in artifact_rows if bool(row.get("symlink_target_inside_canonical_store"))
    )
    symlink_targets_outside_canonical_store = sum(
        1
        for row in artifact_rows
        if bool(row.get("is_symlink")) and not bool(row.get("symlink_target_inside_canonical_store"))
    )

    gate_fail_reasons: list[str] = []
    if apk_paths_total <= 0:
        gate_fail_reasons.append("no_apk_paths_found")
    if regular_apk_files != 0:
        gate_fail_reasons.append("regular_apk_files_present")
    if symlink_apk_files != apk_paths_total:
        gate_fail_reasons.append("symlink_apk_files_do_not_cover_all_apk_paths")
    if missing_sidecars != 0:
        gate_fail_reasons.append("missing_sidecars")
    if missing_manifests_for_apk_paths != 0:
        gate_fail_reasons.append("missing_manifests_for_apk_paths")
    if observed_with_canonical_store_path != observed_artifacts:
        gate_fail_reasons.append("observed_artifacts_missing_canonical_store_path")
    if observed_with_local_artifact_path != observed_artifacts:
        gate_fail_reasons.append("observed_artifacts_missing_local_artifact_path")
    if canonical_blobs_missing != 0:
        gate_fail_reasons.append("canonical_blobs_missing")
    if symlink_targets_outside_canonical_store != 0:
        gate_fail_reasons.append("symlink_targets_outside_canonical_store")
    if local_artifact_path_points_to_session_path != observed_artifacts:
        gate_fail_reasons.append("observed_local_artifact_paths_not_pointing_to_session")

    summary = {
        "session_label": session_dir.name,
        "device_serial": _session_device_serial(session_dir),
        "run_dir": session_dir.as_posix(),
        "package_manifests": package_manifests,
        "package_manifests_with_observed_artifacts": package_manifests_with_observed_artifacts,
        "package_manifests_policy_or_empty": package_manifests_policy_or_empty,
        "observed_artifacts": observed_artifacts,
        "apk_paths_total": apk_paths_total,
        "regular_apk_files": regular_apk_files,
        "symlink_apk_files": symlink_apk_files,
        "sidecars": sidecars,
        "missing_sidecars": missing_sidecars,
        "missing_manifests_for_apk_paths": missing_manifests_for_apk_paths,
        "observed_with_canonical_store_path": observed_with_canonical_store_path,
        "observed_with_local_artifact_path": observed_with_local_artifact_path,
        "canonical_blobs_present": canonical_blobs_present,
        "canonical_blobs_missing": canonical_blobs_missing,
        "symlink_targets_inside_canonical_store": symlink_targets_inside_canonical_store,
        "symlink_targets_outside_canonical_store": symlink_targets_outside_canonical_store,
        "local_artifact_path_points_to_session_path": local_artifact_path_points_to_session_path,
        "gate_pass": not gate_fail_reasons,
        "gate_fail_reasons": gate_fail_reasons,
    }
    return {
        "schema_version": "thin_session_gate_v1",
        "mode": "read_only",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "data_root": resolved_data_root.as_posix(),
        "repo_root": repo_root.as_posix(),
        "device_apks_root": device_root.as_posix(),
        "canonical_store_root": canonical_root.as_posix(),
        "selection": {
            "requested_session_label": _text_or_none(session_label),
            "latest_session": bool(latest_session),
        },
        "summary": summary,
        "artifact_rows": artifact_rows,
        "manifest_rows": manifest_rows,
    }


def build_blocked_sidecar_report(
    *,
    core_q: Any,
    data_root: Path | None = None,
    audit: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_audit = audit or build_storage_pressure_audit(core_q=core_q, data_root=data_root, verify_candidates=False)
    resolved_data_root = (data_root or artifact_store.data_root()).resolve()
    device_root = (resolved_data_root / "device_apks").resolve()
    canonical_root = (resolved_data_root / "store" / "apk" / "sha256").resolve()
    repo_root = resolved_data_root.parent.resolve()

    db_artifact_rows = _load_db_artifact_rows(core_q)
    db_sha_index = _build_db_sha_index(db_artifact_rows)

    session_payload = resolved_audit.get("session_pressure")
    session_rows = session_payload.get("rows", []) if isinstance(session_payload, Mapping) else []
    blocked_rows = [
        row for row in session_rows
        if isinstance(row, Mapping) and str(row.get("classification") or "") == "blocked_missing_sidecar"
    ]

    report_rows = [
        _build_blocked_sidecar_row(
            row=row,
            device_root=device_root,
            canonical_root=canonical_root,
            repo_root=repo_root,
            db_sha_index=db_sha_index,
        )
        for row in blocked_rows
    ]

    safe_count = sum(1 for row in report_rows if bool(row.get("safe_sidecar_reconstruction_possible")))
    summary = {
        "blocked_sidecar_files": len(report_rows),
        "blocked_sidecar_bytes": sum(int(row.get("file_size") or 0) for row in report_rows),
        "safe_reconstruction_candidates": safe_count,
        "needs_manual_review": len(report_rows) - safe_count,
        "recommended_actions": dict(
            sorted(Counter(str(row.get("recommended_action") or "unknown") for row in report_rows).items())
        ),
    }
    return {
        "schema_version": "storage_pressure_blocked_sidecars_v1",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "data_root": resolved_data_root.as_posix(),
        "summary": summary,
        "rows": report_rows,
    }


def write_blocked_sidecar_report(
    report: Mapping[str, Any],
    *,
    out_dir: Path | None = None,
    stamp: str | None = None,
) -> tuple[Path, Path]:
    resolved_out_dir = (out_dir or default_output_root()).resolve()
    resolved_out_dir.mkdir(parents=True, exist_ok=True)
    resolved_stamp = stamp or audit_stamp()

    json_path = resolved_out_dir / f"storage_pressure_blocked_sidecars_{resolved_stamp}.json"
    csv_path = resolved_out_dir / f"storage_pressure_blocked_sidecars_{resolved_stamp}.csv"
    atomic_write_text(json_path, json.dumps(json_ready(report), indent=2, sort_keys=True) + "\n")
    _write_blocked_sidecar_csv(csv_path, report)
    return json_path, csv_path


def write_thin_session_gate_report(
    report: Mapping[str, Any],
    *,
    out_dir: Path | None = None,
    stamp: str | None = None,
) -> tuple[Path, Path]:
    resolved_out_dir = (out_dir or default_output_root()).resolve()
    resolved_out_dir.mkdir(parents=True, exist_ok=True)
    resolved_stamp = stamp or audit_stamp()
    summary = report.get("summary") if isinstance(report, Mapping) else {}
    session_label = _safe_filename_fragment(
        _text_or_none(summary.get("session_label") if isinstance(summary, Mapping) else None) or "unknown"
    )

    json_path = resolved_out_dir / f"thin_session_gate_{session_label}_{resolved_stamp}.json"
    csv_path = resolved_out_dir / f"thin_session_gate_artifacts_{session_label}_{resolved_stamp}.csv"
    atomic_write_text(json_path, json.dumps(json_ready(report), indent=2, sort_keys=True) + "\n")
    _write_thin_session_gate_csv(csv_path, report)
    return json_path, csv_path


def write_storage_pressure_audit(
    audit: Mapping[str, Any],
    *,
    out_dir: Path | None = None,
    stamp: str | None = None,
) -> tuple[Path, Path]:
    resolved_out_dir = (out_dir or default_output_root()).resolve()
    resolved_out_dir.mkdir(parents=True, exist_ok=True)
    resolved_stamp = stamp or audit_stamp()

    json_path = resolved_out_dir / f"storage_pressure_audit_{resolved_stamp}.json"
    csv_path = resolved_out_dir / f"storage_pressure_files_{resolved_stamp}.csv"
    atomic_write_text(json_path, json.dumps(json_ready(audit), indent=2, sort_keys=True) + "\n")
    _write_csv(csv_path, audit)
    return json_path, csv_path


def _load_db_artifact_rows(core_q: Any) -> list[dict[str, Any]]:
    return list(
        core_q.run_sql(
            """
            SELECT
              r.apk_id,
              LOWER(TRIM(r.package_name)) AS package_name,
              COALESCE(CAST(r.version_code AS CHAR), '') AS version_code,
              COALESCE(r.version_name, '') AS version_name,
              LOWER(TRIM(r.sha256)) AS sha256,
              COALESCE(r.is_split_member, 0) AS is_split_member,
              h.local_rel_path,
              sr.root_id AS storage_root_id,
              sr.data_root
            FROM android_apk_repository r
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            WHERE r.sha256 IS NOT NULL
            """,
            fetch="all",
            dictionary=True,
            query_name="storage_pressure.db_artifact_rows",
        )
        or []
    )


def _load_storage_roots(core_q: Any) -> list[dict[str, Any]]:
    return list(
        core_q.run_sql(
            """
            SELECT root_id, host_name, data_root
            FROM harvest_storage_roots
            ORDER BY root_id
            """,
            fetch="all",
            dictionary=True,
            query_name="storage_pressure.storage_roots",
        )
        or []
    )


def _load_install_set_summary_by_hash(core_q: Any, lineage: Any) -> dict[str, dict[str, Any]]:
    if not lineage.table_exists(core_q, "apk_sets"):
        return {}
    rows = core_q.run_sql(
        """
        SELECT
          LOWER(TRIM(base_apk_sha256)) AS base_apk_sha256,
          COUNT(*) AS install_sets_seen,
          SUM(CASE WHEN COALESCE(completeness_state, 'unknown') = 'complete' THEN 1 ELSE 0 END) AS complete_sets,
          MIN(apk_set_id) AS apk_set_id,
          MIN(artifact_set_hash) AS artifact_set_hash,
          MAX(member_count) AS member_count,
          MAX(split_count) AS split_count,
          MIN(COALESCE(completeness_state, 'unknown')) AS completeness_state
        FROM apk_sets
        WHERE base_apk_sha256 IS NOT NULL
        GROUP BY LOWER(TRIM(base_apk_sha256))
        """,
        fetch="all",
        dictionary=True,
        query_name="storage_pressure.install_sets_by_hash",
    ) or []
    return {str(row.get("base_apk_sha256") or "").lower(): dict(row) for row in rows}


def _scan_canonical_store(canonical_root: Path) -> dict[str, int]:
    files = list(canonical_root.rglob("*.apk")) if canonical_root.exists() else []
    return {
        "canonical_apk_files": len(files),
        "canonical_apk_bytes": sum(path.stat().st_size for path in files if path.is_file()),
    }


def _scan_inode_accounting(*, device_root: Path, canonical_root: Path) -> dict[str, int]:
    roots = {
        "session": device_root,
        "canonical": canonical_root,
    }
    by_inode: dict[tuple[int, int], dict[str, Any]] = defaultdict(
        lambda: {
            "kinds": set(),
            "size": 0,
            "blocks": 0,
        }
    )
    totals = {
        "session_files": 0,
        "session_apparent_bytes": 0,
        "session_allocated_bytes": 0,
        "canonical_files": 0,
        "canonical_apparent_bytes": 0,
        "canonical_allocated_bytes": 0,
    }

    for kind, root in roots.items():
        if not root.exists():
            continue
        for path in root.rglob("*.apk"):
            try:
                st = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            inode_key = (int(st.st_dev), int(st.st_ino))
            rec = by_inode[inode_key]
            rec["kinds"].add(kind)
            rec["size"] = max(int(rec["size"]), int(st.st_size))
            rec["blocks"] = max(int(rec["blocks"]), int(getattr(st, "st_blocks", 0)) * 512)
            totals[f"{kind}_files"] += 1
            totals[f"{kind}_apparent_bytes"] += int(st.st_size)
            totals[f"{kind}_allocated_bytes"] += int(getattr(st, "st_blocks", 0)) * 512

    return {
        **totals,
        "unique_apk_inodes": len(by_inode),
        "unique_inode_apparent_bytes": sum(int(rec["size"]) for rec in by_inode.values()),
        "unique_inode_allocated_bytes": sum(int(rec["blocks"]) for rec in by_inode.values()),
        "inodes_seen_in_both_session_and_canonical": sum(
            1 for rec in by_inode.values() if {"session", "canonical"} <= rec["kinds"]
        ),
        "apparent_bytes_seen_in_both_session_and_canonical": sum(
            int(rec["size"]) for rec in by_inode.values() if {"session", "canonical"} <= rec["kinds"]
        ),
        "allocated_bytes_seen_in_both_session_and_canonical": sum(
            int(rec["blocks"]) for rec in by_inode.values() if {"session", "canonical"} <= rec["kinds"]
        ),
        "session_only_inodes": sum(
            1 for rec in by_inode.values() if "session" in rec["kinds"] and "canonical" not in rec["kinds"]
        ),
        "session_only_apparent_bytes": sum(
            int(rec["size"]) for rec in by_inode.values() if "session" in rec["kinds"] and "canonical" not in rec["kinds"]
        ),
        "session_only_allocated_bytes": sum(
            int(rec["blocks"]) for rec in by_inode.values() if "session" in rec["kinds"] and "canonical" not in rec["kinds"]
        ),
        "canonical_only_inodes": sum(
            1 for rec in by_inode.values() if "canonical" in rec["kinds"] and "session" not in rec["kinds"]
        ),
        "canonical_only_apparent_bytes": sum(
            int(rec["size"]) for rec in by_inode.values() if "canonical" in rec["kinds"] and "session" not in rec["kinds"]
        ),
        "canonical_only_allocated_bytes": sum(
            int(rec["blocks"]) for rec in by_inode.values() if "canonical" in rec["kinds"] and "session" not in rec["kinds"]
        ),
    }


def _load_install_set_table_summary(core_q: Any, lineage: Any) -> dict[str, int]:
    if not lineage.table_exists(core_q, "apk_sets"):
        return {
            "install_sets_total": 0,
            "install_sets_complete": 0,
            "install_sets_incomplete": 0,
        }
    row = core_q.run_sql(
        """
        SELECT
          COUNT(*) AS install_sets_total,
          SUM(CASE WHEN COALESCE(completeness_state, 'unknown') = 'complete' THEN 1 ELSE 0 END)
            AS install_sets_complete
        FROM apk_sets
        """,
        fetch="one_dict",
        query_name="storage_pressure.install_sets_table_summary",
    ) or {}
    total = int(row.get("install_sets_total") or 0)
    complete = int(row.get("install_sets_complete") or 0)
    return {
        "install_sets_total": total,
        "install_sets_complete": complete,
        "install_sets_incomplete": max(total - complete, 0),
    }


def _same_inode(path_a: Path | None, path_b: Path | None) -> bool:
    if path_a is None or path_b is None:
        return False
    try:
        stat_a = path_a.lstat()
        stat_b = path_b.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(stat_a.st_mode)
        and stat.S_ISREG(stat_b.st_mode)
        and int(stat_a.st_dev) == int(stat_b.st_dev)
        and int(stat_a.st_ino) == int(stat_b.st_ino)
    )


def _count_session_files_hardlinked_to_canonical(
    *,
    session_rows: Iterable[PressureRow],
    canonical_root: Path,
) -> int:
    count = 0
    for row in session_rows:
        if row.classification not in {"eligible_unverified", "eligible_verified"}:
            continue
        session_path = Path(row.absolute_path) if row.absolute_path else None
        canonical_path = (canonical_root / row.sha256[:2] / f"{row.sha256}.apk").resolve() if row.sha256 else None
        if _same_inode(session_path, canonical_path):
            count += 1
    return count


def _sum_physical_reclaimable_bytes(
    *,
    session_rows: Iterable[PressureRow],
    canonical_root: Path,
    require_distinct_from_canonical: bool,
) -> int:
    total = 0
    for row in session_rows:
        session_path = Path(row.absolute_path) if row.absolute_path else None
        canonical_path = (canonical_root / row.sha256[:2] / f"{row.sha256}.apk").resolve() if row.sha256 else None
        same_inode = _same_inode(session_path, canonical_path)
        if require_distinct_from_canonical and same_inode:
            continue
        if not require_distinct_from_canonical and not same_inode:
            continue
        if session_path is None:
            continue
        try:
            st = session_path.lstat()
        except OSError:
            continue
        total += int(getattr(st, "st_blocks", 0)) * 512
    return total


def _scan_session_pressure(
    *,
    device_root: Path,
    repo_root: Path,
    canonical_root: Path,
    db_sha_set: set[str],
    install_sets_by_sha: Mapping[str, Mapping[str, Any]],
    verify_candidates: bool,
) -> list[PressureRow]:
    rows: list[PressureRow] = []
    if not device_root.exists():
        return rows

    for apk_path in sorted(device_root.rglob("*.apk")):
        if "runs" not in apk_path.parts:
            continue
        if not apk_path.is_file() and not apk_path.is_symlink():
            continue
        rows.append(
            _classify_session_apk(
                apk_path=apk_path,
                device_root=device_root,
                repo_root=repo_root,
                canonical_root=canonical_root,
                db_sha_set=db_sha_set,
                install_sets_by_sha=install_sets_by_sha,
                verify_candidates=verify_candidates,
            )
        )
    return rows


def _classify_session_apk(
    *,
    apk_path: Path,
    device_root: Path,
    repo_root: Path,
    canonical_root: Path,
    db_sha_set: set[str],
    install_sets_by_sha: Mapping[str, Mapping[str, Any]],
    verify_candidates: bool,
) -> PressureRow:
    rel_path = _safe_relative(apk_path, device_root)
    sidecar_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    manifest_path = apk_path.parent / "harvest_package_manifest.json"
    sidecar = _load_json(sidecar_path)
    sidecar_present = sidecar is not None
    manifest_present = manifest_path.exists()

    sha = _norm_sha(sidecar.get("sha256") if sidecar else None)
    canonical_path = _resolve_canonical_path(
        repo_root=repo_root,
        canonical_root=canonical_root,
        expected_sha=sha,
        declared_path=sidecar.get("canonical_store_path") if sidecar else None,
    )
    canonical_exists = bool(canonical_path and canonical_path.exists())
    package_name = _text_or_none(sidecar.get("package_name") if sidecar else None)
    version_code = _text_or_none(sidecar.get("version_code") if sidecar else None)
    version_name = _text_or_none(sidecar.get("version_name") if sidecar else None)
    session_label = _text_or_none(sidecar.get("session_stamp") if sidecar else None)
    device_serial = _text_or_none(sidecar.get("device_serial") if sidecar else None)
    install_info = install_sets_by_sha.get(sha or "", {})
    db_identity_known = bool(sha and sha in db_sha_set)
    is_symlink = apk_path.is_symlink()
    file_size = None if is_symlink else apk_path.stat().st_size
    classification = "blocked_identity_unknown"
    hash_verified = False
    note = None

    if is_symlink:
        classification = "already_thin_symlink"
    elif not sidecar_present:
        classification = "blocked_missing_sidecar"
    elif not manifest_present:
        classification = "blocked_missing_manifest"
    elif not db_identity_known:
        classification = "blocked_identity_unknown"
    elif not canonical_exists:
        classification = "blocked_canonical_missing"
    elif verify_candidates:
        session_hash = _hash_file(apk_path)
        canonical_hash = _hash_file(canonical_path) if canonical_path is not None else None
        if sha and session_hash == sha and canonical_hash == sha:
            classification = "eligible_verified"
            hash_verified = True
        else:
            classification = "blocked_hash_mismatch"
            note = "session_or_canonical_sha256_mismatch"
    else:
        classification = "eligible_unverified"

    reclaimable_bytes = int(file_size or 0) if classification in {"eligible_unverified", "eligible_verified"} else 0
    return PressureRow(
        record_kind="session_file",
        classification=classification,
        package_name=package_name,
        version_code=version_code,
        version_name=version_name,
        sha256=sha,
        file_size=file_size,
        reclaimable_bytes=reclaimable_bytes,
        session_label=session_label,
        device_serial=device_serial,
        local_rel_path=rel_path,
        absolute_path=apk_path.resolve().as_posix() if apk_path.exists() else apk_path.as_posix(),
        canonical_store_path=canonical_path.as_posix() if canonical_path else None,
        storage_root=device_root.as_posix(),
        storage_root_role="current_workspace",
        recorded_path_exists=apk_path.exists(),
        canonical_exists=canonical_exists,
        is_symlink=is_symlink,
        db_identity_known=db_identity_known,
        manifest_present=manifest_present,
        sidecar_present=sidecar_present,
        hash_verified=hash_verified,
        install_set_present=bool(install_info),
        install_set_state=_text_or_none(install_info.get("completeness_state")),
        install_set_member_count=int(install_info.get("member_count") or 0),
        install_set_split_count=int(install_info.get("split_count") or 0),
        note=note,
    )


def _resolve_selected_session_dir(
    *,
    device_root: Path,
    session_label: str | None,
    latest_session: bool,
) -> Path:
    session_dirs = _iter_session_run_dirs(device_root)
    if not session_dirs:
        raise ValueError(f"No harvest session directories found under {device_root}")
    if latest_session:
        return max(session_dirs, key=_session_dir_sort_key)
    requested = _text_or_none(session_label)
    if requested:
        matches = [path for path in session_dirs if path.name == requested]
        if not matches:
            raise ValueError(f"Harvest session {requested!r} was not found under {device_root}")
        if len(matches) > 1:
            joined = ", ".join(path.as_posix() for path in matches)
            raise ValueError(f"Harvest session {requested!r} is ambiguous: {joined}")
        return matches[0]
    return max(session_dirs, key=_session_dir_sort_key)


def _iter_session_run_dirs(device_root: Path) -> list[Path]:
    if not device_root.exists():
        return []
    return sorted(
        (path for path in device_root.glob("*/runs/*") if path.is_dir()),
        key=lambda item: item.as_posix(),
    )


def _session_dir_sort_key(path: Path) -> tuple[int, str]:
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        mtime = 0
    return (mtime, path.as_posix())


def _session_device_serial(session_dir: Path) -> str | None:
    try:
        return _text_or_none(session_dir.parent.parent.name)
    except Exception:
        return None


def _iter_session_apk_paths(session_dir: Path) -> list[Path]:
    rows: list[Path] = []
    if not session_dir.exists():
        return rows
    for apk_path in sorted(session_dir.rglob("*.apk")):
        if not apk_path.is_file() and not apk_path.is_symlink():
            continue
        rows.append(apk_path)
    return rows


def _build_session_gate_artifact_row(
    *,
    apk_path: Path,
    device_root: Path,
    canonical_root: Path,
) -> dict[str, Any]:
    sidecar_path = apk_path.with_suffix(".apk.meta.json")
    sidecar = _load_json(sidecar_path)
    manifest_path = apk_path.parent / "harvest_package_manifest.json"
    is_symlink = apk_path.is_symlink()
    symlink_target = _read_symlink_target(apk_path) if is_symlink else None
    return {
        "local_rel_path": _safe_relative(apk_path, device_root),
        "absolute_path": _lexical_absolute_path(apk_path).as_posix(),
        "manifest_present": manifest_path.exists(),
        "sidecar_present": sidecar is not None,
        "is_symlink": is_symlink,
        "symlink_target": symlink_target.as_posix() if symlink_target else None,
        "symlink_target_inside_canonical_store": bool(
            symlink_target and _path_within_root(symlink_target, canonical_root)
        ),
        "sidecar_canonical_store_path": _text_or_none(sidecar.get("canonical_store_path")) if sidecar else None,
        "sidecar_local_path": _text_or_none(sidecar.get("local_path")) if sidecar else None,
    }


def _build_db_lineage_rows(
    *,
    db_artifact_rows: Iterable[Mapping[str, Any]],
    current_device_root: Path,
    canonical_root: Path,
    install_sets_by_sha: Mapping[str, Mapping[str, Any]],
) -> list[PressureRow]:
    rows: list[PressureRow] = []
    current_root_text = current_device_root.resolve().as_posix()
    for row in db_artifact_rows:
        sha = _norm_sha(row.get("sha256"))
        data_root = _text_or_none(row.get("data_root"))
        local_rel_path = _text_or_none(row.get("local_rel_path"))
        recorded_path = _resolve_db_recorded_path(data_root=data_root, local_rel_path=local_rel_path)
        recorded_exists = bool(recorded_path and recorded_path.exists())
        canonical_path = (canonical_root / sha[:2] / f"{sha}.apk").resolve() if sha else None
        canonical_exists = bool(canonical_path and canonical_path.exists())
        root_exists = bool(data_root and Path(data_root).expanduser().exists())
        root_role = _root_role(data_root, current_root_text)
        install_info = install_sets_by_sha.get(sha or "", {})

        if root_role == "historical_missing_root":
            classification = "blocked_old_root" if canonical_exists else "historical_identity_only"
        elif recorded_exists:
            classification = "recorded_path_present"
        else:
            classification = (
                "recorded_path_stale_canonical_present"
                if canonical_exists
                else "recorded_path_stale_canonical_missing"
            )

        rows.append(
            PressureRow(
                record_kind="db_lineage",
                classification=classification,
                package_name=_text_or_none(row.get("package_name")),
                version_code=_text_or_none(row.get("version_code")),
                version_name=_text_or_none(row.get("version_name")),
                sha256=sha,
                file_size=recorded_path.stat().st_size if recorded_exists and recorded_path and recorded_path.is_file() else None,
                reclaimable_bytes=0,
                session_label=None,
                device_serial=None,
                local_rel_path=local_rel_path,
                absolute_path=recorded_path.as_posix() if recorded_path else None,
                canonical_store_path=canonical_path.as_posix() if canonical_path else None,
                storage_root=data_root,
                storage_root_role=root_role,
                recorded_path_exists=recorded_exists,
                canonical_exists=canonical_exists,
                is_symlink=bool(recorded_path and recorded_path.is_symlink()),
                db_identity_known=bool(sha),
                manifest_present=False,
                sidecar_present=False,
                hash_verified=False,
                install_set_present=bool(install_info),
                install_set_state=_text_or_none(install_info.get("completeness_state")),
                install_set_member_count=int(install_info.get("member_count") or 0),
                install_set_split_count=int(install_info.get("split_count") or 0),
                note=None if root_exists or root_role == "current_workspace" else "historical_missing_root",
            )
        )
    return rows


def _build_base_hash_summary(
    *,
    base_rows: Iterable[Mapping[str, Any]],
    canonical_root: Path,
) -> dict[str, Any]:
    base_apk_identities = 0
    available = 0
    missing = 0
    rows: list[dict[str, Any]] = []
    for row in base_rows:
        sha = _norm_sha(row.get("base_apk_sha256"))
        if not sha:
            continue
        base_apk_identities += 1
        recorded_path = _resolve_db_recorded_path(
            data_root=_text_or_none(row.get("data_root")),
            local_rel_path=_text_or_none(row.get("local_rel_path")),
        )
        recorded_exists = bool(recorded_path and recorded_path.exists())
        canonical_path = canonical_root / sha[:2] / f"{sha}.apk"
        canonical_exists = canonical_path.exists()
        bytes_available = recorded_exists or canonical_exists
        available += int(bytes_available)
        missing += int(not bytes_available)
        rows.append(
            {
                "package_name": _text_or_none(row.get("package_name")),
                "version_code": _text_or_none(row.get("version_code")),
                "version_name": _text_or_none(row.get("version_name")),
                "base_apk_sha256": sha,
                "recorded_path_exists": recorded_exists,
                "canonical_exists": canonical_exists,
                "bytes_available": bytes_available,
            }
        )
    return {
        "base_apk_identities": base_apk_identities,
        "base_hashes_with_bytes_available": available,
        "base_hashes_missing_bytes": missing,
        "rows": rows,
    }


def _build_root_rows(
    *,
    storage_roots: Iterable[Mapping[str, Any]],
    current_device_root: Path,
    db_lineage_rows: Iterable[PressureRow],
) -> list[dict[str, Any]]:
    current_root_text = current_device_root.resolve().as_posix()
    grouped: dict[str, int] = Counter(str(row.storage_root or "") for row in db_lineage_rows)
    out: list[dict[str, Any]] = []
    for row in storage_roots:
        path = _text_or_none(row.get("data_root")) or ""
        exists = bool(path and Path(path).expanduser().exists())
        out.append(
            {
                "root_id": row.get("root_id"),
                "host_name": row.get("host_name"),
                "path": path,
                "exists": exists,
                "role": _root_role(path, current_root_text),
                "artifact_rows": int(grouped.get(path, 0)),
            }
        )
    out.sort(key=lambda item: (item["role"] != "current_workspace", str(item["path"])))
    return out


def _write_csv(path: Path, audit: Mapping[str, Any]) -> None:
    rows: list[dict[str, Any]] = []
    for section in ("session_pressure", "db_lineage"):
        payload = audit.get(section)
        if not isinstance(payload, Mapping):
            continue
        for row in payload.get("rows", []):
            if isinstance(row, Mapping):
                rows.append(dict(row))

    fieldnames = [
        "record_kind",
        "classification",
        "package_name",
        "version_code",
        "version_name",
        "sha256",
        "file_size",
        "reclaimable_bytes",
        "session_label",
        "device_serial",
        "local_rel_path",
        "absolute_path",
        "canonical_store_path",
        "storage_root",
        "storage_root_role",
        "recorded_path_exists",
        "canonical_exists",
        "is_symlink",
        "db_identity_known",
        "manifest_present",
        "sidecar_present",
        "hash_verified",
        "install_set_present",
        "install_set_state",
        "install_set_member_count",
        "install_set_split_count",
        "note",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name) for name in fieldnames})
    atomic_write_text(path, buffer.getvalue())


def _write_blocked_sidecar_csv(path: Path, report: Mapping[str, Any]) -> None:
    rows = report.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    fieldnames = [
        "local_rel_path",
        "absolute_path",
        "file_size",
        "package_name",
        "package_name_source",
        "version_code",
        "version_name",
        "session_label",
        "device_serial",
        "manifest_path",
        "manifest_present",
        "manifest_package_name",
        "manifest_version_code",
        "manifest_version_name",
        "inferred_sha256",
        "sha_source",
        "db_identity_known",
        "db_match_count",
        "db_package_names",
        "canonical_store_path",
        "canonical_exists",
        "safe_sidecar_reconstruction_possible",
        "recommended_action",
        "reconstruction_reason",
        "install_set_present",
        "install_set_state",
        "note",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        serialized = dict(row)
        if isinstance(serialized.get("db_package_names"), list):
            serialized["db_package_names"] = ";".join(str(item) for item in serialized["db_package_names"])
        writer.writerow({name: serialized.get(name) for name in fieldnames})
    atomic_write_text(path, buffer.getvalue())


def _write_thin_session_gate_csv(path: Path, report: Mapping[str, Any]) -> None:
    rows = report.get("artifact_rows", [])
    if not isinstance(rows, list):
        rows = []
    fieldnames = [
        "local_rel_path",
        "absolute_path",
        "manifest_present",
        "sidecar_present",
        "is_symlink",
        "symlink_target",
        "symlink_target_inside_canonical_store",
        "sidecar_canonical_store_path",
        "sidecar_local_path",
    ]
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        writer.writerow({name: row.get(name) for name in fieldnames})
    atomic_write_text(path, buffer.getvalue())


def _build_db_sha_index(db_artifact_rows: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for row in db_artifact_rows:
        sha = _norm_sha(row.get("sha256"))
        if not sha:
            continue
        index.setdefault(sha, []).append(dict(row))
    return index


def _build_blocked_sidecar_row(
    *,
    row: Mapping[str, Any],
    device_root: Path,
    canonical_root: Path,
    repo_root: Path,
    db_sha_index: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    local_rel_path = _text_or_none(row.get("local_rel_path"))
    absolute_path = _resolve_session_row_path(row=row, device_root=device_root)
    manifest_path = _nearest_manifest_path(absolute_path, device_root=device_root) if absolute_path else None
    manifest = _load_json(manifest_path) if manifest_path else None

    manifest_package = _manifest_package_value(manifest, "package_name")
    manifest_version_code = _manifest_package_value(manifest, "version_code")
    manifest_version_name = _manifest_package_value(manifest, "version_name")
    session_label = _manifest_package_value(manifest, "session_label") or _session_label_from_rel(local_rel_path)
    device_serial = _manifest_package_value(manifest, "device_serial") or _device_serial_from_rel(local_rel_path)

    inferred_sha = (
        _hash_file(absolute_path)
        if absolute_path and absolute_path.exists() and absolute_path.is_file() and not absolute_path.is_symlink()
        else None
    )
    canonical_path = _resolve_canonical_path(
        repo_root=repo_root,
        canonical_root=canonical_root,
        expected_sha=inferred_sha,
        declared_path=None,
    )
    canonical_exists = bool(canonical_path and canonical_path.exists())

    db_matches = list(db_sha_index.get(inferred_sha or "", []))
    db_package_names = sorted(
        {
            text
            for text in (_text_or_none(match.get("package_name")) for match in db_matches)
            if text
        }
    )
    inferred_package_from_path = _infer_package_name_from_rel(local_rel_path)
    inferred_package_from_filename = _infer_package_name_from_filename(absolute_path.name if absolute_path else None)
    package_name, package_name_source = _choose_blocker_package_name(
        manifest_package=manifest_package,
        db_package_names=db_package_names,
        inferred_package_from_path=inferred_package_from_path,
        inferred_package_from_filename=inferred_package_from_filename,
    )

    install_set_state = _text_or_none(row.get("install_set_state"))
    install_set_present = bool(row.get("install_set_present"))

    safe_reconstruction = bool(
        manifest_path
        and manifest_package
        and inferred_sha
        and canonical_exists
        and db_matches
        and (manifest_package in db_package_names if db_package_names else True)
    )
    recommended_action, reconstruction_reason = _blocked_sidecar_recommendation(
        manifest_present=manifest_path is not None,
        manifest_package=manifest_package,
        inferred_sha=inferred_sha,
        canonical_exists=canonical_exists,
        db_matches=db_matches,
        safe_reconstruction=safe_reconstruction,
        inferred_package_from_path=inferred_package_from_path,
        inferred_package_from_filename=inferred_package_from_filename,
    )

    note = None
    if manifest_path is None and inferred_package_from_path is None:
        note = "orphan_session_file_outside_package_dir"
    elif manifest_path is not None and not db_matches:
        note = "manifest_present_but_sha_not_in_db_identity_catalog"

    return {
        "local_rel_path": local_rel_path,
        "absolute_path": absolute_path.as_posix() if absolute_path else None,
        "file_size": int(row.get("file_size") or (absolute_path.stat().st_size if absolute_path and absolute_path.exists() else 0)),
        "package_name": package_name,
        "package_name_source": package_name_source,
        "version_code": manifest_version_code,
        "version_name": manifest_version_name,
        "session_label": session_label,
        "device_serial": device_serial,
        "manifest_path": manifest_path.as_posix() if manifest_path else None,
        "manifest_present": manifest_path is not None,
        "manifest_package_name": manifest_package,
        "manifest_version_code": manifest_version_code,
        "manifest_version_name": manifest_version_name,
        "inferred_sha256": inferred_sha,
        "sha_source": "hashed_session_file" if inferred_sha else "unavailable",
        "db_identity_known": bool(db_matches),
        "db_match_count": len(db_matches),
        "db_package_names": db_package_names,
        "canonical_store_path": canonical_path.as_posix() if canonical_path else None,
        "canonical_exists": canonical_exists,
        "safe_sidecar_reconstruction_possible": safe_reconstruction,
        "recommended_action": recommended_action,
        "reconstruction_reason": reconstruction_reason,
        "install_set_present": install_set_present,
        "install_set_state": install_set_state,
        "note": note,
    }


def _resolve_session_row_path(*, row: Mapping[str, Any], device_root: Path) -> Path | None:
    absolute_text = _text_or_none(row.get("absolute_path"))
    if absolute_text:
        candidate = Path(absolute_text)
        if candidate.exists():
            return candidate
    local_rel_path = _text_or_none(row.get("local_rel_path"))
    if local_rel_path:
        candidate = device_root / local_rel_path
        if candidate.exists():
            return candidate
    return Path(absolute_text) if absolute_text else None


def _nearest_manifest_path(path: Path | None, *, device_root: Path) -> Path | None:
    if path is None:
        return None
    try:
        rel = path.resolve().relative_to(device_root.resolve())
    except Exception:
        rel = None
    current = path.parent
    max_up = max(len(rel.parts), 0) if rel is not None else 8
    for _ in range(max_up + 1):
        candidate = current / "harvest_package_manifest.json"
        if candidate.exists():
            return candidate
        if current == device_root or current.parent == current:
            break
        current = current.parent
    return None


def _manifest_package_value(manifest: Mapping[str, Any] | None, key: str) -> str | None:
    if not isinstance(manifest, Mapping):
        return None
    package_block = manifest.get("package")
    if not isinstance(package_block, Mapping):
        return None
    return _text_or_none(package_block.get(key))


def _manifest_observed_artifacts(manifest: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if not isinstance(manifest, Mapping):
        return []
    execution = manifest.get("execution")
    if not isinstance(execution, Mapping):
        return []
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return []
    return [entry for entry in observed if isinstance(entry, Mapping)]


def _session_label_from_rel(local_rel_path: str | None) -> str | None:
    if not local_rel_path:
        return None
    parts = Path(local_rel_path).parts
    if "runs" in parts:
        idx = parts.index("runs")
        if idx + 1 < len(parts):
            return _text_or_none(parts[idx + 1])
    return None


def _device_serial_from_rel(local_rel_path: str | None) -> str | None:
    if not local_rel_path:
        return None
    parts = Path(local_rel_path).parts
    return _text_or_none(parts[0]) if parts else None


def _infer_package_name_from_rel(local_rel_path: str | None) -> str | None:
    if not local_rel_path:
        return None
    parts = Path(local_rel_path).parts
    if "runs" not in parts:
        return None
    idx = parts.index("runs")
    if idx + 4 >= len(parts):
        return None
    return _text_or_none(parts[idx + 2])


def _infer_package_name_from_filename(filename: str | None) -> str | None:
    text = _text_or_none(filename)
    if not text or not text.endswith(".apk"):
        return None
    return _text_or_none(text[:-4])


def _choose_blocker_package_name(
    *,
    manifest_package: str | None,
    db_package_names: list[str],
    inferred_package_from_path: str | None,
    inferred_package_from_filename: str | None,
) -> tuple[str | None, str]:
    if manifest_package:
        return manifest_package, "manifest"
    if len(db_package_names) == 1:
        return db_package_names[0], "db_sha"
    if inferred_package_from_path:
        return inferred_package_from_path, "path"
    if inferred_package_from_filename:
        return inferred_package_from_filename, "filename"
    return None, "unknown"


def _blocked_sidecar_recommendation(
    *,
    manifest_present: bool,
    manifest_package: str | None,
    inferred_sha: str | None,
    canonical_exists: bool,
    db_matches: list[dict[str, Any]],
    safe_reconstruction: bool,
    inferred_package_from_path: str | None,
    inferred_package_from_filename: str | None,
) -> tuple[str, str]:
    if safe_reconstruction:
        return "rebuild_sidecar_from_manifest_and_hash", "manifest+hash+canonical+db_identity"
    if manifest_present and manifest_package and inferred_sha and not canonical_exists:
        return "canonical_missing_reharvest_or_restore", "manifest_present_but_canonical_blob_missing"
    if manifest_present and manifest_package and inferred_sha and not db_matches:
        return "review_manifest_identity_vs_db", "manifest_present_but_sha_not_found_in_db"
    if not manifest_present and (inferred_package_from_path or inferred_package_from_filename):
        return "investigate_orphan_session_file", "package_inferred_without_manifest"
    if not manifest_present:
        return "investigate_orphan_session_file", "no_manifest_or_sidecar"
    if not inferred_sha:
        return "rehash_or_manual_review", "sha_unavailable_from_session_file"
    return "manual_review", "insufficient_identity_or_provenance"


def _load_json(path: Path) -> Mapping[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, Mapping) else None


def _resolve_canonical_path(
    *,
    repo_root: Path,
    canonical_root: Path,
    expected_sha: str | None,
    declared_path: object,
) -> Path | None:
    text = _text_or_none(declared_path)
    if text:
        candidate = Path(text)
        if not candidate.is_absolute():
            repo_candidate = (repo_root / text).resolve()
            if repo_candidate.exists():
                return repo_candidate
            cwd_candidate = (Path.cwd().resolve() / text).resolve()
            return cwd_candidate
        return candidate.resolve()
    if expected_sha:
        return (canonical_root / expected_sha[:2] / f"{expected_sha}.apk").resolve()
    return None


def _resolve_declared_path(*, repo_root: Path, rel_or_abs: str) -> Path | None:
    text = _text_or_none(rel_or_abs)
    if not text:
        return None
    candidate = Path(text).expanduser()
    if candidate.is_absolute():
        return _lexical_absolute_path(candidate)
    return _lexical_absolute_path(repo_root / candidate)


def _resolve_local_artifact_path(*, device_root: Path, local_artifact_path: str) -> Path | None:
    text = _text_or_none(local_artifact_path)
    if not text:
        return None
    candidate = Path(local_artifact_path).expanduser()
    if candidate.is_absolute():
        return _lexical_absolute_path(candidate)
    return _lexical_absolute_path(device_root / candidate)


def _resolve_db_recorded_path(*, data_root: str | None, local_rel_path: str | None) -> Path | None:
    if not local_rel_path:
        return None
    candidate = Path(local_rel_path).expanduser()
    if candidate.is_absolute():
        return candidate
    if data_root:
        return Path(data_root).expanduser() / candidate
    return None


def _lexical_absolute_path(path: Path) -> Path:
    return Path(os.path.normpath(os.path.abspath(path.expanduser().as_posix())))


def _path_within_root(path: Path, root: Path) -> bool:
    try:
        _lexical_absolute_path(path).relative_to(_lexical_absolute_path(root))
        return True
    except Exception:
        return False


def _read_symlink_target(path: Path) -> Path | None:
    if not path.is_symlink():
        return None
    try:
        raw_target = os.readlink(path)
    except OSError:
        return None
    target = Path(raw_target)
    if not target.is_absolute():
        target = path.parent / target
    return _lexical_absolute_path(target)


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        try:
            return path.absolute().relative_to(root.resolve()).as_posix()
        except Exception:
            return path.as_posix()


def _text_or_none(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _safe_filename_fragment(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in str(value or "").strip())
    cleaned = cleaned.strip("-.")
    return cleaned or "unknown"


def _norm_sha(value: object) -> str | None:
    text = str(value or "").strip().lower()
    return text or None


def _hash_file(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _root_role(path: str | None, current_root_text: str) -> str:
    text = _text_or_none(path)
    if not text:
        return "unknown_root"
    try:
        normalized = Path(text).expanduser().resolve().as_posix()
    except Exception:
        normalized = Path(text).expanduser().as_posix()
    if normalized == current_root_text:
        return "current_workspace"
    if not Path(text).expanduser().exists():
        return "historical_missing_root"
    return "foreign_existing_root"


def json_ready(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    if isinstance(value, set):
        return [json_ready(item) for item in sorted(value)]
    return value


__all__ = [
    "audit_stamp",
    "build_blocked_sidecar_report",
    "build_storage_pressure_audit",
    "build_thin_session_gate_report",
    "default_output_root",
    "generate_storage_pressure_audit",
    "generate_thin_session_gate_report",
    "json_ready",
    "write_blocked_sidecar_report",
    "write_thin_session_gate_report",
    "write_storage_pressure_audit",
]
