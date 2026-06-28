#!/usr/bin/env python3
"""Read-only APK storage-pressure and thin-session eligibility audit.

Measures current run-tree APK payload pressure, canonical SHA-store byte
authority, current-workspace thin-session candidates, and historical DB lineage
rows whose recorded paths are stale or missing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        help="Override the ScytaleDroid data root to audit (default: configured DATA_DIR).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Override output directory for JSON/CSV audit files.",
    )
    parser.add_argument(
        "--stamp",
        help="Optional output filename stamp (default: current UTC timestamp).",
    )
    parser.add_argument(
        "--verify-candidates",
        action="store_true",
        help="Hash candidate session APKs and canonical blobs before marking them eligible_verified.",
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Print only the summary object as JSON after writing the audit files.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Print the full audit payload as JSON after writing the audit files.",
    )
    parser.add_argument(
        "--blocked-sidecars",
        action="store_true",
        help="Also build and write a focused report for blocked_missing_sidecar session APKs.",
    )
    parser.add_argument(
        "--session-label",
        help="Resolve and audit one harvest session under data/device_apks/<serial>/runs/<session_label>.",
    )
    parser.add_argument(
        "--latest-session",
        action="store_true",
        help="Select the newest harvest session directory deterministically for thin-session gate checks.",
    )
    parser.add_argument(
        "--thin-session-gate",
        action="store_true",
        help="Run the read-only session-scoped thin-session rollout gate instead of the global DB-backed pressure audit.",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.DeviceAnalysis.services import storage_pressure
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if args.thin_session_gate:
        if args.session_label and args.latest_session:
            sys.stderr.write("--session-label and --latest-session are mutually exclusive.\n")
            return 2
        try:
            report, json_path, csv_path = storage_pressure.generate_thin_session_gate_report(
                data_root=args.data_root,
                out_dir=args.out_dir,
                stamp=args.stamp,
                session_label=args.session_label,
                latest_session=bool(args.latest_session),
            )
        except ValueError as exc:
            sys.stderr.write(f"{exc}\n")
            return 2

        if args.stdout_json:
            payload = {
                "schema_version": report.get("schema_version"),
                "mode": report.get("mode"),
                "generated_at_utc": report.get("generated_at_utc"),
                "data_root": report.get("data_root"),
                "repo_root": report.get("repo_root"),
                "device_apks_root": report.get("device_apks_root"),
                "canonical_store_root": report.get("canonical_store_root"),
                "selection": report.get("selection"),
                "summary": report.get("summary"),
            }
            print(json.dumps(storage_pressure.json_ready(payload), indent=2, sort_keys=True))
            return 0
        if args.summary_json:
            print(json.dumps(storage_pressure.json_ready(report.get("summary", {})), indent=2, sort_keys=True))
            return 0

        _print_thin_session_gate_text(report, json_path=json_path, csv_path=csv_path)
        return 0

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    audit, json_path, csv_path = storage_pressure.generate_storage_pressure_audit(
        core_q=core_q,
        data_root=args.data_root,
        out_dir=args.out_dir,
        stamp=args.stamp,
        verify_candidates=bool(args.verify_candidates),
    )
    blocked_report = None
    blocked_json_path = None
    blocked_csv_path = None
    if args.blocked_sidecars:
        blocked_report = storage_pressure.build_blocked_sidecar_report(
            core_q=core_q,
            data_root=args.data_root,
            audit=audit,
        )
        blocked_json_path, blocked_csv_path = storage_pressure.write_blocked_sidecar_report(
            blocked_report,
            out_dir=args.out_dir,
            stamp=args.stamp,
        )

    if args.stdout_json:
        payload = blocked_report if args.blocked_sidecars and blocked_report is not None else audit
        print(json.dumps(storage_pressure.json_ready(payload), indent=2, sort_keys=True))
        return 0
    if args.summary_json:
        payload = blocked_report.get("summary", {}) if args.blocked_sidecars and blocked_report is not None else audit.get("summary", {})
        print(json.dumps(storage_pressure.json_ready(payload), indent=2, sort_keys=True))
        return 0

    _print_text(
        audit,
        json_path=json_path,
        csv_path=csv_path,
        blocked_report=blocked_report,
        blocked_json_path=blocked_json_path,
        blocked_csv_path=blocked_csv_path,
    )
    return 0


def _print_thin_session_gate_text(
    report: dict[str, object],
    *,
    json_path: Path,
    csv_path: Path,
) -> None:
    summary = dict(report.get("summary") or {})
    print("=== Thin-Session Rollout Gate ===")
    print(f"Run dir: {summary.get('run_dir')}")
    print("")
    lines = [
        ("Session label", summary.get("session_label")),
        ("Device serial", summary.get("device_serial")),
        ("Package manifests", summary.get("package_manifests")),
        ("Manifests with observed artifacts", summary.get("package_manifests_with_observed_artifacts")),
        ("Policy/empty manifests", summary.get("package_manifests_policy_or_empty")),
        ("Observed artifacts", summary.get("observed_artifacts")),
        ("APK paths total", summary.get("apk_paths_total")),
        ("Regular APK files", summary.get("regular_apk_files")),
        ("Symlink APK files", summary.get("symlink_apk_files")),
        ("Sidecars", summary.get("sidecars")),
        ("Missing sidecars", summary.get("missing_sidecars")),
        ("Missing manifests for APK paths", summary.get("missing_manifests_for_apk_paths")),
        ("Observed with canonical_store_path", summary.get("observed_with_canonical_store_path")),
        ("Observed with local_artifact_path", summary.get("observed_with_local_artifact_path")),
        ("Canonical blobs present", summary.get("canonical_blobs_present")),
        ("Canonical blobs missing", summary.get("canonical_blobs_missing")),
        ("Symlink targets inside canonical", summary.get("symlink_targets_inside_canonical_store")),
        ("Symlink targets outside canonical", summary.get("symlink_targets_outside_canonical_store")),
        ("Observed local paths in session", summary.get("local_artifact_path_points_to_session_path")),
        ("Gate pass", summary.get("gate_pass")),
    ]
    width = max(len(str(label)) for label, _value in lines)
    for label, value in lines:
        print(f"{label:<{width}} : {value}")
    reasons = summary.get("gate_fail_reasons") or []
    print("Gate fail reasons".ljust(width) + f" : {', '.join(str(item) for item in reasons) if reasons else '—'}")
    print("")
    print(f"JSON report: {json_path}")
    print(f"CSV report : {csv_path}")


def _print_text(
    audit: dict[str, object],
    *,
    json_path: Path,
    csv_path: Path,
    blocked_report: dict[str, object] | None = None,
    blocked_json_path: Path | None = None,
    blocked_csv_path: Path | None = None,
) -> None:
    summary = dict(audit.get("summary") or {})
    session_summary = dict((audit.get("session_pressure") or {}).get("summary") or {})
    lineage_summary = dict((audit.get("db_lineage") or {}).get("summary") or {})
    rollout_gate = dict(audit.get("thin_session_rollout_gate") or {})
    print("=== APK Storage Pressure Audit ===")
    print(f"Data root: {audit.get('data_root')}")
    print(f"Verify mode: {audit.get('verify_mode')}")
    print("")
    print("Summary")
    print("-------")
    lines = [
        ("DB APK artifact rows", summary.get("db_apk_artifact_rows")),
        ("DB packages", summary.get("db_packages")),
        ("Base APK identities", summary.get("base_apk_identities")),
        ("Split member rows", summary.get("split_member_rows")),
        ("Session regular APK files", summary.get("session_regular_apk_files")),
        ("Session regular APK bytes", summary.get("session_regular_apk_bytes")),
        ("Session regular allocated bytes", summary.get("session_regular_apk_allocated_bytes")),
        ("Session symlink APK files", summary.get("session_symlink_apk_files")),
        ("Canonical APK files", summary.get("canonical_apk_files")),
        ("Canonical APK bytes", summary.get("canonical_apk_bytes")),
        ("Canonical allocated bytes", summary.get("canonical_apk_allocated_bytes")),
        ("Eligible verified files", summary.get("eligible_verified_files")),
        ("Eligible verified reclaimable bytes", summary.get("eligible_verified_reclaimable_bytes")),
        ("Eligible unverified files", summary.get("eligible_unverified_files")),
        ("Eligible unverified reclaimable bytes", summary.get("eligible_unverified_reclaimable_bytes")),
        ("Logical reclaimable bytes", summary.get("logical_reclaimable_bytes")),
        ("Physical reclaimable bytes est.", summary.get("physical_reclaimable_bytes_estimate")),
        ("Shared-inode reclaim bytes est.", summary.get("shared_inode_reclaimable_bytes_estimate")),
        ("Session files hardlinked to canonical", summary.get("session_files_hardlinked_to_canonical")),
        ("Session files distinct from canonical", summary.get("session_files_distinct_from_canonical")),
        ("Current-root stale rows", summary.get("current_root_stale_rows")),
        ("Old-root historical rows", summary.get("old_root_historical_rows")),
        ("Base hashes with bytes", summary.get("base_hashes_with_bytes_available")),
        ("Base hashes missing bytes", summary.get("base_hashes_missing_bytes")),
        ("Install sets total", summary.get("install_sets_total")),
        ("Install sets complete", summary.get("install_sets_complete")),
        ("Install sets incomplete", summary.get("install_sets_incomplete")),
        ("Base hashes with install sets", summary.get("base_hashes_with_install_sets")),
    ]
    width = max(len(str(label)) for label, _ in lines)
    for label, value in lines:
        print(f"{label:<{width}} : {value}")

    print("")
    print("Session pressure states")
    print("-----------------------")
    if session_summary:
        for key in sorted(session_summary):
            print(f"{key:<36} {session_summary[key]}")
    else:
        print("(none)")

    print("")
    print("DB lineage states")
    print("-----------------")
    if lineage_summary:
        for key in sorted(lineage_summary):
            print(f"{key:<36} {lineage_summary[key]}")
    else:
        print("(none)")

    inode_summary = dict(audit.get("inode_accounting") or {})
    if inode_summary:
        print("")
        print("Inode accounting")
        print("---------------")
        for label, key in [
            ("Unique APK inodes", "unique_apk_inodes"),
            ("Shared session+canonical inodes", "inodes_seen_in_both_session_and_canonical"),
            ("Shared apparent bytes", "apparent_bytes_seen_in_both_session_and_canonical"),
            ("Shared allocated bytes", "allocated_bytes_seen_in_both_session_and_canonical"),
            ("Session-only inodes", "session_only_inodes"),
            ("Session-only apparent bytes", "session_only_apparent_bytes"),
            ("Session-only allocated bytes", "session_only_allocated_bytes"),
            ("Canonical-only inodes", "canonical_only_inodes"),
        ]:
            print(f"{label:<31} {inode_summary.get(key)}")

    print("")
    print("Thin-session rollout gate")
    print("-------------------------")
    if rollout_gate:
        for label, value in [
            ("New harvest rollout ready", rollout_gate.get("new_harvest_rollout_ready")),
            ("Recommended scope", rollout_gate.get("recommended_scope")),
            ("Blocked missing sidecars", rollout_gate.get("blocked_missing_sidecar_files")),
            ("Blocked missing sidecar bytes", rollout_gate.get("blocked_missing_sidecar_bytes")),
            ("Already thin symlinks", rollout_gate.get("already_thin_symlink_files")),
            ("Install sets incomplete", rollout_gate.get("install_sets_incomplete")),
        ]:
            print(f"{label:<28} : {value}")
    else:
        print("(none)")

    print("")
    print("Outputs")
    print("-------")
    print(json_path)
    print(csv_path)

    if blocked_report is not None:
        _print_blocked_sidecar_text(
            blocked_report,
            json_path=blocked_json_path,
            csv_path=blocked_csv_path,
        )


def _print_blocked_sidecar_text(
    report: dict[str, object],
    *,
    json_path: Path | None,
    csv_path: Path | None,
) -> None:
    summary = dict(report.get("summary") or {})
    print("")
    print("Blocked sidecar drilldown")
    print("------------------------")
    lines = [
        ("Blocked sidecar files", summary.get("blocked_sidecar_files")),
        ("Blocked sidecar bytes", summary.get("blocked_sidecar_bytes")),
        ("Safe reconstruction candidates", summary.get("safe_reconstruction_candidates")),
        ("Needs manual review", summary.get("needs_manual_review")),
    ]
    width = max(len(str(label)) for label, _ in lines)
    for label, value in lines:
        print(f"{label:<{width}} : {value}")
    actions = summary.get("recommended_actions") or {}
    if actions:
        print("Recommended actions")
        for key in sorted(actions):
            print(f"  {key:<40} {actions[key]}")
    if json_path is not None and csv_path is not None:
        print("Outputs")
        print(f"  {json_path}")
        print(f"  {csv_path}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
