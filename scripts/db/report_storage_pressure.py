#!/usr/bin/env python3
"""Report APK session-copy pressure and thin-session eligibility.

This is a read-only audit.  It complements the retention audit by measuring
run-scoped APK payload pressure under ``data/device_apks`` and whether those
payloads can be represented as thin session evidence pointing at the canonical
SHA-256 store.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        "--root",
        dest="data_root",
        type=Path,
        default=None,
        help="Repository data root to audit; defaults to scytaledroid.Config app_config.DATA_DIR.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Directory for JSON/CSV reports; defaults to OUTPUT_DIR/audit/storage.",
    )
    parser.add_argument("--stamp", default=None, help="Stable timestamp label for output filenames.")
    parser.add_argument(
        "--verify-candidates",
        action="store_true",
        help="Hash candidate session and canonical APKs before marking files eligible_verified.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Also emit the full audit JSON to stdout.",
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Emit only the summary object to stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.DeviceAnalysis.services.storage_pressure import generate_storage_pressure_audit
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config. Storage-pressure audit needs the core DB read model.\n")
        return 2

    try:
        audit, json_path, csv_path = generate_storage_pressure_audit(
            root=args.data_root,
            out_dir=args.out_dir,
            stamp=args.stamp,
            core_q=core_q,
            verify_candidates=bool(args.verify_candidates),
        )
    except Exception as exc:
        sys.stderr.write(f"storage-pressure audit failed: {exc}\n")
        return 2

    if args.stdout_json:
        print(json.dumps(audit, indent=2, sort_keys=True, default=str))
    elif args.summary_json:
        print(json.dumps(audit.get("summary", {}), indent=2, sort_keys=True, default=str))
    else:
        summary = audit.get("summary", {})
        truths = audit.get("truths", {})
        identity = truths.get("identity_known_in_db", {}) if isinstance(truths, dict) else {}
        canonical = truths.get("canonical_bytes_available", {}) if isinstance(truths, dict) else {}
        session = truths.get("session_copy_bytes_present", {}) if isinstance(truths, dict) else {}
        historical = truths.get("historical_provenance_only", {}) if isinstance(truths, dict) else {}
        print(f"json: {json_path}")
        print(f"csv : {csv_path}")
        print(f"verify candidates: {bool(args.verify_candidates)}")
        print(f"DB APK artifact rows: {int(identity.get('apk_artifact_rows') or 0)}")
        print(f"DB packages: {int(identity.get('packages') or 0)}")
        print(f"canonical APK files: {int(canonical.get('canonical_files') or 0)}")
        print(f"canonical APK bytes: {int(canonical.get('canonical_bytes') or 0)}")
        print(f"session regular APK files: {int(session.get('session_regular_apk_files') or 0)}")
        print(f"session regular APK bytes: {int(session.get('session_regular_apk_bytes') or 0)}")
        print(f"eligible verified files: {int(summary.get('eligible_verified_files') or 0)}")
        print(f"eligible verified reclaimable bytes: {int(summary.get('eligible_verified_reclaimable_bytes') or 0)}")
        print(f"eligible unverified files: {int(summary.get('eligible_unverified_files') or 0)}")
        print(f"eligible reclaimable bytes: {int(summary.get('eligible_reclaimable_bytes') or 0)}")
        print(f"historical identity-only rows: {int(historical.get('rows') or 0)}")
        print(f"old-root blocked rows: {int(historical.get('old_root_blocked_rows') or 0)}")
        print(f"issues: {int(summary.get('issues') or 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
