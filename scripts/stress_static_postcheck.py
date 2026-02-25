#!/usr/bin/env python3
"""
Static batch stress post-check (freeze-anchored research profile).

This script does NOT run scans. It validates that a completed static batch run
produced the expected artifacts and left the DB in a sane state.

Usage:
  scripts/stress_static_postcheck.py output/batches/static/<batch>.json
  scripts/stress_static_postcheck.py --latest
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Ensure imports work when running as a script from the repo root.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@dataclass(frozen=True)
class CheckFailure:
    code: str
    detail: str


REQUIRED_PLAN_KEYS = {
    "plan_schema_version",
    "schema_version",
    "generated_at",
    "run_identity",
    "network_targets",
    "permissions",
    "exported_components",
    "risk_flags",
}

REQUIRED_NETWORK_TARGET_KEYS = {
    "domains",
    "cleartext_domains",
    "domain_sources",
    "domain_sources_note",
}

REQUIRED_RUN_IDENTITY_KEYS = {
    "run_signature_version",
    "run_signature",
    "artifact_set_hash",
    "base_apk_sha256",
    "identity_valid",
    "identity_error_reason",
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _latest_batch_summary() -> Path | None:
    root = Path("output/batches/static")
    if not root.exists():
        return None
    candidates = sorted(root.glob("static-batch-*.json"))
    return candidates[-1] if candidates else None


def _check_db_no_open_static_runs() -> list[CheckFailure]:
    failures: list[CheckFailure] = []
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        return [CheckFailure("DB_IMPORT_FAILED", str(exc))]
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM static_analysis_runs WHERE status='RUNNING' AND ended_at_utc IS NULL",
            (),
            fetch="one",
        )
        open_count = int(row[0] if row and row[0] is not None else 0)
        if open_count != 0:
            failures.append(CheckFailure("DB_OPEN_STATIC_RUNS", f"open_runs={open_count}"))
    except Exception as exc:
        failures.append(CheckFailure("DB_QUERY_FAILED", str(exc)))
    return failures


def _check_batch_summary(path: Path) -> tuple[list[CheckFailure], dict[str, Any]]:
    failures: list[CheckFailure] = []
    payload = _load_json(path)
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return [CheckFailure("BATCH_SCHEMA", "missing rows[]")], payload

    apps_total = payload.get("apps_total")
    apps_completed = payload.get("apps_completed")
    apps_failed = payload.get("apps_failed")

    if isinstance(apps_total, int) and len(rows) != apps_completed:
        failures.append(
            CheckFailure(
                "BATCH_ROWCOUNT_MISMATCH",
                f"rows={len(rows)} apps_completed={apps_completed} apps_total={apps_total}",
            )
        )
    if isinstance(apps_failed, int) and apps_failed != 0:
        failures.append(CheckFailure("BATCH_HAS_FAILURES", f"apps_failed={apps_failed}"))

    # Per-row checks: status, paper_grade, plan + evidence paths.
    for row in rows:
        if not isinstance(row, dict):
            failures.append(CheckFailure("BATCH_ROW_SCHEMA", "non-dict row"))
            continue

        pkg = str(row.get("package_name") or "")
        label = str(row.get("selection_label") or pkg or "<unknown>")
        status = str(row.get("status") or "")
        paper_grade = str(row.get("paper_grade") or "")
        evidence_path = row.get("evidence_path")
        plan_path = row.get("plan_path")

        if status != "ok":
            failures.append(CheckFailure("APP_STATUS_NOT_OK", f"{label} status={status}"))
        if paper_grade != "ok":
            failures.append(CheckFailure("APP_NOT_PAPER_GRADE", f"{label} paper_grade={paper_grade}"))

        if isinstance(evidence_path, str) and evidence_path:
            ev = Path(evidence_path)
            if not ev.exists():
                failures.append(CheckFailure("EVIDENCE_MISSING", f"{label} evidence_path={evidence_path}"))
            else:
                # Minimum evidence file we rely on for audit trails.
                manifest_evidence = ev / "manifest_evidence.json"
                if not manifest_evidence.exists():
                    failures.append(
                        CheckFailure("MANIFEST_EVIDENCE_MISSING", f"{label} {manifest_evidence}")
                    )

        if not isinstance(plan_path, (str, Path)) or not str(plan_path):
            failures.append(CheckFailure("PLAN_PATH_MISSING", f"{label} plan_path=missing"))
            continue

        plan = Path(str(plan_path))
        if not plan.exists():
            failures.append(CheckFailure("PLAN_FILE_MISSING", f"{label} plan_path={plan}"))
            continue

        # Plan schema invariants: these are contract keys for static->dynamic.
        try:
            plan_payload = _load_json(plan)
        except Exception as exc:
            failures.append(CheckFailure("PLAN_JSON_INVALID", f"{label} error={exc}"))
            continue

        missing = sorted(k for k in REQUIRED_PLAN_KEYS if k not in plan_payload)
        if missing:
            failures.append(CheckFailure("PLAN_SCHEMA_MISSING_KEYS", f"{label} missing={missing}"))

        nt = plan_payload.get("network_targets")
        if isinstance(nt, dict):
            missing_nt = sorted(k for k in REQUIRED_NETWORK_TARGET_KEYS if k not in nt)
            if missing_nt:
                failures.append(CheckFailure("PLAN_NETWORK_TARGETS_KEYS", f"{label} missing={missing_nt}"))
        else:
            failures.append(CheckFailure("PLAN_NETWORK_TARGETS_SCHEMA", f"{label} network_targets not dict"))

        ri = plan_payload.get("run_identity")
        if isinstance(ri, dict):
            missing_ri = sorted(k for k in REQUIRED_RUN_IDENTITY_KEYS if k not in ri)
            if missing_ri:
                failures.append(CheckFailure("PLAN_RUN_IDENTITY_KEYS", f"{label} missing={missing_ri}"))
            identity_valid = ri.get("identity_valid")
            if identity_valid is False:
                failures.append(CheckFailure("PLAN_IDENTITY_INVALID", f"{label} identity_valid=false"))
        else:
            failures.append(CheckFailure("PLAN_RUN_IDENTITY_SCHEMA", f"{label} run_identity not dict"))

    return failures, payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("batch_summary", nargs="?", help="Path to output/batches/static/static-batch-*.json")
    ap.add_argument("--latest", action="store_true", help="Use latest batch summary under output/batches/static/")
    args = ap.parse_args()

    path = None
    if args.latest:
        path = _latest_batch_summary()
        if not path:
            print("[ERROR] No batch summaries found under output/batches/static/.", file=sys.stderr)
            return 2
    else:
        if not args.batch_summary:
            ap.print_help()
            return 2
        path = Path(args.batch_summary)

    if not path.exists():
        print(f"[ERROR] Batch summary not found: {path}", file=sys.stderr)
        return 2

    failures, payload = _check_batch_summary(path)
    failures.extend(_check_db_no_open_static_runs())

    print(f"[OK] batch_summary={path}")
    print(
        f"[OK] apps_total={payload.get('apps_total')} apps_completed={payload.get('apps_completed')} "
        f"apps_failed={payload.get('apps_failed')}"
    )

    if failures:
        print(f"[ERROR] failures={len(failures)}")
        for f in failures[:30]:
            print(f"  - {f.code}: {f.detail}")
        if len(failures) > 30:
            print(f"  ... ({len(failures) - 30} more)")
        return 1

    print("[OK] Post-check passed (artifacts + DB sanity).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
