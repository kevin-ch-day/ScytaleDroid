#!/usr/bin/env python3
"""Apply Phase A additive typed replacement columns and conservative backfill."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "state" / "schema_migrations",
        help="Write before/after receipt JSON here.",
    )
    parser.add_argument("--apply", action="store_true", help="Run DDL/backfill. Default is dry-run summary only.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.phase_a_typed_replacements import (
            backfill_typed_replacement_columns,
            write_phase_a_backfill_receipt,
        )
        from scytaledroid.Database.db_utils.schema_migration_registry import (
            attach_receipt_path_to_latest_migration,
            registered_migrations,
        )
        from scytaledroid.Database.db_utils.type_normalization_preflight import (
            collect_type_normalization_preflight,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    before = collect_type_normalization_preflight(core_q.run_sql)
    payload = {
        "mode": "apply" if args.apply else "dry_run",
        "generated_at": datetime.now(UTC).isoformat(),
        "before": before.get("summary") or {},
    }
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"phase_a_typed_replacements_{stamp}"

    if args.apply:
        result = backfill_typed_replacement_columns(core_q.run_sql, core_q.run_sql_rowcount)
        after = collect_type_normalization_preflight(core_q.run_sql)
        payload["apply_result"] = {
            "ddl_applied": result.ddl_applied,
            "artifact_registry_dynamic_run_uuid_backfilled": result.artifact_registry_dynamic_run_uuid_backfilled,
            "dynamic_sessions_static_run_id_u_backfilled": result.dynamic_sessions_static_run_id_u_backfilled,
            "static_analysis_runs_run_started_at_utc_backfilled": result.static_analysis_runs_run_started_at_utc_backfilled,
            "latest_schema_version_after": result.latest_schema_version_after,
        }
        payload["after"] = after.get("summary") or {}

    receipt = write_phase_a_backfill_receipt(args.receipt_dir, stem=stem, payload=payload)
    payload["receipt_path"] = receipt
    if args.apply:
        for spec in registered_migrations()[1:3]:
            attach_receipt_path_to_latest_migration(
                core_q.run_sql,
                migration_id=spec.migration_id,
                receipt_path=receipt,
            )

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0
    print("# phase-a typed replacements")
    print(f"mode: {payload['mode']}")
    print(f"preflight_clean: {payload['before'].get('preflight_clean')}")
    print(f"receipt_path: {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
