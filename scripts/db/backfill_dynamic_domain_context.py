#!/usr/bin/env python3
"""Apply and backfill DB-backed dynamic domain context from local evidence packs."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_DEFAULT_RECEIPT_DIR = _REPO_ROOT / "data" / "state" / "schema_migrations" / "dynamic_domain_context"
_DEFAULT_EVIDENCE_ROOT = _REPO_ROOT / "output" / "evidence" / "dynamic"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=_DEFAULT_EVIDENCE_ROOT,
        help=f"Dynamic evidence-pack root (default: {_DEFAULT_EVIDENCE_ROOT}).",
    )
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=_DEFAULT_RECEIPT_DIR,
        help=f"Receipt directory (default: {_DEFAULT_RECEIPT_DIR}).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    parser.add_argument("--write-bundle", action="store_true", help="Write JSON receipt bundle.")
    parser.add_argument("--apply", action="store_true", help="Apply migration and DB writes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
        from scytaledroid.Database.db_utils.dynamic_domain_context import (
            COLLATION_HOTFIX_SCHEMA_VERSION_AFTER,
            apply_dynamic_domain_context_collation_hotfix,
            apply_dynamic_domain_context_migration,
            load_domain_reference_rows,
        )
        from scytaledroid.DynamicAnalysis.storage.domain_context_index import (
            index_dynamic_domain_context_from_evidence_packs,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    migration_payload: dict[str, object] = {}
    backfill_result: dict[str, object] = {"scanned": 0, "indexed_rows": 0, "errors": 0}
    if args.apply:
        try:
            with database_session() as db:
                with db.transaction():
                    migration_payload = apply_dynamic_domain_context_migration(core_q.run_sql)
                    hotfix_payload = apply_dynamic_domain_context_collation_hotfix(core_q.run_sql)
            backfill_result = index_dynamic_domain_context_from_evidence_packs(args.evidence_root)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Apply/backfill failed: {exc}\n")
            return 2
    else:
        try:
            references = load_domain_reference_rows(core_q.run_sql)
        except Exception:
            references = []
        migration_payload = {
            "generated_at": datetime.now(UTC).isoformat(),
            "dry_run": True,
            "schema_version_after": COLLATION_HOTFIX_SCHEMA_VERSION_AFTER,
            "reference_rows_visible": len(references),
        }
        hotfix_payload = {}

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "applied": bool(args.apply),
        "evidence_root": str(args.evidence_root.resolve()),
        "schema_version_after": hotfix_payload.get("schema_version_after") or migration_payload.get("schema_version_after"),
        "migration": migration_payload,
        "hotfix": hotfix_payload,
        "backfill": backfill_result,
    }

    receipt_path: str | None = None
    if args.write_bundle:
        args.receipt_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        receipt = args.receipt_dir / f"dynamic_domain_context_backfill_{stamp}.json"
        receipt.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        receipt_path = str(receipt.resolve())
        summary["receipt_json"] = receipt_path

    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# dynamic domain context")
    print(f"applied: {summary['applied']}")
    print(f"schema_version_after: {summary.get('schema_version_after')}")
    print(f"reference_rows: {migration_payload.get('reference_rows_after') or migration_payload.get('reference_rows_visible')}")
    print(f"runs_scanned: {backfill_result.get('scanned')}")
    print(f"observation_rows_indexed: {backfill_result.get('indexed_rows')}")
    print(f"errors: {backfill_result.get('errors')}")
    if receipt_path:
        print(f"receipt_json: {receipt_path}")
    if not args.apply:
        print("dry-run only (no DB writes). Re-run with --apply to create tables and backfill rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
