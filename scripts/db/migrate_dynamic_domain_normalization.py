#!/usr/bin/env python3
"""Audit or apply versioned dynamic root-domain normalization."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_DEFAULT_RECEIPT_ROOT = (
    _REPO_ROOT / "data" / "state" / "schema_migrations" / "dynamic_domain_normalization"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt-root",
        type=Path,
        default=_DEFAULT_RECEIPT_ROOT,
        help=f"Receipt parent directory (default: {_DEFAULT_RECEIPT_ROOT}).",
    )
    parser.add_argument(
        "--write-bundle",
        action="store_true",
        help="Write the dry-run JSON and exact CSV worklist.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the additive schema and bounded row updates.",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required with --apply.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return parser


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _write_worklist(path: Path, candidates: list[Any]) -> None:
    fieldnames = [
        "observation_id",
        "dynamic_run_id",
        "package_name",
        "indicator_type",
        "observed_domain",
        "root_domain",
        "registrable_domain_psl",
        "normalization_key",
        "reference_sha256",
        "psl_boundary_differs",
        "needs_update",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for candidate in candidates:
            writer.writerow(candidate.as_dict())


def _new_receipt_dir(root: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    path = root / f"dynamic_domain_normalization_{stamp}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def _render_text(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# dynamic domain normalization",
        f"mode: {payload['mode']}",
        f"schema_version_after: {payload['schema_version_after']}",
        f"candidate_rows: {summary['candidate_rows']}",
        f"rows_needing_update: {summary['rows_needing_update']}",
        f"psl_boundary_difference_rows: {summary['psl_boundary_difference_rows']}",
        f"packages_affected: {summary['packages_affected']}",
        f"runs_affected: {summary['runs_affected']}",
    ]
    if payload.get("verification") is not None:
        lines.append(f"verification_ok: {payload['verification']['ok']}")
    if payload.get("receipt_dir"):
        lines.append(f"receipt_dir: {payload['receipt_dir']}")
    if payload["mode"] == "dry_run":
        lines.append("dry-run only: no schema or observation rows were changed")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.apply and not args.confirm:
        sys.stderr.write("--apply requires --confirm\n")
        return 2

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_core.session import database_session
        from scytaledroid.Database.db_utils.dynamic_domain_normalization import (
            SCHEMA_VERSION_AFTER,
            apply_candidate_updates,
            apply_dynamic_domain_normalization_schema,
            build_candidates,
            candidate_worklist_sha256,
            load_observation_rows,
            normalization_columns_available,
            summarize_candidates,
            verify_candidates,
        )
        from scytaledroid.Utils.domain_identity import registrable_domain_resolver_metadata
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        has_provenance_columns = normalization_columns_available(core_q.run_sql)
        before_rows = load_observation_rows(
            core_q.run_sql,
            include_provenance=has_provenance_columns,
        )
        candidates = build_candidates(before_rows)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"Preflight failed without DB writes: {exc}\n")
        return 2

    payload: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "apply" if args.apply else "dry_run",
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "resolver": registrable_domain_resolver_metadata(),
        "provenance_columns_present_before": has_provenance_columns,
        "summary": summarize_candidates(candidates),
        "worklist_sha256": candidate_worklist_sha256(candidates),
        "bounded_by": ["observation_id", "dynamic_run_id"],
        "verification": None,
        "receipt_dir": None,
    }

    receipt_dir: Path | None = None
    if args.write_bundle or args.apply:
        receipt_dir = _new_receipt_dir(args.receipt_root)
        payload["receipt_dir"] = str(receipt_dir.resolve())
        _write_worklist(receipt_dir / "worklist.csv", candidates)
        _write_json(receipt_dir / "preflight.json", payload)

    if args.apply:
        try:
            schema_applied = apply_dynamic_domain_normalization_schema(core_q.run_sql)
            with database_session() as db:
                with db.transaction():
                    locked_rows = load_observation_rows(
                        core_q.run_sql,
                        include_provenance=True,
                        for_update=True,
                    )
                    locked_candidates = build_candidates(locked_rows)
                    locked_worklist_sha256 = candidate_worklist_sha256(locked_candidates)
                    if locked_worklist_sha256 != payload["worklist_sha256"]:
                        raise RuntimeError(
                            "database observations changed after preflight; no row updates applied"
                        )
                    migrated_rows = apply_candidate_updates(
                        core_q.run_sql,
                        locked_candidates,
                    )
                    after_rows = load_observation_rows(
                        core_q.run_sql,
                        include_provenance=True,
                    )
                    verification = verify_candidates(after_rows, locked_candidates)
                    residual = summarize_candidates(build_candidates(after_rows))
                    verification["residual_rows_needing_update"] = residual["rows_needing_update"]
                    verification["worklist_sha256"] = locked_worklist_sha256
                    verification["ok"] = (
                        bool(verification["ok"]) and not residual["rows_needing_update"]
                    )
                    if not verification["ok"]:
                        raise RuntimeError(
                            "post-update verification failed; observation updates rolled back"
                        )
            payload["schema_applied"] = schema_applied
            payload["migrated_rows"] = migrated_rows
            payload["verification"] = verification
        except Exception as exc:  # noqa: BLE001
            payload["error"] = str(exc)
            if receipt_dir is not None:
                _write_json(receipt_dir / "result.json", payload)
            sys.stderr.write(f"Migration stopped: {exc}\n")
            return 2

    if receipt_dir is not None:
        _write_json(receipt_dir / "result.json", payload)

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    else:
        sys.stdout.write(_render_text(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
