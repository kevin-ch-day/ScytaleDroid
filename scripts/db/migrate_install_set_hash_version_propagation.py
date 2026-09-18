#!/usr/bin/env python3
"""Audit or apply 0.3.17 install-set hash-version propagation.

Default is a read-only preflight. ``--apply --confirm`` is the official apply
path. MariaDB DDL is implicit-commit; the tool resumes from physical posture.
Historical dynamic rows stay version-unknown. Writers remain v1.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_DEFAULT_RECEIPT_ROOT = (
    _REPO_ROOT / "data" / "state" / "schema_migrations" / "install_set_hash_version_propagation"
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
        help="Write the dry-run JSON receipt even without --apply.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply missing DDL and the bounded static version backfill.",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required with --apply or --rehearse.",
    )
    parser.add_argument(
        "--rehearse",
        action="store_true",
        help="Apply against the current DSN only when it is not a production catalog.",
    )
    parser.add_argument(
        "--rehearse-offline",
        action="store_true",
        help="Run the isolated in-memory implicit-commit rehearsal and exit.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    return parser


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _new_receipt_dir(root: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    path = root / f"install_set_hash_version_propagation_{stamp}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def _render_text(payload: dict[str, Any]) -> str:
    static = payload.get("static") or {}
    dynamic = payload.get("dynamic") or {}
    verification = payload.get("verification") or {}
    lines = [
        "# install-set hash-version propagation",
        f"mode: {payload.get('mode')}",
        f"schema_version_after: {payload.get('schema_version_after')}",
        f"apply_supported: {payload.get('apply_supported')}",
        f"writer_mode: {payload.get('writer_mode')}",
        f"static_safe_candidates: {static.get('static_safe_candidates')}",
        f"static_conflicts: {static.get('static_conflicts')}",
        f"static_insufficient_proof: {static.get('static_insufficient_proof')}",
        f"dynamic_version_unknown_legacy: {dynamic.get('dynamic_version_unknown_legacy')}",
        f"dynamic_automatic_version_backfill: {dynamic.get('dynamic_automatic_version_backfill')}",
    ]
    if payload.get("apply_blocked_reason"):
        lines.append(f"apply_blocked_reason: {payload['apply_blocked_reason']}")
    if verification:
        lines.append(f"verification_ok: {verification.get('ok')}")
    if payload.get("receipt_dir"):
        lines.append(f"receipt_dir: {payload['receipt_dir']}")
    if payload.get("mode") == "dry_run":
        lines.append("dry-run only: no schema or identity rows were changed")
    return "\n".join(lines) + "\n"


def _offline_rehearsal_payload() -> dict[str, Any]:
    from scytaledroid.Database.db_utils.install_set_hash_version_propagation import (
        SCHEMA_VERSION_AFTER,
        IsolatedIdentityRehearsal,
        apply_install_set_hash_version_propagation,
        apply_missing_ddl,
        build_preflight,
    )

    store = IsolatedIdentityRehearsal(
        static_rows=[
            {
                "id": 1,
                "apk_set_id": 843,
                "artifact_set_hash": "a" * 64,
                "stored_artifact_set_hash_version": None,
                "linked_artifact_set_hash": "a" * 64,
                "linked_artifact_set_hash_version": "v1",
            },
            {
                "id": 2,
                "apk_set_id": None,
                "artifact_set_hash": "b" * 64,
                "stored_artifact_set_hash_version": None,
                "linked_artifact_set_hash": None,
                "linked_artifact_set_hash_version": None,
            },
        ],
        dynamic_rows=[
            {
                "dynamic_run_id": "dyn-1",
                "apk_set_id": 843,
                "artifact_set_hash": "a" * 64,
                "artifact_set_hash_version": None,
            }
        ],
    )
    preflight = build_preflight(store.run_sql, database_name="scytaledroid_core_rehearsal")
    try:
        apply_missing_ddl(store.run_sql, crash_after=1)
        interrupted = True
    except RuntimeError:
        interrupted = True
    resumed = apply_install_set_hash_version_propagation(
        store.run_sql,
        database_name="scytaledroid_core_rehearsal",
        allow_production=False,
    )
    return {
        "mode": "rehearse_offline",
        "apply_supported": True,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "writer_mode": resumed["writer_mode"],
        "interrupted_after_first_ddl": interrupted,
        "preflight": preflight,
        "static": resumed["static"],
        "dynamic": resumed["dynamic"],
        "verification": resumed["verification"],
        "ddl": resumed["ddl"],
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if (args.apply or args.rehearse) and not args.confirm:
        sys.stderr.write("--apply/--rehearse requires --confirm\n")
        return 2
    if args.apply and args.rehearse:
        sys.stderr.write("choose either --apply or --rehearse, not both\n")
        return 2

    if args.rehearse_offline:
        payload = _offline_rehearsal_payload()
        if args.json:
            sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        else:
            sys.stdout.write(_render_text(payload))
        return 0 if payload["verification"]["ok"] else 1

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.install_set_hash_version_propagation import (
            APPLY_SUPPORTED,
            SCHEMA_VERSION_AFTER,
            WRITER_MODE,
            apply_install_set_hash_version_propagation,
            build_preflight,
            is_production_database,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    database_name = str(db_config.DB_CONFIG.get("database") or "").strip() or None
    try:
        payload = build_preflight(core_q.run_sql, database_name=database_name)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"Preflight failed without DB writes: {exc}\n")
        return 2

    payload["generated_at"] = datetime.now(UTC).isoformat()
    payload["mode"] = "dry_run"
    payload["apply_supported"] = APPLY_SUPPORTED
    payload["writer_mode"] = WRITER_MODE
    payload["schema_version_after"] = SCHEMA_VERSION_AFTER
    payload["verification"] = None
    payload["receipt_dir"] = None

    receipt_dir: Path | None = None
    if args.write_bundle or args.apply or args.rehearse:
        receipt_dir = _new_receipt_dir(args.receipt_root)
        payload["receipt_dir"] = str(receipt_dir.resolve())
        _write_json(receipt_dir / "preflight.json", payload)

    if args.apply or args.rehearse:
        if args.rehearse and is_production_database(database_name):
            sys.stderr.write("refusing --rehearse against a production catalog\n")
            return 2
        if payload.get("apply_blocked_reason"):
            sys.stderr.write(f"apply blocked: {payload['apply_blocked_reason']}\n")
            if receipt_dir is not None:
                _write_json(receipt_dir / "result.json", payload)
            return 2
        try:
            applied = apply_install_set_hash_version_propagation(
                core_q.run_sql,
                database_name=database_name,
                receipt_path=str(receipt_dir / "result.json") if receipt_dir else None,
                allow_production=bool(args.apply),
            )
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"Apply failed: {exc}\n")
            return 1
        payload.update(applied)
        if receipt_dir is not None:
            _write_json(receipt_dir / "result.json", payload)
        if not (payload.get("verification") or {}).get("ok"):
            return 1

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    else:
        sys.stdout.write(_render_text(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
