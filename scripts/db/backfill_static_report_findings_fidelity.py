#!/usr/bin/env python3
"""Backfill missing ``metadata.findings_fidelity`` on archived static report JSON.

Default mode is dry-run: inspect one static session archive, report JSON files
missing the package-level findings-fidelity block, and show what would be
backfilled. Pass ``--apply`` to rewrite only those archived JSON files.

This script is intentionally bounded:
- no DB writes
- no schema changes
- no detector/persistence recomputation
- archive-session JSON only (does not touch ``reports/latest``)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

def _default_receipt_dir() -> Path:
    return _REPO_ROOT / "data" / "state" / "static_report_findings_fidelity_backfill"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session",
        "--session-stamp",
        dest="session_stamp",
        default=None,
        help="Static session stamp. Defaults to newest run-health file.",
    )
    parser.add_argument("--apply", action="store_true", help="Rewrite missing archived report JSON in place.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=None,
        help="Receipt directory for apply mode. Defaults to data/state/static_report_findings_fidelity_backfill.",
    )
    return parser


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _package_key(value: Any) -> str | None:
    text = _norm_text_or_none(value)
    return text.lower() if text else None


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _run_health_dir(data_dir: Path) -> Path:
    return data_dir / "store" / "apk"


def _reports_archive_root(data_dir: Path) -> Path:
    return data_dir / "static_analysis" / "reports" / "archive"


def _latest_run_health_session(data_dir: Path) -> str | None:
    candidates = sorted(_run_health_dir(data_dir).glob("*_run_health.json"))
    if not candidates:
        return None
    latest = max(candidates, key=lambda p: (p.stat().st_mtime, p.name))
    return latest.name.removesuffix("_run_health.json")


def _resolve_session_stamp(data_dir: Path, requested: str | None) -> str | None:
    token = _norm_text_or_none(requested)
    if token:
        return token
    return _latest_run_health_session(data_dir)


def _load_run_health(data_dir: Path, session_stamp: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    path = _run_health_dir(data_dir) / f"{session_stamp}_run_health.json"
    payload = _read_json(path) or {}
    package_rows: dict[str, dict[str, Any]] = {}
    for app in payload.get("apps") or []:
        if not isinstance(app, Mapping):
            continue
        package_name = _package_key(app.get("package_name"))
        if not package_name:
            continue
        persistence = app.get("finding_persistence")
        persistence_map = persistence if isinstance(persistence, Mapping) else {}
        package_rows[package_name] = {
            "display_name": _norm_text_or_none(app.get("app_label") or app.get("package_name")),
            "runtime_findings": _safe_int(persistence_map.get("runtime_findings")),
            "persisted_findings_db": _safe_int(persistence_map.get("persisted_findings_db")),
            "capped_not_persisted": _safe_int(persistence_map.get("capped_not_persisted")),
            "capped_by_detector": {
                str(key): int(value or 0)
                for key, value in (persistence_map.get("capped_by_detector") or {}).items()
            }
            if isinstance(persistence_map.get("capped_by_detector"), Mapping)
            else {},
        }
    return payload, package_rows


def _load_optional_db(session_stamp: str) -> tuple[dict[str, Any], list[str]]:
    from scripts.db import report_static_findings_fidelity_audit as fidelity_audit

    return fidelity_audit._load_optional_db(session_stamp)  # type: ignore[attr-defined]


def _build_findings_fidelity_metadata(
    *,
    package_name: str,
    run_health_row: Mapping[str, Any] | None,
    db_row: Mapping[str, Any] | None,
    db_package_severity: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    rh = run_health_row if isinstance(run_health_row, Mapping) else {}
    db = db_row if isinstance(db_row, Mapping) else {}
    sev = db_package_severity if isinstance(db_package_severity, Mapping) else {}

    runtime = _safe_int(rh.get("runtime_findings"))
    persisted = _safe_int(rh.get("persisted_findings_db"))
    capped = _safe_int(rh.get("capped_not_persisted"))

    if runtime is None:
        runtime = _safe_int(db.get("findings_runtime_total"))
    if persisted is None:
        persisted = _safe_int(db.get("persisted_findings_db"))
    if capped is None:
        capped = _safe_int(db.get("findings_capped_total"))
    if capped is None and runtime is not None and persisted is not None:
        capped = max(runtime - persisted, 0)

    if runtime is None and persisted is None and capped is None:
        return None

    runtime = int(runtime or 0)
    persisted = int(persisted or 0)
    capped = int(capped or 0)

    fidelity_ratio = round(persisted / runtime, 6) if runtime > 0 else None
    capped_ratio = round(capped / runtime, 6) if runtime > 0 else None

    persisted_p0 = _safe_int(sev.get("P0")) if isinstance(sev, Mapping) else None
    runtime_p0: int | None = None
    capped_p0: int | None = None
    notes: list[str] = [
        "Backfilled findings_fidelity metadata after the archived report was persisted without that block.",
    ]
    if persisted_p0 is not None and capped <= 0:
        runtime_p0 = int(persisted_p0)
        capped_p0 = 0
        notes.append("P0 counts inferred from canonical DB because run-health package rows do not carry per-severity runtime counters.")
    elif persisted_p0 is not None:
        notes.append("Persisted P0 counts came from canonical DB; runtime/capped P0 counts were not provable from current package-level sources.")

    if capped > 0:
        notes.append(
            "Canonical DB finding rows are incomplete for this package because per-detector caps fired during persistence."
        )

    return {
        "finding_fidelity_status": "complete" if runtime <= 0 or capped <= 0 else "capped",
        "runtime_findings": runtime,
        "persisted_db_findings": persisted,
        "capped_not_persisted": capped,
        "fidelity_ratio": fidelity_ratio,
        "capped_ratio": capped_ratio,
        "canonical_db_complete": capped <= 0,
        "artifact_runtime_evidence_complete": True,
        "cap_policy_applied": capped > 0,
        "cap_policy_basis": "detector_count",
        "cap_policy_detector_aware": True,
        "cap_policy_severity_aware": False,
        "cap_metadata_grain": "package",
        "per_finding_persistence_status_available": False,
        "runtime_p0_findings": runtime_p0,
        "persisted_db_p0_findings": int(persisted_p0) if persisted_p0 is not None else None,
        "capped_p0_findings": capped_p0,
        "notes": notes,
        "backfill_package_name": package_name,
    }


def _package_name_from_payload(payload: Mapping[str, Any]) -> str | None:
    manifest = payload.get("manifest")
    metadata = payload.get("metadata")
    manifest_map = manifest if isinstance(manifest, Mapping) else {}
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    return _package_key(
        manifest_map.get("package_name")
        or metadata_map.get("package_name")
        or metadata_map.get("normalized_package_name")
    )


def _collect_missing_reports(
    *,
    archive_dir: Path,
    run_health_rows: Mapping[str, dict[str, Any]],
    db_state: Mapping[str, Any],
) -> list[dict[str, Any]]:
    run_rows = db_state.get("run_rows") if isinstance(db_state.get("run_rows"), Mapping) else {}
    severity_rows = (
        db_state.get("package_persisted_by_severity")
        if isinstance(db_state.get("package_persisted_by_severity"), Mapping)
        else {}
    )

    results: list[dict[str, Any]] = []
    for path in sorted(archive_dir.glob("*.json")):
        payload = _read_json(path)
        if not isinstance(payload, Mapping):
            continue
        metadata = payload.get("metadata")
        metadata_map = metadata if isinstance(metadata, Mapping) else {}
        if isinstance(metadata_map.get("findings_fidelity"), Mapping):
            continue
        package_name = _package_name_from_payload(payload)
        if not package_name:
            continue
        metadata_block = _build_findings_fidelity_metadata(
            package_name=package_name,
            run_health_row=run_health_rows.get(package_name),
            db_row=run_rows.get(package_name) if isinstance(run_rows, Mapping) else None,
            db_package_severity=severity_rows.get(package_name) if isinstance(severity_rows, Mapping) else None,
        )
        results.append(
            {
                "path": path,
                "package_name": package_name,
                "display_package_name": _norm_text_or_none(
                    (payload.get("manifest") or {}).get("package_name")
                    if isinstance(payload.get("manifest"), Mapping)
                    else None
                )
                or package_name,
                "metadata": metadata_block,
                "generated_at": payload.get("generated_at"),
                "is_split_member": bool(metadata_map.get("is_split_member")),
            }
        )
    return results


def _write_receipt(
    *,
    receipt_dir: Path,
    payload: Mapping[str, Any],
) -> Path:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    receipt = receipt_dir / f"static_report_findings_fidelity_backfill_{stamp}.json"
    receipt.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return receipt


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    data_dir = _REPO_ROOT / "data"
    session_stamp = _resolve_session_stamp(data_dir, args.session_stamp)
    if not session_stamp:
        sys.stderr.write("No static session could be resolved from data/store/apk or the requested --session.\n")
        return 1

    archive_dir = _reports_archive_root(data_dir) / session_stamp
    if not archive_dir.exists():
        sys.stderr.write(f"Static reports archive missing for session {session_stamp}: {archive_dir}\n")
        return 1

    _, run_health_rows = _load_run_health(data_dir, session_stamp)
    try:
        db_state, db_notes = _load_optional_db(session_stamp)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"DB helper load failed: {exc}\n")
        return 2

    missing = _collect_missing_reports(
        archive_dir=archive_dir,
        run_health_rows=run_health_rows,
        db_state=db_state,
    )

    updated_paths: list[str] = []
    if args.apply:
        for row in missing:
            metadata = row.get("metadata")
            if not isinstance(metadata, Mapping):
                continue
            payload = _read_json(Path(row["path"]))
            if not isinstance(payload, Mapping):
                continue
            new_payload = dict(payload)
            meta = dict(new_payload.get("metadata") or {})
            meta["findings_fidelity"] = dict(metadata)
            new_payload["metadata"] = meta
            _write_json(Path(row["path"]), new_payload)
            updated_paths.append(str(Path(row["path"]).resolve()))

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "session_stamp": session_stamp,
        "archive_dir": str(archive_dir.resolve()),
        "applied": bool(args.apply),
        "missing_report_count": len(missing),
        "updated_report_count": len(updated_paths),
        "db_notes": list(db_notes),
        "targets": [
            {
                "package_name": str(row.get("package_name") or ""),
                "display_package_name": str(row.get("display_package_name") or ""),
                "path": str(Path(row["path"]).resolve()),
                "is_split_member": bool(row.get("is_split_member")),
                "generated_at": row.get("generated_at"),
            }
            for row in missing
        ],
        "updated_paths": updated_paths,
        "scope": "archive_session_json_only",
        "no_db_writes": True,
    }

    if args.apply:
        receipt_dir = args.receipt_dir or _default_receipt_dir()
        receipt = _write_receipt(receipt_dir=receipt_dir, payload=summary)
        summary["receipt_json"] = str(receipt.resolve())

    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print(f"session: {session_stamp}")
    print(f"archive_dir: {archive_dir}")
    print(f"missing reports: {len(missing)}")
    print(f"applied: {bool(args.apply)}")
    if updated_paths:
        print(f"updated reports: {len(updated_paths)}")
    for row in missing[:20]:
        print(f"- {_norm_text(row.get('display_package_name') or row.get('package_name'))} :: {Path(row['path']).name}")
    if args.apply and summary.get("receipt_json"):
        print(f"receipt_json: {summary['receipt_json']}")
    if not args.apply:
        print("dry-run only (no writes). Re-run with --apply to backfill missing archive metadata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
