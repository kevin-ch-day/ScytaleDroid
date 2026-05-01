"""Freeze lifecycle helpers for canonical vs legacy freeze handling."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def inspect_canonical_freeze(*, archive_dir: Path, evidence_root: Path) -> dict[str, Any]:
    """Inspect canonical freeze state without mutating any files."""
    canonical_path = archive_dir / "dataset_freeze.json"
    out: dict[str, Any] = {
        "canonical_path": str(canonical_path),
        "canonical_exists": canonical_path.exists(),
        "freeze_role": "none",
        "paper_contract_hash_present": False,
        "included_run_ids_total": 0,
        "included_run_ids_present": 0,
        "included_run_ids_missing": 0,
        "noncanonical_reasons": [],
    }
    if not canonical_path.exists():
        return out

    payload = _read_json(canonical_path)
    if not isinstance(payload, dict):
        out["freeze_role"] = "invalid"
        out["noncanonical_reasons"] = ["INVALID_JSON"]
        return out

    role = str(payload.get("freeze_role") or "").strip().lower()
    out["freeze_role"] = role or "unspecified"
    contract_hash = str(payload.get("paper_contract_hash") or "").strip().lower()
    out["paper_contract_hash_present"] = bool(contract_hash)
    ids_raw = payload.get("included_run_ids")
    if not isinstance(ids_raw, list):
        out["noncanonical_reasons"] = ["MISSING_INCLUDED_RUN_IDS"]
        return out

    ids = {str(v).strip() for v in ids_raw if str(v).strip()}
    out["included_run_ids_total"] = len(ids)
    if not ids:
        out["noncanonical_reasons"] = ["EMPTY_INCLUDED_RUN_IDS"]
        return out

    available = {p.name for p in evidence_root.iterdir() if p.is_dir()} if evidence_root.exists() else set()
    present = ids.intersection(available)
    out["included_run_ids_present"] = len(present)
    out["included_run_ids_missing"] = len(ids) - len(present)

    reasons: list[str] = []
    if role != "canonical":
        reasons.append("FREEZE_ROLE_NOT_CANONICAL")
    if not contract_hash:
        reasons.append("MISSING_CONTRACT_HASH")
    if out["included_run_ids_missing"] > 0:
        reasons.append("MISSING_RUN_DIRS")
    out["noncanonical_reasons"] = reasons
    return out


def demote_noncanonical_canonical_freeze(
    *,
    archive_dir: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    """Auto-demote non-canonical dataset_freeze.json to legacy_freeze_*.json."""
    state = inspect_canonical_freeze(archive_dir=archive_dir, evidence_root=evidence_root)
    reasons = state.get("noncanonical_reasons")
    if not isinstance(reasons, list) or not reasons:
        return {"demoted": False, "state": state}
    canonical_path = archive_dir / "dataset_freeze.json"
    payload = _read_json(canonical_path) or {}
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    legacy_path = archive_dir / f"legacy_freeze_{stamp}.json"
    suffix = 1
    while legacy_path.exists():
        legacy_path = archive_dir / f"legacy_freeze_{stamp}_{suffix}.json"
        suffix += 1
    payload["freeze_role"] = "legacy"
    payload["legacy_demoted_at_utc"] = datetime.now(UTC).isoformat()
    payload["legacy_demotion_reasons"] = [str(r) for r in reasons]
    payload["legacy_source"] = "dataset_freeze.json"
    legacy_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    canonical_path.unlink(missing_ok=True)
    return {"demoted": True, "legacy_path": str(legacy_path), "state": state}


__all__ = ["inspect_canonical_freeze", "demote_noncanonical_canonical_freeze"]
