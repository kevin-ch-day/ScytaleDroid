"""Read-only reconciliation helpers for Paper 3 cohort authority decisions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def split_run_ids(value: object) -> list[str]:
    """Normalize the comma-separated selected-run representation used by freezes."""

    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def _manifest_run_record(run_id: str, evidence_root: Path) -> dict[str, Any]:
    manifest_path = evidence_root / run_id / "run_manifest.json"
    if not manifest_path.is_file():
        return {"dynamic_run_id": run_id, "artifact_status": "missing_run_manifest"}

    manifest = _read_json(manifest_path)
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    identity = target.get("run_identity") if isinstance(target.get("run_identity"), Mapping) else {}
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
    return {
        "dynamic_run_id": run_id,
        "artifact_status": "present",
        "package_name": str(target.get("package_name") or ""),
        "version_code": str(target.get("version_code") or identity.get("version_code") or ""),
        "version_name": str(target.get("version_name") or ""),
        "static_run_id": str(identity.get("static_run_id") or target.get("static_run_id") or ""),
        "base_apk_sha256": str(identity.get("base_apk_sha256") or ""),
        "run_profile": str(operator.get("run_profile") or target.get("run_intent") or ""),
        "valid_dataset_run": dataset.get("valid_dataset_run"),
        "paper_eligible": dataset.get("paper_eligible"),
        "paper_exclusion_reason": str(dataset.get("paper_exclusion_primary_reason_code") or ""),
        "identity_valid": identity.get("identity_valid"),
        "pcap_available": dataset.get("pcap_available"),
    }


def build_paper3_authority_audit(
    *,
    alignment_manifest_path: Path | str,
    freeze_manifest_path: Path | str,
    evidence_root: Path | str,
) -> dict[str, Any]:
    """Compare a historical alignment cohort to a later freeze without mutation."""

    alignment_path = Path(alignment_manifest_path)
    freeze_path = Path(freeze_manifest_path)
    root = Path(evidence_root)
    alignment = _read_json(alignment_path)
    freeze = _read_json(freeze_path)

    historical_ids = set(split_run_ids(alignment.get("selected_dynamic_run_ids")))
    freeze_ids: set[str] = set()
    for app in freeze.get("apps") or []:
        if isinstance(app, Mapping):
            freeze_ids.update(split_run_ids(app.get("selected_dynamic_run_ids")))

    rows: list[dict[str, Any]] = []
    for run_id in sorted(historical_ids | freeze_ids):
        row = _manifest_run_record(run_id, root)
        row["in_historical_alignment"] = run_id in historical_ids
        row["in_candidate_freeze"] = run_id in freeze_ids
        if run_id in historical_ids and run_id in freeze_ids:
            row["membership"] = "shared"
        elif run_id in historical_ids:
            row["membership"] = "historical_only"
        else:
            row["membership"] = "candidate_only"
        rows.append(row)

    historical_selected_ineligible = [
        row
        for row in rows
        if row["in_historical_alignment"] and row.get("paper_eligible") is False
    ]
    candidate_selected_ineligible = [
        row
        for row in rows
        if row["in_candidate_freeze"] and row.get("paper_eligible") is False
    ]
    return {
        "schema_version": 1,
        "read_only": True,
        "alignment_manifest": str(alignment_path),
        "freeze_manifest": str(freeze_path),
        "evidence_root": str(root),
        "summary": {
            "historical_selected_runs": len(historical_ids),
            "candidate_selected_runs": len(freeze_ids),
            "shared_runs": len(historical_ids & freeze_ids),
            "historical_only_runs": len(historical_ids - freeze_ids),
            "candidate_only_runs": len(freeze_ids - historical_ids),
            "historical_explicitly_paper_ineligible_runs": len(historical_selected_ineligible),
            "candidate_explicitly_paper_ineligible_runs": len(candidate_selected_ineligible),
            "candidate_declared_paper_excluded_runs": int(
                (freeze.get("summary") or {}).get("explicitly_paper_excluded_runs") or 0
            ),
        },
        "candidate_selection_contract": freeze.get("selection_contract"),
        "historical_explicitly_paper_ineligible": historical_selected_ineligible,
        "candidate_explicitly_paper_ineligible": candidate_selected_ineligible,
        "runs": rows,
    }


__all__ = ["build_paper3_authority_audit", "split_run_ids"]
