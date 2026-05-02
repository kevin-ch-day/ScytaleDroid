"""Stable dataset identity hash for freeze manifests (Paper #2).

Problem:
- The SHA256 of the *freeze JSON file* is not stable across machines/reruns because
  it includes runtime metadata (timestamps, git commit, etc.).

Solution:
- Define a canonical "dataset identity payload" derived from the freeze manifest,
  excluding volatile metadata, and hash that instead.

This hash is intended to be:
- cross-machine reproducible
- a paper citation anchor
- an ML artifact anchor
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FREEZE_DATASET_IDENTITY_VERSION = 1
FREEZE_DATASET_HASH_ALGORITHM = "sha256"


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _canonical_identity_payload(freeze: dict[str, Any]) -> dict[str, Any]:
    """Return a stable subset of freeze fields used to compute dataset identity.

    Excludes volatile fields such as created_at_utc, tool_git_commit, host tool versions, etc.
    """
    included = freeze.get("included_run_ids") or []
    if not isinstance(included, list):
        included = []
    included_run_ids = sorted(str(x).strip() for x in included if str(x).strip())
    checksums = freeze.get("included_run_checksums")
    if not isinstance(checksums, dict):
        checksums = {}

    return {
        "dataset_identity_version": int(FREEZE_DATASET_IDENTITY_VERSION),
        "dataset_id": freeze.get("dataset_id"),
        "dataset_version": freeze.get("dataset_version"),
        "freeze_contract_version": freeze.get("freeze_contract_version"),
        "paper_contract_version": freeze.get("paper_contract_version"),
        "paper_mode_contract_version": freeze.get("paper_mode_contract_version"),
        "paper_contract_hash": freeze.get("paper_contract_hash"),
        "capture_policy_version_required": freeze.get("capture_policy_version_required"),
        "reason_taxonomy_version": freeze.get("reason_taxonomy_version"),
        "plan_schema_version_required": freeze.get("plan_schema_version_required"),
        "plan_paper_contract_version_required": freeze.get("plan_paper_contract_version_required"),
        "quota_policy": freeze.get("quota_policy"),
        "qa_thresholds": freeze.get("qa_thresholds"),
        "included_run_ids": included_run_ids,
        "included_run_checksums": checksums,
    }


def compute_freeze_dataset_hash_from_payload(freeze: dict[str, Any]) -> str:
    canonical = _canonical_identity_payload(freeze)
    material = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def compute_freeze_dataset_hash_from_path(freeze_path: Path) -> str:
    freeze = _read_json(freeze_path)
    if not isinstance(freeze, dict):
        raise RuntimeError(f"Invalid freeze JSON: {freeze_path}")
    return compute_freeze_dataset_hash_from_payload(freeze)


@dataclass(frozen=True)
class FreezeDatasetIdentity:
    version: int
    algorithm: str
    hash: str
    canonical_payload: dict[str, Any]


def derive_freeze_dataset_identity(freeze: dict[str, Any]) -> FreezeDatasetIdentity:
    canonical = _canonical_identity_payload(freeze)
    material = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return FreezeDatasetIdentity(
        version=int(FREEZE_DATASET_IDENTITY_VERSION),
        algorithm=str(FREEZE_DATASET_HASH_ALGORITHM),
        hash=str(digest),
        canonical_payload=canonical,
    )


__all__ = [
    "FREEZE_DATASET_IDENTITY_VERSION",
    "FREEZE_DATASET_HASH_ALGORITHM",
    "FreezeDatasetIdentity",
    "compute_freeze_dataset_hash_from_payload",
    "compute_freeze_dataset_hash_from_path",
    "derive_freeze_dataset_identity",
]

