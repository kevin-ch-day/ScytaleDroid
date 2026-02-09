"""Selector models + selection manifest writer (Phase F1).

Contract:
- Evidence packs are authoritative.
- DB may be used for candidate discovery only.
- Manifest output must be deterministic (stable ordering + SHA).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_operational as operational_config
from scytaledroid.DynamicAnalysis.ml.anomaly_model_training import fixed_model_specs
from scytaledroid.Utils.toolchain_versions import gather_toolchain_versions


SelectorType = Literal["freeze", "query"]
RunMode = Literal["baseline", "interactive", "unknown"]


@dataclass(frozen=True)
class QueryParams:
    """Query selector parameters (serialized into selection manifest)."""

    tier: str | None = "dataset"
    package_name: str | None = None
    base_apk_sha256: str | None = None
    mode: RunMode | None = None
    started_at_utc_from: str | None = None
    started_at_utc_to: str | None = None
    ended_at_utc_from: str | None = None
    ended_at_utc_to: str | None = None
    include_unknown_mode: bool = True
    pool_versions: bool = False
    require_valid_dataset_run: bool = True


@dataclass(frozen=True)
class RunRef:
    run_id: str
    evidence_dir: Path
    manifest_path: Path
    manifest_sha256: str
    package_name: str | None
    base_apk_sha256: str | None
    mode: RunMode
    mode_source: str
    run_profile: str | None
    started_at_utc: str | None
    ended_at_utc: str | None


@dataclass(frozen=True)
class SelectionResult:
    selector_type: SelectorType
    query_params: dict[str, Any] | None
    grouping_key: str
    pool_versions: bool
    included: list[RunRef]
    excluded: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class SelectionManifest:
    """Serialized selection manifest payload (written to JSON)."""

    payload: dict[str, Any]
    sha256: str


def _git_commit_hash(repo_root: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None


def _repo_root() -> Path:
    # repo_root/scytaledroid/DynamicAnalysis/ml/selectors/models.py -> parents[5] is repo root
    return Path(__file__).resolve().parents[5]

def _cfg_for_selector(selector_type: SelectorType):
    # Freeze selector fingerprints Paper #2 config; query selector fingerprints operational config.
    return operational_config if selector_type == "query" else paper_config


def _config_fingerprint(selector_type: SelectorType) -> dict[str, Any]:
    # Use a fixed seed for fingerprinting spec templates (not app-specific seeds).
    ml_config = _cfg_for_selector(selector_type)
    specs = fixed_model_specs(seed=0)
    spec_rows = [{"name": s.name, "params": dict(s.params)} for s in specs]
    return {
        "ml_schema_version": int(ml_config.ML_SCHEMA_VERSION),
        "window_size_s": float(ml_config.WINDOW_SIZE_S),
        "window_stride_s": float(ml_config.WINDOW_STRIDE_S),
        "threshold_percentile": float(ml_config.THRESHOLD_PERCENTILE),
        "np_percentile_method": str(ml_config.NP_PERCENTILE_METHOD),
        "feature_log1p": bool(ml_config.FEATURE_LOG1P),
        "feature_robust_scale": bool(ml_config.FEATURE_ROBUST_SCALE),
        "model_specs_seed0": spec_rows,
    }


def _config_fingerprint_sha256(selector_type: SelectorType) -> str:
    blob = json.dumps(_config_fingerprint(selector_type), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return sha256(blob).hexdigest()


def write_selection_manifest(path: Path, *, result: SelectionResult) -> SelectionManifest:
    """Write a deterministic selection manifest and return (payload, sha)."""

    created_at = datetime.now(UTC).isoformat()
    repo_root = _repo_root()
    tool_version = _git_commit_hash(repo_root)
    toolchain = gather_toolchain_versions()
    cfg_fp = _config_fingerprint_sha256(result.selector_type)

    included_run_ids = [r.run_id for r in result.included]
    per_run_meta: dict[str, Any] = {}
    for r in result.included:
        per_run_meta[r.run_id] = {
            "mode": r.mode,
            "mode_source": r.mode_source,
            "package_name": r.package_name,
            "base_apk_sha256": r.base_apk_sha256,
            "run_profile": r.run_profile,
            "evidence_pack_path": str(r.evidence_dir),
            "manifest_relpath": str(r.manifest_path.relative_to(r.evidence_dir)),
            "manifest_sha256": r.manifest_sha256,
            "started_at_utc": r.started_at_utc,
            "ended_at_utc": r.ended_at_utc,
        }

    # Exclusion counts by reason.
    reason_counts: dict[str, int] = {}
    for ex in result.excluded.values():
        reason = str(ex.get("reason") or "unknown")
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    payload: dict[str, Any] = {
        "selector_type": result.selector_type,
        "created_at_utc": created_at,
        "tool_version_git_sha": tool_version,
        "config_fingerprint_sha256": cfg_fp,
        "toolchain": toolchain,
        "query": {
            "query_params": result.query_params or {},
            "grouping_key": result.grouping_key,
            "pool_versions": bool(result.pool_versions),
        },
        "inclusion": {
            "included_run_ids": included_run_ids,
            "runs": per_run_meta,
        },
        "exclusion": {
            "excluded_runs": result.excluded,
            "counts_by_reason": {k: int(v) for k, v in sorted(reason_counts.items())},
        },
    }

    # Compute sha over the payload without the sha field.
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    digest = sha256(blob).hexdigest()
    payload["selection_manifest_sha256"] = digest

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return SelectionManifest(payload=payload, sha256=digest)


__all__ = [
    "QueryParams",
    "RunMode",
    "RunRef",
    "SelectionManifest",
    "SelectionResult",
    "SelectorType",
    "write_selection_manifest",
]
