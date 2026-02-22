"""Operational snapshot freeze manifest (Phase F3).

Goal:
- Turn a query selection + evidence packs into a checksummed, immutable snapshot artifact.
- Reuse the same included_run_checksums schema as Paper #2 freeze verification so we can
  run the same immutability checker.

This is *operational* and does not change Phase E semantics or artifacts.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_operational as operational_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper_config
from scytaledroid.DynamicAnalysis.plans.loader import enrich_dynamic_plan

_REQUIRED_RELATIVE_INPUTS = (
    "run_manifest.json",
    "inputs/static_dynamic_plan.json",
    "analysis/summary.json",
    "analysis/pcap_report.json",
    "analysis/pcap_features.json",
)


def _normalize_hex(value: object, *, n: int) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw or len(raw) != int(n):
        return None
    allowed = set("0123456789abcdef")
    if any(ch not in allowed for ch in raw):
        return None
    return raw


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    # repo_root/scytaledroid/DynamicAnalysis/ml/snapshot_freeze.py -> parents[5]
    return Path(__file__).resolve().parents[5]


@dataclass(frozen=True)
class SnapshotFreezeResult:
    freeze_path: Path
    included_run_ids: list[str]
    missing_inputs: dict[str, list[str]]


def build_snapshot_freeze_manifest(
    *,
    selection_manifest_path: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    sel = _read_json(selection_manifest_path)
    if not isinstance(sel, dict):
        raise RuntimeError(f"Invalid selection manifest JSON: {selection_manifest_path}")

    inclusion = sel.get("inclusion") if isinstance(sel.get("inclusion"), dict) else {}
    runs = inclusion.get("runs") if isinstance(inclusion.get("runs"), dict) else {}
    included = inclusion.get("included_run_ids") if isinstance(inclusion.get("included_run_ids"), list) else []
    if not included:
        raise RuntimeError("selection_manifest missing inclusion.included_run_ids")

    included_run_ids = [str(rid).strip() for rid in included if isinstance(rid, str) and rid.strip()]
    included_run_ids = sorted(dict.fromkeys(included_run_ids))  # stable unique

    missing_inputs: dict[str, list[str]] = {}
    run_checksums: dict[str, dict[str, Any]] = {}
    identity_index: dict[tuple[str, str, str, str, str], str] = {}
    plan_schema_versions: set[str] = set()
    plan_paper_contract_versions: set[int] = set()

    for rid in included_run_ids:
        # Prefer the evidence-pack path recorded in the selection manifest (authoritative).
        meta = runs.get(rid) if isinstance(runs.get(rid), dict) else {}
        run_dir = None
        ev_path = meta.get("evidence_pack_path")
        if isinstance(ev_path, str) and ev_path.strip():
            candidate = Path(ev_path)
            if candidate.exists():
                run_dir = candidate
        if run_dir is None:
            run_dir = evidence_root / rid
        miss = [rel for rel in _REQUIRED_RELATIVE_INPUTS if not (run_dir / rel).exists()]

        mf = _read_json(run_dir / "run_manifest.json") or {}
        pcap_rel = None
        for a in (mf.get("artifacts") or []):
            if isinstance(a, dict) and a.get("type") == "pcapdroid_capture":
                pcap_rel = a.get("relative_path")
                break
        if isinstance(pcap_rel, str) and pcap_rel:
            if not (run_dir / pcap_rel).exists():
                miss.append(str(pcap_rel))

        if miss:
            missing_inputs[rid] = sorted(set(miss))
            continue

        checks: dict[str, str] = {}
        for rel in _REQUIRED_RELATIVE_INPUTS:
            checks[rel] = _sha256_file(run_dir / rel)

        pcap_sha256 = None
        pcap_size_bytes = None
        rep = _read_json(run_dir / "analysis/pcap_report.json") or {}
        pcap_sha256 = rep.get("pcap_sha256") or None
        pcap_size_bytes = rep.get("pcap_size_bytes") or None
        if isinstance(pcap_rel, str) and pcap_rel:
            pcap_path = run_dir / pcap_rel
            if pcap_path.exists():
                if not isinstance(pcap_sha256, str) or not pcap_sha256.strip():
                    pcap_sha256 = _sha256_file(pcap_path)
                if pcap_size_bytes is None:
                    try:
                        pcap_size_bytes = int(pcap_path.stat().st_size)
                    except Exception:
                        pcap_size_bytes = None

        run_checksums[rid] = {
            "package_name": meta.get("package_name"),
            "run_profile": meta.get("run_profile"),
            "ended_at": meta.get("ended_at_utc"),
            "mode": meta.get("mode"),
            "mode_source": meta.get("mode_source"),
            "files_sha256": checks,
            "pcap": {
                "relative_path": pcap_rel,
                "sha256": pcap_sha256,
                "size_bytes": pcap_size_bytes,
            },
        }
        plan = _read_json(run_dir / "inputs/static_dynamic_plan.json") or {}
        if isinstance(plan, dict):
            plan = enrich_dynamic_plan(plan)
        selector_type = str(sel.get("selector_type") or "")
        paper_mode = selector_type == "freeze"
        if paper_mode:
            plan_schema_version = str(plan.get("plan_schema_version") or "").strip()
            if not plan_schema_version:
                raise RuntimeError(f"FREEZE_MISSING_SCHEMA_VERSION:{rid}")
            try:
                plan_paper_contract_version = int(plan.get("paper_contract_version"))
            except Exception:
                raise RuntimeError(f"FREEZE_MISSING_SCHEMA_VERSION:{rid}")
            plan_schema_versions.add(plan_schema_version)
            plan_paper_contract_versions.add(int(plan_paper_contract_version))
        run_identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}
        pkg_lc = str(run_identity.get("package_name_lc") or plan.get("package_name") or meta.get("package_name") or "").strip().lower()
        version_code = str(run_identity.get("version_code") or plan.get("version_code") or "").strip()
        base_sha = _normalize_hex(run_identity.get("base_apk_sha256"), n=64)
        artifact_set_hash = _normalize_hex(run_identity.get("artifact_set_hash"), n=64)
        signer_set_hash = _normalize_hex(run_identity.get("signer_set_hash") or run_identity.get("signer_digest"), n=64)
        if not (pkg_lc and version_code and base_sha and artifact_set_hash and signer_set_hash):
            raise RuntimeError(f"FREEZE_BAD_IDENTITY:{rid}")
        identity_key = (pkg_lc, version_code, base_sha, artifact_set_hash, signer_set_hash)
        existing = identity_index.get(identity_key)
        if existing and existing != rid:
            raise RuntimeError(f"FREEZE_DUPLICATE_IDENTITY:{existing},{rid}")
        identity_index[identity_key] = rid
        run_checksums[rid]["identity"] = {
            "package_name_lc": pkg_lc,
            "version_code": version_code,
            "base_apk_sha256": base_sha,
            "artifact_set_hash": artifact_set_hash,
            "signer_set_hash": signer_set_hash,
        }

    if missing_inputs:
        raise RuntimeError(f"Missing required inputs for {len(missing_inputs)} run(s): {missing_inputs}")

    repo_root = _repo_root()
    selector_type = str(sel.get("selector_type") or "")
    paper_mode = selector_type == "freeze"
    if paper_mode and (len(plan_schema_versions) != 1 or len(plan_paper_contract_versions) != 1):
        raise RuntimeError(
            "FREEZE_MIXED_SCHEMA_VERSION:"
            f"plan_schema={sorted(plan_schema_versions)}:"
            f"paper_contract={sorted(plan_paper_contract_versions)}"
        )
    required_plan_schema_version = next(iter(plan_schema_versions)) if (paper_mode and plan_schema_versions) else None
    required_plan_paper_contract_version = (
        int(next(iter(plan_paper_contract_versions))) if (paper_mode and plan_paper_contract_versions) else None
    )
    min_pcap_bytes = int(paper_config.MIN_PCAP_BYTES if paper_mode else operational_config.MIN_PCAP_BYTES_FALLBACK)
    payload = {
        "artifact_type": "snapshot_freeze",
        "freeze_contract_version": int(paper_config.FREEZE_CONTRACT_VERSION if paper_mode else 1),
        "paper_contract_version": int(paper_config.PAPER_CONTRACT_VERSION if paper_mode else 0),
        "reason_taxonomy_version": int(paper_config.REASON_TAXONOMY_VERSION if paper_mode else 0),
        "created_at_utc": datetime.now(UTC).isoformat(),
        "tool_semver": app_config.APP_VERSION,
        "tool_git_commit": _git_commit_hash(repo_root),
        "selection_manifest_path": str(selection_manifest_path),
        "selection_manifest_sha256": str(sel.get("selection_manifest_sha256") or ""),
        "selector_type": selector_type,
        "query": sel.get("query"),
        "qa_thresholds": {
            "min_pcap_bytes": int(min_pcap_bytes),
        },
        "min_pcap_bytes_used": int(min_pcap_bytes),
        "frozen_inputs_per_run": list(_REQUIRED_RELATIVE_INPUTS) + ["<pcap from manifest artifact:pcapdroid_capture>"],
        "included_run_ids": included_run_ids,
        "included_run_checksums": run_checksums,
    }
    if required_plan_schema_version is not None:
        payload["plan_schema_version_required"] = required_plan_schema_version
    if required_plan_paper_contract_version is not None:
        payload["plan_paper_contract_version_required"] = required_plan_paper_contract_version
    return payload


def write_snapshot_freeze_manifest(
    *,
    snapshot_dir: Path,
    evidence_root: Path,
    overwrite: bool = False,
) -> SnapshotFreezeResult:
    selection_manifest_path = snapshot_dir / "selection_manifest.json"
    if not selection_manifest_path.exists():
        raise RuntimeError(f"Missing selection manifest: {selection_manifest_path}")

    freeze_path = snapshot_dir / "freeze_manifest.json"
    if freeze_path.exists() and not overwrite:
        payload = _read_json(freeze_path) or {}
        ids = payload.get("included_run_ids") if isinstance(payload.get("included_run_ids"), list) else []
        return SnapshotFreezeResult(freeze_path=freeze_path, included_run_ids=[str(x) for x in ids], missing_inputs={})

    payload = build_snapshot_freeze_manifest(selection_manifest_path=selection_manifest_path, evidence_root=evidence_root)
    freeze_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ids = payload.get("included_run_ids") if isinstance(payload.get("included_run_ids"), list) else []
    return SnapshotFreezeResult(freeze_path=freeze_path, included_run_ids=[str(x) for x in ids], missing_inputs={})


__all__ = ["SnapshotFreezeResult", "write_snapshot_freeze_manifest"]
