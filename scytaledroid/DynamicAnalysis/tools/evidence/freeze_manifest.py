"""Dataset freeze manifest generator (Paper #2).

PM-locked goals:
- Evidence packs remain authoritative and immutable after freeze.
- The freeze artifact is dataset-level (does not mutate evidence packs).
- It lists the exact included run_ids (1 baseline + 2 interactive per app) and
  records provenance (tool versions, thresholds, quota policy).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper_config
from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN
from scytaledroid.DynamicAnalysis.plans.loader import enrich_dynamic_plan


@dataclass(frozen=True)
class FreezeConfig:
    baseline_required: int = int(getattr(app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1))
    interactive_required: int = int(getattr(app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2))
    min_duration_s: int = int(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120))
    min_pcap_bytes: int = int(paper_config.MIN_PCAP_BYTES)
    min_windows_baseline: int = int(paper_config.MIN_WINDOWS_BASELINE)


_REQUIRED_RELATIVE_INPUTS = (
    "run_manifest.json",
    "inputs/static_dynamic_plan.json",
    "analysis/summary.json",
    "analysis/pcap_report.json",
    "analysis/pcap_features.json",
)


@dataclass(frozen=True)
class _RunCandidate:
    run_id: str
    package_name_lc: str
    bucket: str  # baseline|interactive
    window_count: int
    pcap_size_bytes: int
    actual_duration_s: float
    capture_start_utc: str


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


def _git_commit_short() -> str | None:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
        return out or None
    except Exception:
        return None


def _host_tools_versions_from_manifest(manifest: dict[str, Any]) -> dict[str, str] | None:
    env = manifest.get("environment") if isinstance(manifest.get("environment"), dict) else {}
    tools = env.get("host_tools") if isinstance(env.get("host_tools"), dict) else None
    if not isinstance(tools, dict):
        return None
    versions: dict[str, str] = {}
    for k in ("tshark", "capinfos"):
        v = tools.get(k)
        if isinstance(v, dict):
            vs = str(v.get("version") or v.get("version_text") or "").strip()
            if vs:
                versions[k] = vs
    return versions or None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bucket_from_profile(profile: str) -> str:
    p = str(profile or "").strip().lower()
    if "baseline" in p or "idle" in p:
        return "baseline"
    if p.startswith("interaction_") or "interactive" in p or "script" in p:
        return "interactive"
    return "unknown"


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def build_dataset_freeze_manifest(
    *,
    dataset_plan_path: Path,
    evidence_root: Path,
    cfg: FreezeConfig | None = None,
) -> dict[str, Any]:
    config = cfg or FreezeConfig()
    dataset_plan = _read_json(dataset_plan_path)
    if not isinstance(dataset_plan, dict):
        raise RuntimeError(f"Invalid dataset plan JSON: {dataset_plan_path}")

    if not evidence_root.exists():
        raise RuntimeError(f"FREEZE_BLOCKED_NO_EVIDENCE_ROOT:{evidence_root}")

    apps = dataset_plan.get("apps")
    if not isinstance(apps, dict) or not apps:
        raise RuntimeError("dataset_plan.json missing apps")

    # Deterministic included set is evidence-first and paper-eligibility-gated.
    included_by_app: dict[str, dict[str, list[str]]] = {}
    included_run_ids: list[str] = []
    missing_inputs: dict[str, list[str]] = {}
    # Dataset-level immutability anchor: checksums for the frozen inputs per included run.
    # This avoids relying on per-artifact hashes inside run_manifest.json (which are not
    # part of the Paper #2 contract and may be missing for older runs).
    run_checksums: dict[str, dict[str, Any]] = {}
    plan_schema_versions: set[str] = set()
    plan_paper_contract_versions: set[int] = set()
    excluded_reason_counts_by_app: dict[str, dict[str, int]] = defaultdict(dict)
    legacy_runs_present = False

    host_tool_versions: dict[str, set[str]] = {"tshark": set(), "capinfos": set()}
    dataset_pkgs = {str(pkg).strip().lower() for pkg in apps.keys() if str(pkg).strip()}
    candidates_by_pkg_bucket: dict[tuple[str, str], list[_RunCandidate]] = defaultdict(list)

    for run_dir in sorted([p for p in evidence_root.iterdir() if p.is_dir()], key=lambda p: p.name):
        rid = str(run_dir.name)
        mf = _read_json(run_dir / "run_manifest.json")
        if not isinstance(mf, dict):
            continue
        target = mf.get("target") if isinstance(mf.get("target"), dict) else {}
        pkg = str(target.get("package_name") or "").strip().lower()
        if pkg not in dataset_pkgs:
            continue
        op = mf.get("operator") if isinstance(mf.get("operator"), dict) else {}
        ds = mf.get("dataset") if isinstance(mf.get("dataset"), dict) else {}
        run_plan = _read_json(run_dir / "inputs/static_dynamic_plan.json") or {}
        if isinstance(run_plan, dict):
            run_plan = enrich_dynamic_plan(run_plan)
        eligibility = derive_paper_eligibility(
            manifest=mf,
            plan=run_plan if isinstance(run_plan, dict) else {},
            min_windows=int(MIN_WINDOWS_PER_RUN),
            required_capture_policy_version=int(paper_config.PAPER_CONTRACT_VERSION),
        )
        if not eligibility.paper_eligible:
            reason = str(eligibility.reason_code or "EXCLUDED_INTERNAL_ERROR")
            app_counts = excluded_reason_counts_by_app[pkg]
            app_counts[reason] = int(app_counts.get(reason, 0)) + 1
            if reason == "EXCLUDED_IDENTITY_MISMATCH":
                legacy_runs_present = True
            continue

        profile = str(op.get("run_profile") or ds.get("run_profile") or "")
        bucket = _bucket_from_profile(profile)
        if bucket not in {"baseline", "interactive"}:
            app_counts = excluded_reason_counts_by_app[pkg]
            app_counts["EXCLUDED_INTENT_NOT_ALLOWED"] = int(app_counts.get("EXCLUDED_INTENT_NOT_ALLOWED", 0)) + 1
            continue
        window_count = _safe_int(ds.get("window_count"))
        pcap_size_bytes = _safe_int(ds.get("pcap_size_bytes"))
        actual_duration_s = _safe_float(ds.get("sampling_duration_seconds"))
        capture_start_utc = str(mf.get("started_at") or (mf.get("scenario") or {}).get("started_at") or "").strip()
        if window_count is None or pcap_size_bytes is None or actual_duration_s is None or not capture_start_utc:
            app_counts = excluded_reason_counts_by_app[pkg]
            app_counts["EXCLUDED_MISSING_QUALITY_KEYS"] = int(app_counts.get("EXCLUDED_MISSING_QUALITY_KEYS", 0)) + 1
            continue
        candidates_by_pkg_bucket[(pkg, bucket)].append(
            _RunCandidate(
                run_id=rid,
                package_name_lc=pkg,
                bucket=bucket,
                window_count=int(window_count),
                pcap_size_bytes=int(pcap_size_bytes),
                actual_duration_s=float(actual_duration_s),
                capture_start_utc=capture_start_utc,
            )
        )

    for pkg in sorted(dataset_pkgs):
        base_cands = sorted(
            candidates_by_pkg_bucket.get((pkg, "baseline"), []),
            key=lambda c: (-c.window_count, -c.pcap_size_bytes, -c.actual_duration_s, c.capture_start_utc, c.run_id),
        )
        inter_cands = sorted(
            candidates_by_pkg_bucket.get((pkg, "interactive"), []),
            key=lambda c: (-c.window_count, -c.pcap_size_bytes, -c.actual_duration_s, c.capture_start_utc, c.run_id),
        )
        if len(base_cands) < int(config.baseline_required) or len(inter_cands) < int(config.interactive_required):
            raise RuntimeError(
                f"FREEZE_INSUFFICIENT_ELIGIBLE_RUNS:{pkg}:baseline={len(base_cands)}/{int(config.baseline_required)}:"
                f"interactive={len(inter_cands)}/{int(config.interactive_required)}"
            )
        base = [c.run_id for c in base_cands[: int(config.baseline_required)]]
        inter = [c.run_id for c in inter_cands[: int(config.interactive_required)]]
        included = base + inter
        included_by_app[pkg] = {
            "baseline_run_ids": base,
            "interactive_run_ids": inter,
            "included_run_ids": included,
        }
        included_run_ids.extend(included)
        expected_bucket_by_run_id = {rid: "baseline" for rid in base}
        expected_bucket_by_run_id.update({rid: "interactive" for rid in inter})

        # Track paper-eligible extras not selected by deterministic rank.
        for c in base_cands[int(config.baseline_required):]:
            app_counts = excluded_reason_counts_by_app[pkg]
            app_counts["EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK"] = (
                int(app_counts.get("EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK", 0)) + 1
            )
        for c in inter_cands[int(config.interactive_required):]:
            app_counts = excluded_reason_counts_by_app[pkg]
            app_counts["EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK"] = (
                int(app_counts.get("EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK", 0)) + 1
            )

        # Verify required frozen inputs and record checksums for included runs.
        for rid in included:
            run_dir = evidence_root / rid
            miss = [rel for rel in _REQUIRED_RELATIVE_INPUTS if not (run_dir / rel).exists()]
            mf = _read_json(run_dir / "run_manifest.json") or {}
            ds = mf.get("dataset") if isinstance(mf.get("dataset"), dict) else {}
            op = mf.get("operator") if isinstance(mf.get("operator"), dict) else {}
            observed_profile = str(op.get("run_profile") or ds.get("run_profile") or "").lower()
            observed_bucket = _bucket_from_profile(observed_profile)
            expected_bucket = expected_bucket_by_run_id.get(rid, "")
            if expected_bucket and observed_bucket and expected_bucket != observed_bucket:
                raise RuntimeError(f"FREEZE_EVIDENCE_PROFILE_MISMATCH:{rid}:{expected_bucket}!={observed_bucket}")
            pcap_rel = None
            for a in (mf.get("artifacts") or []):
                if isinstance(a, dict) and a.get("type") == "pcapdroid_capture":
                    pcap_rel = a.get("relative_path")
                    break
            if isinstance(pcap_rel, str) and pcap_rel and not (run_dir / pcap_rel).exists():
                miss.append(str(pcap_rel))
            if miss:
                missing_inputs[rid] = sorted(set(miss))
                continue

            versions = _host_tools_versions_from_manifest(mf)
            if versions:
                for k, v in versions.items():
                    host_tool_versions.setdefault(k, set()).add(v)

            checks: dict[str, str] = {rel: _sha256_file(run_dir / rel) for rel in _REQUIRED_RELATIVE_INPUTS}
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

            run_plan = _read_json(run_dir / "inputs/static_dynamic_plan.json") or {}
            if isinstance(run_plan, dict):
                run_plan = enrich_dynamic_plan(run_plan)
            plan_schema_version = str(run_plan.get("plan_schema_version") or "").strip()
            if not plan_schema_version:
                raise RuntimeError(f"FREEZE_MISSING_SCHEMA_VERSION:{rid}")
            try:
                plan_paper_contract_version = int(run_plan.get("paper_contract_version"))
            except Exception:
                raise RuntimeError(f"FREEZE_MISSING_SCHEMA_VERSION:{rid}")
            plan_schema_versions.add(plan_schema_version)
            plan_paper_contract_versions.add(int(plan_paper_contract_version))

            run_identity = run_plan.get("run_identity") if isinstance(run_plan.get("run_identity"), dict) else {}
            pkg_lc = str(run_identity.get("package_name_lc") or run_plan.get("package_name") or pkg).strip().lower()
            version_code = str(run_identity.get("version_code") or run_plan.get("version_code") or "").strip()
            base_sha = _normalize_hex(run_identity.get("base_apk_sha256"), n=64)
            artifact_set_hash = _normalize_hex(run_identity.get("artifact_set_hash"), n=64)
            signer_set_hash = _normalize_hex(run_identity.get("signer_set_hash") or run_identity.get("signer_digest"), n=64)
            if not (pkg_lc and version_code and base_sha and artifact_set_hash and signer_set_hash):
                raise RuntimeError(f"FREEZE_BAD_IDENTITY:{rid}")
            run_checksums[rid] = {
                "package_name": pkg,
                "run_profile": str(op.get("run_profile") or ""),
                "ended_at": mf.get("ended_at"),
                "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
                "low_signal_reasons": ds.get("low_signal_reasons") if isinstance(ds.get("low_signal_reasons"), list) else [],
                "files_sha256": checks,
                "pcap": {"relative_path": pcap_rel, "sha256": pcap_sha256, "size_bytes": pcap_size_bytes},
                "identity": {
                    "package_name_lc": pkg_lc,
                    "version_code": version_code,
                    "base_apk_sha256": base_sha,
                    "artifact_set_hash": artifact_set_hash,
                    "signer_set_hash": signer_set_hash,
                },
            }

    if missing_inputs:
        # Fail-closed: a freeze manifest must not reference incomplete packs.
        raise RuntimeError(f"Missing required frozen inputs for {len(missing_inputs)} run(s): {missing_inputs}")
    if len(plan_schema_versions) != 1 or len(plan_paper_contract_versions) != 1:
        raise RuntimeError(
            "FREEZE_MIXED_SCHEMA_VERSION:"
            f"plan_schema={sorted(plan_schema_versions)}:"
            f"paper_contract={sorted(plan_paper_contract_versions)}"
        )
    required_plan_schema_version = next(iter(plan_schema_versions))
    required_plan_paper_contract_version = int(next(iter(plan_paper_contract_versions)))

    return {
        "artifact_type": "dataset_freeze",
        "freeze_contract_version": int(paper_config.FREEZE_CONTRACT_VERSION),
        "paper_contract_version": int(paper_config.PAPER_CONTRACT_VERSION),
        "capture_policy_version_required": int(paper_config.PAPER_CONTRACT_VERSION),
        "reason_taxonomy_version": int(paper_config.REASON_TAXONOMY_VERSION),
        "plan_schema_version_required": required_plan_schema_version,
        "plan_paper_contract_version_required": required_plan_paper_contract_version,
        "dataset_id": "Research Dataset Alpha",
        "dataset_version": "paper2_v1",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "tool_semver": app_config.APP_VERSION,
        "tool_git_commit": _git_commit_short(),
        "schema_version": None,  # optional; DB is non-authoritative
        "quota_policy": {
            "baseline_required": int(config.baseline_required),
            "interactive_required": int(config.interactive_required),
            "selection_rule": "include iff evidence-derived paper_eligible=true; rank within (package,bucket) by "
            "window_count desc, pcap_bytes desc, actual_duration_s desc, capture_start_utc asc, run_id asc",
            "extras_policy": "extra valid runs are retained but excluded deterministically (out-of-dataset)",
        },
        "qa_thresholds": {
            "min_duration_s": int(config.min_duration_s),
            "min_pcap_bytes": int(config.min_pcap_bytes),
            "min_windows_baseline": int(config.min_windows_baseline),
        },
        "min_pcap_bytes_used": int(config.min_pcap_bytes),
        "frozen_inputs_per_run": list(_REQUIRED_RELATIVE_INPUTS) + ["<pcap from manifest artifact:pcapdroid_capture>"],
        "host_tools_versions": {k: sorted(v) for k, v in host_tool_versions.items() if v},
        "apps": included_by_app,
        "included_run_ids": sorted(set(included_run_ids)),
        "included_run_checksums": run_checksums,
        "legacy_runs_present": bool(legacy_runs_present),
        "excluded_reason_counts_by_app": {
            pkg: {k: int(v) for k, v in sorted(reasons.items())}
            for pkg, reasons in sorted(excluded_reason_counts_by_app.items())
        },
        "source_dataset_plan": {
            "path": str(dataset_plan_path),
            "updated_at": dataset_plan.get("updated_at"),
        },
    }


def write_dataset_freeze_manifest(
    *,
    evidence_root: Path,
    out_dir: Path,
    also_write_canonical: bool = True,
) -> Path:
    """Write a timestamped freeze manifest under out_dir.

    If also_write_canonical is True and out_dir/dataset_freeze.json does not exist,
    create it as a copy. Never overwrite an existing canonical freeze file.
    """

    dataset_plan_path = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    payload = build_dataset_freeze_manifest(dataset_plan_path=dataset_plan_path, evidence_root=evidence_root)

    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"dataset_freeze-{ts}.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    if also_write_canonical:
        canonical = out_dir / "dataset_freeze.json"
        if not canonical.exists():
            canonical.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    return out_path


__all__ = ["FreezeConfig", "build_dataset_freeze_manifest", "write_dataset_freeze_manifest"]
