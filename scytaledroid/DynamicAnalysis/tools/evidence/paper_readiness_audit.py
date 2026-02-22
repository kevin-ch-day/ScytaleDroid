"""Paper-readiness audit for dynamic evidence packs.

This is a pre-freeze operator check that surfaces contract drift quickly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    load_dataset_packages,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config
from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN


@dataclass(frozen=True)
class AuditSummary:
    total_runs: int
    valid_runs: int
    paper_eligible_runs: int
    missing_run_manifest_dirs: int
    missing_capture_policy_version: int
    capture_policy_version_mismatch: int
    missing_signer_set_hash: int
    identity_mismatch: int
    missing_window_count: int
    window_count_below_min: int
    evidence_root: str
    evidence_root_exists: bool
    runs_discovered_from: str
    expected_valid_runs: int
    expected_total_runs: int
    result: str
    reasons: tuple[str, ...]
    tracker_runs_hint: int
    static_runs_hint: int
    report_path: str


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def run_paper_readiness_audit(
    *,
    evidence_root: Path | None = None,
    out_dir: Path | None = None,
) -> AuditSummary:
    default_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    root = evidence_root if evidence_root is not None else default_root
    out = out_dir or (Path(app_config.OUTPUT_DIR) / "audit" / "dynamic")
    out.mkdir(parents=True, exist_ok=True)

    required_policy = int(getattr(paper2_config, "PAPER_CONTRACT_VERSION", 1))
    min_window_count = int(MIN_WINDOWS_PER_RUN)

    issues: dict[str, list[str]] = {
        "missing_run_manifest_dirs": [],
        "missing_capture_policy_version": [],
        "capture_policy_version_mismatch": [],
        "missing_signer_set_hash": [],
        "identity_mismatch": [],
        "missing_window_count": [],
        "window_count_below_min": [],
    }

    run_rows: list[dict[str, Any]] = []
    total_runs = 0
    valid_runs = 0
    paper_eligible_runs = 0
    tracker_runs_hint = 0
    static_runs_hint = 0
    reasons: list[str] = []

    if root.exists():
        for run_dir in sorted([p for p in root.iterdir() if p.is_dir()]):
            manifest = _read_json(run_dir / "run_manifest.json")
            if not isinstance(manifest, dict):
                issues["missing_run_manifest_dirs"].append(str(run_dir.name))
                continue
            total_runs += 1
            run_id = str(manifest.get("dynamic_run_id") or run_dir.name)
            operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
            target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
            dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
            if dataset.get("valid_dataset_run") is True:
                valid_runs += 1

            cpv_raw = operator.get("capture_policy_version")
            try:
                cpv = int(cpv_raw)
            except Exception:
                cpv = None
            if cpv is None:
                issues["missing_capture_policy_version"].append(run_id)
            elif cpv != required_policy:
                issues["capture_policy_version_mismatch"].append(run_id)

            signer_set_hash = str(
                target.get("signer_set_hash")
                or (target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}).get("signer_set_hash")
                or ""
            ).strip()
            if not signer_set_hash:
                issues["missing_signer_set_hash"].append(run_id)

            plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
            eligibility = derive_paper_eligibility(
                manifest=manifest,
                plan=plan if isinstance(plan, dict) else {},
                min_windows=min_window_count,
                required_capture_policy_version=required_policy,
            )
            if eligibility.paper_eligible:
                paper_eligible_runs += 1
            if "EXCLUDED_IDENTITY_MISMATCH" in set(eligibility.all_reason_codes):
                issues["identity_mismatch"].append(run_id)

            wc_raw = dataset.get("window_count")
            try:
                wc = int(wc_raw)
            except Exception:
                wc = None
            if wc is None:
                issues["missing_window_count"].append(run_id)
            elif wc < min_window_count:
                issues["window_count_below_min"].append(run_id)

            run_rows.append(
                {
                    "run_id": run_id,
                    "package_name": target.get("package_name"),
                    "valid_dataset_run": dataset.get("valid_dataset_run"),
                    "capture_policy_version": cpv,
                    "signer_set_hash_present": bool(signer_set_hash),
                    "window_count": wc,
                    "min_window_count": min_window_count,
                }
            )

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    cfg = DatasetTrackerConfig()
    dataset_pkgs = load_dataset_packages()
    if dataset_pkgs:
        expected_valid_runs = len(dataset_pkgs) * (
            int(cfg.baseline_required) + int(cfg.interactive_required)
        )
    else:
        expected_valid_runs = 0
    expected_total_runs = expected_valid_runs
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    if isinstance(apps, dict):
        for entry in apps.values():
            if not isinstance(entry, dict):
                continue
            runs = entry.get("runs")
            if isinstance(runs, list):
                tracker_runs_hint += len(runs)
    static_root = Path("evidence") / "static_runs"
    if static_root.exists():
        for run_dir in static_root.iterdir():
            if run_dir.is_dir() and (run_dir / "run_manifest.json").exists():
                static_runs_hint += 1
    report_path = out / f"paper_readiness_audit_{stamp}.json"
    if total_runs <= 0:
        reasons.append("NO_EVIDENCE_PACKS_FOUND")
    if valid_runs <= 0:
        reasons.append("NO_VALID_RUNS")
    if paper_eligible_runs <= 0:
        reasons.append("NO_PAPER_ELIGIBLE_RUNS")
    if expected_valid_runs > 0 and (
        paper_eligible_runs < expected_valid_runs or total_runs < expected_valid_runs
    ):
        reasons.append("QUOTA_NOT_SATISFIED")
    if len(issues["missing_capture_policy_version"]) > 0:
        reasons.append("MISSING_CAPTURE_POLICY_VERSION")
    if len(issues["missing_run_manifest_dirs"]) > 0:
        reasons.append("INCOMPLETE_EVIDENCE_DIRS_PRESENT")
    if len(issues["capture_policy_version_mismatch"]) > 0:
        reasons.append("CAPTURE_POLICY_VERSION_MISMATCH")
    if len(issues["missing_signer_set_hash"]) > 0:
        reasons.append("MISSING_SIGNER_SET_HASH")
    if len(issues["identity_mismatch"]) > 0:
        reasons.append("IDENTITY_MISMATCH")
    if len(issues["missing_window_count"]) > 0:
        reasons.append("MISSING_WINDOW_COUNT")
    if len(issues["window_count_below_min"]) > 0:
        reasons.append("WINDOW_COUNT_BELOW_MIN")
    result = "GO" if not reasons else "NO_GO"

    payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "evidence_root": str(root.resolve()),
        "evidence_root_exists": bool(root.exists()),
        "runs_discovered_from": "filesystem",
        "result": result,
        "reasons": reasons,
        "required_capture_policy_version": required_policy,
        "required_min_window_count": min_window_count,
        "expected_valid_runs": expected_valid_runs,
        "expected_total_runs": expected_total_runs,
        "summary": {
            "total_runs": total_runs,
            "valid_runs": valid_runs,
            "paper_eligible_runs": paper_eligible_runs,
            "missing_run_manifest_dirs": len(issues["missing_run_manifest_dirs"]),
            "missing_capture_policy_version": len(issues["missing_capture_policy_version"]),
            "capture_policy_version_mismatch": len(issues["capture_policy_version_mismatch"]),
            "missing_signer_set_hash": len(issues["missing_signer_set_hash"]),
            "identity_mismatch": len(issues["identity_mismatch"]),
            "missing_window_count": len(issues["missing_window_count"]),
            "window_count_below_min": len(issues["window_count_below_min"]),
            "tracker_runs_hint": tracker_runs_hint,
            "static_runs_hint": static_runs_hint,
        },
        "issues": issues,
        "runs": run_rows,
    }
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    return AuditSummary(
        total_runs=total_runs,
        valid_runs=valid_runs,
        paper_eligible_runs=paper_eligible_runs,
        missing_run_manifest_dirs=len(issues["missing_run_manifest_dirs"]),
        missing_capture_policy_version=len(issues["missing_capture_policy_version"]),
        capture_policy_version_mismatch=len(issues["capture_policy_version_mismatch"]),
        missing_signer_set_hash=len(issues["missing_signer_set_hash"]),
        identity_mismatch=len(issues["identity_mismatch"]),
        missing_window_count=len(issues["missing_window_count"]),
        window_count_below_min=len(issues["window_count_below_min"]),
        evidence_root=str(root.resolve()),
        evidence_root_exists=bool(root.exists()),
        runs_discovered_from="filesystem",
        expected_valid_runs=expected_valid_runs,
        expected_total_runs=expected_total_runs,
        result=result,
        reasons=tuple(reasons),
        tracker_runs_hint=tracker_runs_hint,
        static_runs_hint=static_runs_hint,
        report_path=str(report_path),
    )


__all__ = ["AuditSummary", "run_paper_readiness_audit"]
