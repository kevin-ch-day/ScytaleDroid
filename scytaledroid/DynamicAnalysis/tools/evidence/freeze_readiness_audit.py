"""Freeze readiness audit for dynamic evidence packs.

This is a pre-freeze operator check that surfaces contract drift quickly.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    load_dataset_packages,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_lifecycle import (
    demote_noncanonical_canonical_freeze,
    inspect_canonical_freeze,
)


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
    # Evidence-derived quota (authoritative) for freeze mode: first N baseline + interaction
    # runs per package, after eligibility + low-signal rules.
    quota_runs_counted: int
    apps_satisfied: int
    result: str
    reasons: tuple[str, ...]
    tracker_runs_hint: int
    static_runs_hint: int
    can_freeze: bool
    first_failing_reason: str | None
    freeze_run_ids_present: int
    freeze_run_ids_total: int
    canonical_freeze_role: str
    canonical_freeze_contract_hash_present: bool
    canonical_freeze_demoted_to_legacy: str | None
    report_path: str


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _run_profile_bucket(run_profile: str) -> str:
    prof = (run_profile or "").strip().lower()
    if "baseline" in prof or "idle" in prof:
        return "baseline"
    if "interaction" in prof or "interactive" in prof or "script" in prof or "manual" in prof:
        return "interactive"
    return "unknown"


def _compute_evidence_quota(
    *,
    root: Path,
    dataset_pkgs_lc: set[str],
    cfg: DatasetTrackerConfig,
    required_policy: int,
    min_window_count: int,
) -> tuple[int, int]:
    """Return (quota_runs_counted, apps_satisfied) from evidence packs."""
    per_pkg: dict[str, dict[str, int]] = {}
    quota_runs_counted = 0
    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        manifest = _read_json(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        package = str(target.get("package_name") or "").strip().lower()
        if package not in dataset_pkgs_lc:
            continue
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        eligibility = derive_freeze_eligibility(
            manifest=manifest,
            plan=plan if isinstance(plan, dict) else {},
            min_windows=min_window_count,
            required_capture_policy_version=required_policy,
        )
        if not eligibility.paper_eligible:
            continue
        bucket = _run_profile_bucket(str(dataset.get("run_profile") or operator.get("run_profile") or ""))
        if bucket == "unknown":
            continue
        # Low-signal *idle* baseline rule: retained but must not satisfy quota.
        # baseline_connected must remain quota-eligible (low_signal is a tag, not an invalidation).
        prof_lc = str(dataset.get("run_profile") or operator.get("run_profile") or "").strip().lower()
        if bucket == "baseline" and prof_lc == "baseline_idle" and bool(dataset.get("low_signal")):
            continue
        counts = per_pkg.setdefault(package, {"baseline": 0, "interactive": 0})
        needed = int(cfg.baseline_required if bucket == "baseline" else cfg.interactive_required)
        if int(counts.get(bucket, 0)) < needed:
            counts[bucket] = int(counts.get(bucket, 0)) + 1
            quota_runs_counted += 1
    apps_satisfied = sum(
        1
        for counts in per_pkg.values()
        if int(counts.get("baseline", 0)) >= int(cfg.baseline_required)
        and int(counts.get("interactive", 0)) >= int(cfg.interactive_required)
    )
    return quota_runs_counted, apps_satisfied


def run_freeze_readiness_audit(
    *,
    evidence_root: Path | None = None,
    out_dir: Path | None = None,
) -> AuditSummary:
    default_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    root = evidence_root if evidence_root is not None else default_root
    out = out_dir or (Path(app_config.OUTPUT_DIR) / "audit" / "dynamic")
    out.mkdir(parents=True, exist_ok=True)

    required_policy = int(getattr(profile_config, "PAPER_CONTRACT_VERSION", 1))
    min_window_count = int(MIN_WINDOWS_PER_RUN)
    archive_dir = Path(app_config.DATA_DIR) / "archive"
    demotion = (
        demote_noncanonical_canonical_freeze(archive_dir=archive_dir, evidence_root=root)
        if evidence_root is None
        else {"demoted": False}
    )
    canonical_state = inspect_canonical_freeze(archive_dir=archive_dir, evidence_root=root)

    issues: dict[str, list[str]] = {
        "missing_run_manifest_dirs": [],
        "missing_capture_policy_version": [],
        "capture_policy_version_mismatch": [],
        "missing_signer_set_hash": [],
        "identity_mismatch": [],
        "missing_window_count": [],
        "window_count_below_min": [],
    }
    exclusion_reason_counts: Counter[str] = Counter()
    exclusion_top_offenders: dict[str, list[dict[str, str]]] = defaultdict(list)

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
            version_code = str(
                target.get("version_code")
                or (target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}).get("version_code")
                or ""
            ).strip()
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
            eligibility = derive_freeze_eligibility(
                manifest=manifest,
                plan=plan if isinstance(plan, dict) else {},
                min_windows=min_window_count,
                required_capture_policy_version=required_policy,
            )
            if eligibility.paper_eligible:
                paper_eligible_runs += 1
            else:
                reason = str(eligibility.reason_code or "EXCLUDED_INTERNAL_ERROR")
                exclusion_reason_counts[reason] += 1
                if len(exclusion_top_offenders[reason]) < 5:
                    exclusion_top_offenders[reason].append(
                        {
                            "run_id": run_id,
                            "package_name": str(target.get("package_name") or ""),
                            "version_code": version_code,
                        }
                    )
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
                    "version_code": version_code,
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
    dataset_pkgs_lc = {str(p).strip().lower() for p in dataset_pkgs if str(p).strip()}
    if dataset_pkgs:
        expected_valid_runs = len(dataset_pkgs) * (
            int(cfg.baseline_required) + int(cfg.interactive_required)
        )
    else:
        expected_valid_runs = 0
    expected_total_runs = expected_valid_runs
    quota_runs_counted = 0
    apps_satisfied = 0
    if root.exists() and dataset_pkgs_lc:
        quota_runs_counted, apps_satisfied = _compute_evidence_quota(
            root=root,
            dataset_pkgs_lc=dataset_pkgs_lc,
            cfg=cfg,
            required_policy=required_policy,
            min_window_count=min_window_count,
        )
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
        int(quota_runs_counted) < int(expected_valid_runs)
        or int(apps_satisfied) < len(dataset_pkgs_lc)
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
    freeze_run_presence = _classify_freeze_run_id_presence(archive_dir=archive_dir, evidence_root=root)
    if freeze_run_presence["missing_run_dirs"] > 0:
        reasons.append("FREEZE_RUN_IDS_MISSING_LOCALLY")
    result = "GO" if not reasons else "NO_GO"
    first_failing_reason = reasons[0] if reasons else None

    payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "evidence_root": str(root.resolve()),
        "evidence_root_exists": bool(root.exists()),
        "runs_discovered_from": "filesystem",
        "result": result,
        "reasons": reasons,
        "can_freeze": bool(result == "GO"),
        "first_failing_reason": first_failing_reason,
        "canonical_freeze": {
            "role": canonical_state.get("freeze_role"),
            "paper_contract_hash_present": bool(canonical_state.get("paper_contract_hash_present")),
            "run_ids_present": int(canonical_state.get("included_run_ids_present") or 0),
            "run_ids_total": int(canonical_state.get("included_run_ids_total") or 0),
            "noncanonical_reasons": canonical_state.get("noncanonical_reasons") or [],
            "demoted_to_legacy": str(demotion.get("legacy_path") or "") if bool(demotion.get("demoted")) else None,
            "run_id_presence_classification": freeze_run_presence,
        },
        "exclusion_reason_counts": dict(sorted((k, int(v)) for k, v in exclusion_reason_counts.items())),
        "exclusion_top_offenders": {
            str(k): [dict(x) for x in v]
            for k, v in sorted(exclusion_top_offenders.items())
        },
        "required_capture_policy_version": required_policy,
        "required_min_window_count": min_window_count,
        "expected_valid_runs": expected_valid_runs,
        "expected_total_runs": expected_total_runs,
        "quota_runs_counted": int(quota_runs_counted),
        "apps_satisfied": int(apps_satisfied),
        "summary": {
            "total_runs": total_runs,
            "valid_runs": valid_runs,
            "paper_eligible_runs": paper_eligible_runs,
            "quota_runs_counted": int(quota_runs_counted),
            "apps_satisfied": int(apps_satisfied),
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
        quota_runs_counted=int(quota_runs_counted),
        apps_satisfied=int(apps_satisfied),
        result=result,
        reasons=tuple(reasons),
        tracker_runs_hint=tracker_runs_hint,
        static_runs_hint=static_runs_hint,
        can_freeze=bool(result == "GO"),
        first_failing_reason=first_failing_reason,
        freeze_run_ids_present=int(canonical_state.get("included_run_ids_present") or 0),
        freeze_run_ids_total=int(canonical_state.get("included_run_ids_total") or 0),
        canonical_freeze_role=str(canonical_state.get("freeze_role") or "none"),
        canonical_freeze_contract_hash_present=bool(canonical_state.get("paper_contract_hash_present")),
        canonical_freeze_demoted_to_legacy=(
            str(demotion.get("legacy_path") or "") if bool(demotion.get("demoted")) else None
        ),
        report_path=str(report_path),
    )


def _classify_freeze_run_id_presence(*, archive_dir: Path, evidence_root: Path) -> dict[str, Any]:
    freeze_path = archive_dir / "dataset_freeze.json"
    payload = _read_json(freeze_path)
    if not isinstance(payload, dict):
        return {
            "freeze_exists": False,
            "total_run_ids": 0,
            "present_run_dirs": 0,
            "missing_run_dirs": 0,
            "found_but_incomplete": 0,
            "found_but_missing_required_files": 0,
            "found_but_identity_mismatch": 0,
            "sample_by_reason": {},
        }
    ids_raw = payload.get("included_run_ids")
    if not isinstance(ids_raw, list):
        return {
            "freeze_exists": True,
            "total_run_ids": 0,
            "present_run_dirs": 0,
            "missing_run_dirs": 0,
            "found_but_incomplete": 0,
            "found_but_missing_required_files": 0,
            "found_but_identity_mismatch": 0,
            "sample_by_reason": {},
        }
    ids = [str(v).strip() for v in ids_raw if str(v).strip()]
    required = (
        "run_manifest.json",
        "inputs/static_dynamic_plan.json",
        "analysis/summary.json",
        "analysis/pcap_report.json",
        "analysis/pcap_features.json",
    )
    summary: dict[str, Any] = {
        "freeze_exists": True,
        "total_run_ids": len(ids),
        "present_run_dirs": 0,
        "missing_run_dirs": 0,
        "found_but_incomplete": 0,
        "found_but_missing_required_files": 0,
        "found_but_identity_mismatch": 0,
        "sample_by_reason": {
            "missing_run_dirs": [],
            "found_but_incomplete": [],
            "found_but_missing_required_files": [],
            "found_but_identity_mismatch": [],
        },
    }
    for run_id in ids:
        run_dir = evidence_root / run_id
        if not run_dir.exists():
            summary["missing_run_dirs"] = int(summary["missing_run_dirs"]) + 1
            if len(summary["sample_by_reason"]["missing_run_dirs"]) < 5:
                summary["sample_by_reason"]["missing_run_dirs"].append({"run_id": run_id})
            continue
        summary["present_run_dirs"] = int(summary["present_run_dirs"]) + 1
        manifest = _read_json(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            summary["found_but_incomplete"] = int(summary["found_but_incomplete"]) + 1
            if len(summary["sample_by_reason"]["found_but_incomplete"]) < 5:
                summary["sample_by_reason"]["found_but_incomplete"].append({"run_id": run_id})
            continue
        missing = [rel for rel in required if not (run_dir / rel).exists()]
        if missing:
            summary["found_but_missing_required_files"] = int(summary["found_but_missing_required_files"]) + 1
            if len(summary["sample_by_reason"]["found_but_missing_required_files"]) < 5:
                summary["sample_by_reason"]["found_but_missing_required_files"].append(
                    {"run_id": run_id, "missing_files": ",".join(missing)}
                )
            continue
        plan = _read_json(run_dir / "inputs/static_dynamic_plan.json") or {}
        eligibility = derive_freeze_eligibility(
            manifest=manifest,
            plan=plan if isinstance(plan, dict) else {},
            min_windows=int(MIN_WINDOWS_PER_RUN),
            required_capture_policy_version=int(getattr(profile_config, "PAPER_CONTRACT_VERSION", 1)),
        )
        if "EXCLUDED_IDENTITY_MISMATCH" in set(eligibility.all_reason_codes):
            summary["found_but_identity_mismatch"] = int(summary["found_but_identity_mismatch"]) + 1
            if len(summary["sample_by_reason"]["found_but_identity_mismatch"]) < 5:
                summary["sample_by_reason"]["found_but_identity_mismatch"].append({"run_id": run_id})
    return summary


__all__ = ["AuditSummary", "run_freeze_readiness_audit"]
