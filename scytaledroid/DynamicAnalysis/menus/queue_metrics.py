"""Queue-facing evidence and quota summary helpers."""

from __future__ import annotations

import json
from pathlib import Path


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def summarize_evidence_quota(
    dataset_pkgs: set[str],
    cfg,
    *,
    output_dir: str,
    derive_freeze_eligibility_fn,
    min_windows: int,
    required_capture_policy_version: int,
    run_profile_bucket_fn,
) -> dict[str, int | bool]:
    root = Path(output_dir) / "evidence" / "dynamic"
    out: dict[str, int | bool] = {
        "evidence_root_exists": root.exists(),
        "total_runs": 0,
        "technical_valid_runs": 0,
        "paper_eligible_runs": 0,
        "quota_runs_counted": 0,
        "apps_satisfied": 0,
        "excluded_runs": 0,
        "extra_eligible_runs": 0,
        "baseline_ml_pool_runs": 0,
        "protocol_fit_poor_runs": 0,
        "low_signal_exploratory_runs": 0,
    }
    if not root.exists():
        return out

    per_pkg: dict[str, dict[str, int]] = {}
    per_pkg_rows: dict[str, list[dict[str, object]]] = {}
    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        out["total_runs"] = int(out["total_runs"]) + 1
        dataset = payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {}
        if dataset.get("valid_dataset_run") is True:
            out["technical_valid_runs"] = int(out["technical_valid_runs"]) + 1
        operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
        target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
        package = str(target.get("package_name") or "").strip().lower()
        if package not in dataset_pkgs:
            continue
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        eligibility = derive_freeze_eligibility_fn(
            manifest=payload,
            plan=plan,
            min_windows=min_windows,
            required_capture_policy_version=required_capture_policy_version,
        )
        if not eligibility.paper_eligible:
            out["excluded_runs"] = int(out["excluded_runs"]) + 1
            continue
        out["paper_eligible_runs"] = int(out["paper_eligible_runs"]) + 1
        bucket = run_profile_bucket_fn(str(dataset.get("run_profile") or operator.get("run_profile") or ""))
        if bucket == "unknown":
            continue
        per_pkg_rows.setdefault(package, []).append(
            {
                "bucket": bucket,
                "run_profile": str(dataset.get("run_profile") or operator.get("run_profile") or ""),
                "countable": (
                    True
                    if dataset.get("countable") is True
                    else False
                    if dataset.get("countable") is False
                    else None
                ),
                "low_signal": bool(dataset.get("low_signal")),
                "protocol_fit": str(operator.get("protocol_fit") or "").strip().lower(),
                "sort_key": str(payload.get("ended_at") or payload.get("started_at") or run_dir.name),
            }
        )

    for package, package_rows in per_pkg_rows.items():
        rows = sorted(package_rows, key=lambda row: str(row.get("sort_key") or ""))
        counts = {
            "baseline": 0,
            "interactive_manual": 0,
            "interactive_scripted": 0,
        }
        baseline_required = int(getattr(cfg, "baseline_required", 3))
        interactive_required = int(getattr(cfg, "interactive_required", 4))
        for row in rows:
            bucket = str(row.get("bucket") or "")
            explicit_countable = row.get("countable")

            if explicit_countable is False:
                out["extra_eligible_runs"] = int(out["extra_eligible_runs"]) + 1
                if bucket == "baseline":
                    out["baseline_ml_pool_runs"] = int(out["baseline_ml_pool_runs"]) + 1
                if row.get("protocol_fit") == "poor":
                    out["protocol_fit_poor_runs"] = int(out["protocol_fit_poor_runs"]) + 1
                if bool(row.get("low_signal")):
                    out["low_signal_exploratory_runs"] = int(out["low_signal_exploratory_runs"]) + 1
                continue

            if bucket == "baseline":
                if explicit_countable is True:
                    counts["baseline"] += 1
                    out["quota_runs_counted"] = int(out["quota_runs_counted"]) + 1
                elif counts["baseline"] < baseline_required:
                    counts["baseline"] += 1
                    out["quota_runs_counted"] = int(out["quota_runs_counted"]) + 1
                else:
                    out["extra_eligible_runs"] = int(out["extra_eligible_runs"]) + 1
                    out["baseline_ml_pool_runs"] = int(out["baseline_ml_pool_runs"]) + 1
                if row.get("protocol_fit") == "poor":
                    out["protocol_fit_poor_runs"] = int(out["protocol_fit_poor_runs"]) + 1
                if bool(row.get("low_signal")):
                    out["low_signal_exploratory_runs"] = int(out["low_signal_exploratory_runs"]) + 1
                continue

            if bucket == "unknown":
                continue
            bucket_key = "interactive_scripted" if bucket == "interactive_scripted" else "interactive_manual"
            if explicit_countable is True:
                counts[bucket_key] += 1
                out["quota_runs_counted"] = int(out["quota_runs_counted"]) + 1
            elif (
                counts["interactive_manual"] + counts["interactive_scripted"]
                < interactive_required
            ):
                counts[bucket_key] += 1
                out["quota_runs_counted"] = int(out["quota_runs_counted"]) + 1
            else:
                out["extra_eligible_runs"] = int(out["extra_eligible_runs"]) + 1
            if row.get("protocol_fit") == "poor":
                out["protocol_fit_poor_runs"] = int(out["protocol_fit_poor_runs"]) + 1
            if bool(row.get("low_signal")):
                out["low_signal_exploratory_runs"] = int(out["low_signal_exploratory_runs"]) + 1

        per_pkg[package] = counts

    for counts in per_pkg.values():
        if counts["baseline"] >= int(getattr(cfg, "baseline_required", 3)) and (
            counts["interactive_manual"] + counts["interactive_scripted"]
        ) >= int(getattr(cfg, "interactive_required", 4)):
            out["apps_satisfied"] = int(out["apps_satisfied"]) + 1

    return out


def resolve_active_cohort_evidence_quota_summary() -> dict[str, int | bool]:
    """Queue-aligned quota summary for the active research cohort."""
    from scytaledroid.Config import app_config, profile_config
    from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig
    from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
    from scytaledroid.DynamicAnalysis.tracker_scope import (
        min_windows_per_run as _min_windows_per_run,
        run_profile_bucket as _run_profile_bucket,
    )

    cfg = DatasetTrackerConfig()
    dataset_pkgs = {
        str(package).strip().lower()
        for package in active_research_cohort_packages()
        if str(package).strip()
    }
    return summarize_evidence_quota(
        dataset_pkgs,
        cfg,
        output_dir=app_config.OUTPUT_DIR,
        derive_freeze_eligibility_fn=derive_freeze_eligibility,
        min_windows=_min_windows_per_run(),
        required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
        run_profile_bucket_fn=_run_profile_bucket,
    )
