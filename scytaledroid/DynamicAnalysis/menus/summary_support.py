"""State-summary support helpers for Dynamic Analysis menus."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
from scytaledroid.DynamicAnalysis.utils.path_utils import iter_dynamic_run_dirs


def run_profile_bucket(run_profile: str) -> str:
    prof = (run_profile or "").strip().lower()
    if "baseline" in prof or "idle" in prof:
        return "baseline"
    if "interaction" in prof or "interactive" in prof or "script" in prof or "manual" in prof:
        return "interactive"
    return "unknown"


def min_windows_per_run() -> int:
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN

        return int(MIN_WINDOWS_PER_RUN)
    except Exception:
        return 20


def next_action_from_need(need_baseline: int, need_interactive: int) -> str:
    nb = max(0, int(need_baseline))
    ni = max(0, int(need_interactive))
    if nb > 0:
        return "baseline"
    if ni > 0:
        return "manual interaction"
    return "—"


def compute_tracker_vs_evidence_deltas(
    *,
    read_json,
    min_windows_per_run,
) -> list[dict[str, object]]:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )

    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    tracker_apps = tracker.get("apps") if isinstance(tracker.get("apps"), dict) else {}
    dataset_pkgs = {str(pkg).strip().lower() for pkg in active_research_cohort_packages() if str(pkg).strip()}
    per_pkg: dict[str, dict[str, int]] = {
        pkg: {"base_eligible": 0, "inter_eligible": 0, "excluded": 0} for pkg in dataset_pkgs
    }
    run_dirs = iter_dynamic_run_dirs()
    if run_dirs:
        for run_dir in run_dirs:
            manifest = read_json(run_dir / "run_manifest.json")
            if not isinstance(manifest, dict):
                continue
            target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
            pkg = str(target.get("package_name") or "").strip().lower()
            if pkg not in dataset_pkgs:
                continue
            plan = read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
            eligibility = derive_freeze_eligibility(
                manifest=manifest,
                plan=plan,
                min_windows=min_windows_per_run(),
                required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
            )
            if not eligibility.paper_eligible:
                per_pkg[pkg]["excluded"] += 1
                continue
            operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
            dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
            bucket = run_profile_bucket(str(operator.get("run_profile") or dataset.get("run_profile") or ""))
            if bucket == "baseline":
                per_pkg[pkg]["base_eligible"] += 1
            elif bucket == "interactive":
                per_pkg[pkg]["inter_eligible"] += 1
            else:
                per_pkg[pkg]["excluded"] += 1

    rows: list[dict[str, object]] = []
    for pkg in sorted(dataset_pkgs):
        entry = tracker_apps.get(pkg) if isinstance(tracker_apps, dict) else None
        tracker_base = int(entry.get("baseline_valid_runs") or 0) if isinstance(entry, dict) else 0
        tracker_inter = int(entry.get("interactive_valid_runs") or 0) if isinstance(entry, dict) else 0
        base_eligible = int(per_pkg.get(pkg, {}).get("base_eligible", 0))
        inter_eligible = int(per_pkg.get(pkg, {}).get("inter_eligible", 0))
        evidence_countable = min(base_eligible, int(cfg.baseline_required)) + min(inter_eligible, int(cfg.interactive_required))
        need_baseline = max(0, int(cfg.baseline_required) - min(base_eligible, int(cfg.baseline_required)))
        need_interactive = max(0, int(cfg.interactive_required) - min(inter_eligible, int(cfg.interactive_required)))
        extras = max(0, base_eligible - int(cfg.baseline_required)) + max(0, inter_eligible - int(cfg.interactive_required))
        excluded = int(per_pkg.get(pkg, {}).get("excluded", 0))
        rows.append(
            {
                "Package": pkg,
                "Tracker countable": tracker_base + tracker_inter,
                "Evidence eligible countable": evidence_countable,
                "Need baseline": need_baseline,
                "Need interactive": need_interactive,
                "Extras": extras,
                "Excluded": excluded,
            }
        )
    return rows


def build_collection_priorities(delta_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for row in delta_rows:
        need_b = int(row.get("Need baseline") or 0)
        need_i = int(row.get("Need interactive") or 0)
        total = need_b + need_i
        if total <= 0:
            continue
        out.append(
            {
                "Package": row.get("Package"),
                "Need baseline": need_b,
                "Need interactive": need_i,
                "Total needed": total,
                "Suggested next": next_action_from_need(need_b, need_i),
            }
        )
    out.sort(key=lambda row: (-int(row["Total needed"]), str(row["Package"])))
    return out
