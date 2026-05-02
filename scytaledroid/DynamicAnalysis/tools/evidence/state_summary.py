"""Scriptable state summary for freeze/evidence/tracker health."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import load_dataset_packages
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    load_dataset_tracker,
)
from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _min_windows_per_run() -> int:
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN

        return int(MIN_WINDOWS_PER_RUN)
    except Exception:
        return 20


def _run_profile_bucket(run_profile: str) -> str:
    prof = (run_profile or "").strip().lower()
    if "baseline" in prof or "idle" in prof:
        return "baseline"
    if "interaction" in prof or "interactive" in prof or "script" in prof or "manual" in prof:
        return "interactive"
    return "unknown"


def build_state_summary() -> dict[str, Any]:
    summary = run_freeze_readiness_audit()
    payload = _read_json(Path(summary.report_path)) or {}
    out: dict[str, Any] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "audit_result": summary.result,
        "can_freeze": bool(summary.can_freeze),
        "first_failing_reason": summary.first_failing_reason,
        "audit_report_path": summary.report_path,
        "evidence_root": summary.evidence_root,
        "freeze": {
            "role": summary.canonical_freeze_role,
            "paper_contract_hash_present": bool(summary.canonical_freeze_contract_hash_present),
            "run_ids_present": int(summary.freeze_run_ids_present),
            "run_ids_total": int(summary.freeze_run_ids_total),
            "demoted_to_legacy": summary.canonical_freeze_demoted_to_legacy,
            "presence_classification": ((payload.get("canonical_freeze") or {}).get("run_id_presence_classification") or {}),
        },
        "summary_counts": payload.get("summary") or {},
        "reasons": list(payload.get("reasons") or []),
        "exclusion_reason_counts": dict(payload.get("exclusion_reason_counts") or {}),
        "exclusion_top_offenders": dict(payload.get("exclusion_top_offenders") or {}),
        "tracker_vs_evidence_per_app": _tracker_vs_evidence_per_app(),
        "baseline_signal_summary": _baseline_signal_summary(),
    }
    out["next_collection_priorities"] = _build_collection_priorities(
        out["tracker_vs_evidence_per_app"] if isinstance(out["tracker_vs_evidence_per_app"], list) else []
    )
    return out


def _baseline_signal_summary() -> dict[str, Any]:
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    out: dict[str, Any] = {
        "baseline_idle_failures_by_category": {},
        "baseline_connected_successes": 0,
        "baseline_connected_successes_by_category": {},
    }
    if not root.exists():
        return out
    fail_by_cat: dict[str, int] = {}
    connected_ok_by_cat: dict[str, int] = {}
    connected_ok_total = 0
    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        manifest = _read_json(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        pkg = str(target.get("package_name") or "").strip().lower()
        cat = str(category_for_package(pkg) or "unknown")
        run_profile = str(operator.get("run_profile") or dataset.get("run_profile") or "").strip().lower()
        valid = dataset.get("valid_dataset_run")
        if run_profile == "baseline_idle" and valid is False:
            fail_by_cat[cat] = int(fail_by_cat.get(cat, 0)) + 1
        if run_profile == "baseline_connected" and valid is True:
            connected_ok_total += 1
            connected_ok_by_cat[cat] = int(connected_ok_by_cat.get(cat, 0)) + 1
    out["baseline_idle_failures_by_category"] = {k: int(v) for k, v in sorted(fail_by_cat.items())}
    out["baseline_connected_successes"] = int(connected_ok_total)
    out["baseline_connected_successes_by_category"] = {
        k: int(v) for k, v in sorted(connected_ok_by_cat.items())
    }
    return out


def _tracker_vs_evidence_per_app() -> list[dict[str, Any]]:
    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    tracker_apps = tracker.get("apps") if isinstance(tracker.get("apps"), dict) else {}
    dataset_pkgs = {str(pkg).strip().lower() for pkg in load_dataset_packages() if str(pkg).strip()}
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    per_pkg: dict[str, dict[str, int]] = {}
    for pkg in dataset_pkgs:
        per_pkg[pkg] = {"base_eligible": 0, "inter_eligible": 0, "excluded": 0}
    if root.exists():
        for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
            manifest = _read_json(run_dir / "run_manifest.json")
            if not isinstance(manifest, dict):
                continue
            target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
            pkg = str(target.get("package_name") or "").strip().lower()
            if pkg not in dataset_pkgs:
                continue
            plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
            eligibility = derive_freeze_eligibility(
                manifest=manifest,
                plan=plan,
                min_windows=_min_windows_per_run(),
                required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
            )
            if not eligibility.paper_eligible:
                per_pkg[pkg]["excluded"] += 1
                continue
            operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
            dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
            bucket = _run_profile_bucket(str(operator.get("run_profile") or dataset.get("run_profile") or ""))
            if bucket == "baseline":
                per_pkg[pkg]["base_eligible"] += 1
            elif bucket == "interactive":
                per_pkg[pkg]["inter_eligible"] += 1
            else:
                per_pkg[pkg]["excluded"] += 1

    rows: list[dict[str, Any]] = []
    for pkg in sorted(dataset_pkgs):
        entry = tracker_apps.get(pkg) if isinstance(tracker_apps, dict) else None
        tracker_base = int(entry.get("baseline_valid_runs") or 0) if isinstance(entry, dict) else 0
        tracker_inter = int(entry.get("interactive_valid_runs") or 0) if isinstance(entry, dict) else 0
        tracker_countable = tracker_base + tracker_inter
        base_eligible = int(per_pkg.get(pkg, {}).get("base_eligible", 0))
        inter_eligible = int(per_pkg.get(pkg, {}).get("inter_eligible", 0))
        evidence_countable = min(base_eligible, int(cfg.baseline_required)) + min(inter_eligible, int(cfg.interactive_required))
        need_baseline = max(0, int(cfg.baseline_required) - min(base_eligible, int(cfg.baseline_required)))
        need_interactive = max(0, int(cfg.interactive_required) - min(inter_eligible, int(cfg.interactive_required)))
        extras = max(0, base_eligible - int(cfg.baseline_required)) + max(0, inter_eligible - int(cfg.interactive_required))
        excluded = int(per_pkg.get(pkg, {}).get("excluded", 0))
        rows.append(
            {
                "package_name": pkg,
                "tracker_countable": tracker_countable,
                "evidence_eligible_countable": evidence_countable,
                "need_baseline": need_baseline,
                "need_interactive": need_interactive,
                "extras": extras,
                "excluded": excluded,
            }
        )
    return rows


def _build_collection_priorities(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        need_b = int(row.get("need_baseline") or 0)
        need_i = int(row.get("need_interactive") or 0)
        total = need_b + need_i
        if total <= 0:
            continue
        next_action = "scripted"
        if need_b > 0:
            next_action = "baseline"
        out.append(
            {
                "package_name": str(row.get("package_name") or ""),
                "need_baseline": need_b,
                "need_interactive": need_i,
                "total_needed": total,
                "suggested_next": next_action,
            }
        )
    out.sort(key=lambda r: (-int(r["total_needed"]), str(r["package_name"])))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dynamic freeze/evidence state summary")
    parser.add_argument("--json-out", default="", help="Optional output path for JSON summary.")
    args = parser.parse_args(argv)
    out = build_state_summary()
    print(f"CAN_FREEZE={str(bool(out.get('can_freeze'))).lower()}")
    print(f"FIRST_FAIL={out.get('first_failing_reason') or '-'}")
    freeze = out.get("freeze") if isinstance(out.get("freeze"), dict) else {}
    print(f"FREEZE_ROLE={freeze.get('role') or 'none'}")
    print(
        f"FREEZE_RUN_IDS_PRESENT={int(freeze.get('run_ids_present') or 0)}/{int(freeze.get('run_ids_total') or 0)}"
    )
    reasons = out.get("reasons") if isinstance(out.get("reasons"), list) else []
    if reasons:
        print("REASONS=" + ",".join(str(x) for x in reasons))
    ex = out.get("exclusion_reason_counts") if isinstance(out.get("exclusion_reason_counts"), dict) else {}
    if ex:
        print("EXCLUSION_COUNTS_TOP")
        for k, v in sorted(ex.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))[:10]:
            print(f"  {k}: {v}")
    baseline_signal = out.get("baseline_signal_summary") if isinstance(out.get("baseline_signal_summary"), dict) else {}
    if baseline_signal:
        print("BASELINE_SIGNAL")
        by_cat = (
            baseline_signal.get("baseline_idle_failures_by_category")
            if isinstance(baseline_signal.get("baseline_idle_failures_by_category"), dict)
            else {}
        )
        if by_cat:
            for cat, cnt in sorted(by_cat.items()):
                print(f"  baseline_idle_failures[{cat}]={int(cnt)}")
        print(
            "  baseline_connected_successes="
            + str(int(baseline_signal.get("baseline_connected_successes") or 0))
        )
    priorities = out.get("next_collection_priorities") if isinstance(out.get("next_collection_priorities"), list) else []
    if priorities:
        print("NEXT_COLLECTION_PRIORITIES")
        for row in priorities[:12]:
            print(
                "  "
                + f"{row.get('package_name')}: "
                + f"B{int(row.get('need_baseline') or 0)} "
                + f"I{int(row.get('need_interactive') or 0)} "
                + f"next={row.get('suggested_next')}"
            )
    json_out = str(args.json_out or "").strip()
    if json_out:
        out_path = Path(json_out)
    else:
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        out_path = Path(app_config.OUTPUT_DIR) / "audit" / "dynamic" / f"state_summary_{stamp}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(f"JSON={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
