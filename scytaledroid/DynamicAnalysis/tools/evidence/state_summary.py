"""Scriptable state summary for freeze/evidence/tracker health."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    load_dataset_tracker,
)
from scytaledroid.DynamicAnalysis.plans import (
    SUPPORTED_SIGNATURE_VERSIONS,
    extract_plan_identity,
)
from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_lifecycle import (
    inspect_canonical_freeze,
)
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_freeze_read_path


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
    repeatability = build_repeatability_summary()
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
        "static_handoff_plan_summary": build_static_handoff_plan_summary(),
        "repeatability_summary": repeatability,
    }
    out["next_collection_priorities"] = _build_collection_priorities(
        out["tracker_vs_evidence_per_app"] if isinstance(out["tracker_vs_evidence_per_app"], list) else []
    )
    return out


def build_static_handoff_plan_summary() -> dict[str, Any]:
    """Summarize dynamic plan readiness for the dataset cohort.

    Dynamic evidence packs are authoritative after collection, but before the
    first post-reset run the useful readiness signal is whether static produced
    usable dynamic plans for the dataset apps.
    """

    plan_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    dataset_pkgs = sorted({str(pkg).strip().lower() for pkg in active_research_cohort_packages() if str(pkg).strip()})
    by_pkg: dict[str, list[dict[str, Any]]] = {pkg: [] for pkg in dataset_pkgs}
    dynamic_plan_files = 0
    valid_plan_files = 0
    invalid_plan_files = 0

    if plan_dir.exists():
        for path in sorted(plan_dir.glob("*.json")):
            dynamic_plan_files += 1
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                invalid_plan_files += 1
                continue
            if not isinstance(payload, dict):
                invalid_plan_files += 1
                continue
            identity_raw = payload.get("run_identity") if isinstance(payload.get("run_identity"), dict) else {}
            if identity_raw.get("identity_valid") is False:
                invalid_plan_files += 1
                continue
            identity = extract_plan_identity(payload)
            package_name = str(identity.get("package") or payload.get("package_name") or "").strip().lower()
            if not package_name:
                invalid_plan_files += 1
                continue
            if identity.get("run_signature_version") not in SUPPORTED_SIGNATURE_VERSIONS:
                invalid_plan_files += 1
                continue
            if not identity.get("run_signature") or not identity.get("artifact_set_hash"):
                invalid_plan_files += 1
                continue
            valid_plan_files += 1
            if package_name in by_pkg:
                by_pkg[package_name].append(
                    {
                        "path": str(path),
                        "static_run_id": identity.get("static_run_id"),
                        "apk_set_id": identity.get("apk_set_id"),
                        "base_apk_sha256": identity.get("base_apk_sha256"),
                        "artifact_set_hash": identity.get("artifact_set_hash"),
                        "generated_at": payload.get("generated_at"),
                    }
                )

    packages_with_plan = [pkg for pkg, rows in by_pkg.items() if rows]
    missing_packages = [pkg for pkg, rows in by_pkg.items() if not rows]
    multiple_plan_packages = [pkg for pkg, rows in by_pkg.items() if len(_identity_keys(rows)) > 1]
    return {
        "plan_dir": str(plan_dir),
        "plan_dir_exists": bool(plan_dir.exists()),
        "dynamic_plan_files": int(dynamic_plan_files),
        "valid_plan_files": int(valid_plan_files),
        "invalid_plan_files": int(invalid_plan_files),
        "dataset_packages_total": int(len(dataset_pkgs)),
        "dataset_packages_with_plan": int(len(packages_with_plan)),
        "dataset_packages_missing_plan": int(len(missing_packages)),
        "missing_packages": missing_packages,
        "multiple_plan_identity_packages": multiple_plan_packages,
        "ready_for_guided_dataset_run": bool(dataset_pkgs and not missing_packages),
    }


def build_repeatability_summary() -> dict[str, Any]:
    """Summarize evidence-pack repeatability/readiness using on-disk contracts only."""

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    archive_dir = resolve_dataset_freeze_read_path().parent
    publication_manifests = Path(app_config.OUTPUT_DIR) / "publication" / "manifests"
    canonical_freeze = inspect_canonical_freeze(archive_dir=archive_dir, evidence_root=root)

    summary: dict[str, Any] = {
        "evidence_root": str(root),
        "evidence_root_exists": bool(root.exists()),
        "runs_total": 0,
        "runs_with_manifest": 0,
        "runs_identity_complete": 0,
        "runs_static_link_ready": 0,
        "runs_pcap_present": 0,
        "runs_features_present": 0,
        "runs_windowing_recorded": 0,
        "runs_threshold_present": 0,
        "runs_rdi_ready": 0,
        "runs_freeze_stamped": 0,
        "runs_repeatability_ready": 0,
        "issue_counts": {},
        "top_blockers": [],
        "publication_manifests_present": bool(publication_manifests.exists()),
        "publication_manifest_files": int(len(list(publication_manifests.glob("*.json"))) if publication_manifests.exists() else 0),
        "freeze_role": str(canonical_freeze.get("freeze_role") or "none"),
    }
    if not root.exists():
        return summary

    issue_counts: dict[str, int] = {}
    blocker_samples: dict[str, list[str]] = {}

    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        summary["runs_total"] = int(summary["runs_total"]) + 1
        manifest = _read_json(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            _bump_issue(issue_counts, blocker_samples, "manifest_missing_or_invalid", run_dir.name)
            continue
        summary["runs_with_manifest"] = int(summary["runs_with_manifest"]) + 1

        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
        ident = extract_plan_identity(plan) if isinstance(plan, dict) else {}
        features = _read_json(run_dir / "analysis" / "pcap_features.json")
        report = _read_json(run_dir / "analysis" / "pcap_report.json")
        summary_json = _read_json(run_dir / "analysis" / "summary.json")
        ml_summary = _read_json(run_dir / "analysis" / "ml" / "v1" / "ml_summary.json")
        model_manifest = _read_json(run_dir / "analysis" / "ml" / "v1" / "model_manifest.json")

        run_blockers: list[str] = []

        identity_complete = _identity_complete(ident)
        if identity_complete:
            summary["runs_identity_complete"] = int(summary["runs_identity_complete"]) + 1
        else:
            run_blockers.append("identity_incomplete")

        static_link_ready = bool(ident.get("static_run_id")) and bool(ident.get("static_handoff_hash"))
        if static_link_ready:
            summary["runs_static_link_ready"] = int(summary["runs_static_link_ready"]) + 1
        else:
            run_blockers.append("static_link_missing")

        pcap_present = _pcap_present(run_dir, manifest, report)
        if pcap_present:
            summary["runs_pcap_present"] = int(summary["runs_pcap_present"]) + 1
        else:
            run_blockers.append("pcap_missing")

        features_present = isinstance(features, dict) and isinstance(report, dict) and isinstance(summary_json, dict)
        if features_present:
            summary["runs_features_present"] = int(summary["runs_features_present"]) + 1
        else:
            run_blockers.append("analysis_outputs_missing")

        windowing_recorded = _windowing_recorded(manifest, ml_summary)
        if windowing_recorded:
            summary["runs_windowing_recorded"] = int(summary["runs_windowing_recorded"]) + 1
        else:
            run_blockers.append("windowing_unrecorded")

        threshold_present = _threshold_present(run_dir, ml_summary)
        if threshold_present:
            summary["runs_threshold_present"] = int(summary["runs_threshold_present"]) + 1
        else:
            run_blockers.append("baseline_threshold_missing")

        rdi_ready = _rdi_ready(run_dir, ml_summary)
        if rdi_ready:
            summary["runs_rdi_ready"] = int(summary["runs_rdi_ready"]) + 1
        else:
            run_blockers.append("rdi_missing")

        freeze_stamped = _freeze_stamped(model_manifest, ml_summary)
        if freeze_stamped:
            summary["runs_freeze_stamped"] = int(summary["runs_freeze_stamped"]) + 1
        else:
            run_blockers.append("freeze_stamp_missing")

        if not run_blockers:
            summary["runs_repeatability_ready"] = int(summary["runs_repeatability_ready"]) + 1
        else:
            for blocker in run_blockers:
                _bump_issue(issue_counts, blocker_samples, blocker, run_dir.name)

    summary["issue_counts"] = dict(sorted(issue_counts.items(), key=lambda kv: (-int(kv[1]), str(kv[0]))))
    summary["top_blockers"] = [
        {
            "code": code,
            "count": int(count),
            "sample_run_ids": blocker_samples.get(code, [])[:5],
        }
        for code, count in sorted(issue_counts.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))[:8]
    ]
    return summary


def _bump_issue(
    issue_counts: dict[str, int],
    blocker_samples: dict[str, list[str]],
    code: str,
    run_id: str,
) -> None:
    issue_counts[code] = int(issue_counts.get(code, 0)) + 1
    samples = blocker_samples.setdefault(code, [])
    if len(samples) < 5:
        samples.append(run_id)


def _identity_complete(identity: dict[str, Any]) -> bool:
    if not isinstance(identity, dict) or identity.get("identity_valid") is False:
        return False
    required = (
        "static_run_id",
        "run_signature",
        "run_signature_version",
        "artifact_set_hash",
        "base_apk_sha256",
        "static_handoff_hash",
    )
    if identity.get("run_signature_version") not in SUPPORTED_SIGNATURE_VERSIONS:
        return False
    return all(identity.get(key) for key in required)


def _pcap_present(run_dir: Path, manifest: dict[str, Any], report: dict[str, Any] | None) -> bool:
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    for item in artifacts:
        if not isinstance(item, dict) or item.get("type") != "pcapdroid_capture":
            continue
        rel = item.get("relative_path")
        if isinstance(rel, str) and rel and (run_dir / rel).exists():
            if not isinstance(report, dict):
                return True
            try:
                return int(report.get("pcap_size_bytes") or 0) > 0
            except Exception:
                return True
    return False


def _windowing_recorded(manifest: dict[str, Any], ml_summary: dict[str, Any] | None) -> bool:
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    try:
        window_count_ok = int(dataset.get("window_count") or 0) > 0
    except Exception:
        window_count_ok = False
    try:
        duration_ok = float(dataset.get("sampling_duration_seconds") or 0) > 0
    except Exception:
        duration_ok = False
    windowing = ml_summary.get("windowing") if isinstance(ml_summary, dict) and isinstance(ml_summary.get("windowing"), dict) else {}
    try:
        stride_ok = float(windowing.get("stride_s") or 0) > 0
    except Exception:
        stride_ok = False
    try:
        size_ok = float(windowing.get("window_size_s") or 0) > 0
    except Exception:
        size_ok = False
    return window_count_ok and duration_ok and stride_ok and size_ok


def _threshold_present(run_dir: Path, ml_summary: dict[str, Any] | None) -> bool:
    if (run_dir / "analysis" / "ml" / "v1" / "baseline_threshold.json").exists():
        return True
    models = ml_summary.get("models") if isinstance(ml_summary, dict) and isinstance(ml_summary.get("models"), dict) else {}
    return any(isinstance(meta, dict) and meta.get("threshold_value") is not None for meta in models.values())


def _rdi_ready(run_dir: Path, ml_summary: dict[str, Any] | None) -> bool:
    if (run_dir / "analysis" / "ml" / "v1" / "dars_v1.json").exists():
        return True
    models = ml_summary.get("models") if isinstance(ml_summary, dict) and isinstance(ml_summary.get("models"), dict) else {}
    return any(isinstance(meta, dict) and isinstance(meta.get("dars_v1"), dict) for meta in models.values())


def _freeze_stamped(model_manifest: dict[str, Any] | None, ml_summary: dict[str, Any] | None) -> bool:
    sources = []
    if isinstance(model_manifest, dict):
        sources.append(model_manifest)
    if isinstance(ml_summary, dict):
        sources.append(ml_summary)
    for payload in sources:
        if payload.get("freeze_manifest_sha256") and payload.get("freeze_dataset_hash"):
            return True
    return False


def _identity_keys(rows: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    out: set[tuple[str, str, str]] = set()
    for row in rows:
        out.add(
            (
                str(row.get("base_apk_sha256") or ""),
                str(row.get("artifact_set_hash") or ""),
                str(row.get("apk_set_id") or ""),
            )
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
    dataset_pkgs = {str(pkg).strip().lower() for pkg in active_research_cohort_packages() if str(pkg).strip()}
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
        countable_base = min(base_eligible, int(cfg.baseline_required))
        countable_inter = (
            min(inter_eligible, int(cfg.interactive_required))
            if countable_base >= int(cfg.baseline_required)
            else 0
        )
        evidence_countable = countable_base + countable_inter
        need_baseline = max(0, int(cfg.baseline_required) - min(base_eligible, int(cfg.baseline_required)))
        need_interactive = (
            max(0, int(cfg.interactive_required) - min(inter_eligible, int(cfg.interactive_required)))
            if need_baseline == 0
            else int(cfg.interactive_required)
        )
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
    handoff = (
        out.get("static_handoff_plan_summary")
        if isinstance(out.get("static_handoff_plan_summary"), dict)
        else {}
    )
    if handoff:
        print(
            "STATIC_HANDOFF_PLANS "
            + f"dataset_ready={int(handoff.get('dataset_packages_with_plan') or 0)}/"
            + f"{int(handoff.get('dataset_packages_total') or 0)} "
            + f"files={int(handoff.get('dynamic_plan_files') or 0)} "
            + f"valid={int(handoff.get('valid_plan_files') or 0)} "
            + f"missing={int(handoff.get('dataset_packages_missing_plan') or 0)}"
        )
    repeatability = (
        out.get("repeatability_summary")
        if isinstance(out.get("repeatability_summary"), dict)
        else {}
    )
    if repeatability:
        print(
            "REPEATABILITY "
            + f"ready={int(repeatability.get('runs_repeatability_ready') or 0)}/"
            + f"{int(repeatability.get('runs_total') or 0)} "
            + f"identity={int(repeatability.get('runs_identity_complete') or 0)} "
            + f"pcap={int(repeatability.get('runs_pcap_present') or 0)} "
            + f"rdi={int(repeatability.get('runs_rdi_ready') or 0)} "
            + f"freeze_stamped={int(repeatability.get('runs_freeze_stamped') or 0)}"
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
