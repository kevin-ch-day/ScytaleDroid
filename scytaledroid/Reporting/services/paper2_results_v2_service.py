"""Paper 2 v2 runtime ML results package writer.

This writer is the current Paper 2 runtime-ML publication path.  The v2 package
is built from the locked dataset freeze and per-window ML score files so
statistical results are not derived from rounded publication tables.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats
from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_freeze_read_path
from scytaledroid.DynamicAnalysis.run_duration_tiers import classify_duration_tier

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = REPO_ROOT / "data" / "evidence" / "dynamic"
DEFAULT_DATASET_PLAN = REPO_ROOT / "data" / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "_internal" / "publication" / "paper2_v2"
PRIMARY_MODEL = "iforest"
SECONDARY_MODEL = "ocsvm"
BOOTSTRAP_SEED = 20260713
BOOTSTRAP_N = 10_000

APP_LABELS = {
    "bbc.mobile.news.ww": "BBC News",
    "com.cnn.mobile.android.phone": "CNN",
    "com.facebook.katana": "Facebook",
    "com.facebook.orca": "Facebook Msg",
    "com.guardian": "The Guardian",
    "com.instagram.android": "Instagram",
    "com.linkedin.android": "LinkedIn",
    "com.pinterest": "Pinterest",
    "com.reddit.frontpage": "Reddit",
    "com.snapchat.android": "Snapchat",
    "com.twitter.android": "X",
    "com.whatsapp": "WhatsApp",
    "com.zhiliaoapp.musically": "TikTok",
    "org.telegram.messenger": "Telegram",
    "org.thoughtcrime.securesms": "Signal",
}

APP_CATEGORIES = {
    "bbc.mobile.news.ww": "News",
    "com.cnn.mobile.android.phone": "News",
    "com.guardian": "News",
    "com.facebook.katana": "Social media",
    "com.instagram.android": "Social media",
    "com.linkedin.android": "Social media",
    "com.pinterest": "Social media",
    "com.reddit.frontpage": "Social media",
    "com.snapchat.android": "Social media",
    "com.twitter.android": "Social media",
    "com.zhiliaoapp.musically": "Social media",
    "com.facebook.orca": "Messaging",
    "com.whatsapp": "Messaging",
    "org.telegram.messenger": "Messaging",
    "org.thoughtcrime.securesms": "Messaging",
}


@dataclass(frozen=True)
class ScoreMetrics:
    windows: int
    anomalous_windows: int
    rdi: float | None
    threshold: float | None = None


@dataclass(frozen=True)
class RunMetric:
    package_name: str
    display_name: str
    category: str
    run_id: str
    phase: str
    duration_s: float | None
    duration_tier: str
    duration_tier_label: str
    artifact_set_hash: str
    base_apk_sha256: str
    version_code: str
    version_name: str
    iforest: ScoreMetrics
    ocsvm: ScoreMetrics
    inclusion_reason: str
    exclusion_reason: str
    run_profile: str
    interaction_level: str
    static_run_id: str


def generate_paper2_results_v2(
    *,
    freeze_path: Path | None = None,
    dataset_plan_path: Path = DEFAULT_DATASET_PLAN,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
) -> dict[str, Any]:
    """Generate the Paper 2 v2 results package and return a manifest summary."""

    freeze_path = Path(freeze_path or resolve_dataset_freeze_read_path())
    output_root = Path(output_root)
    tables_dir = output_root / "tables"
    figures_dir = output_root / "figures"
    manifest_dir = output_root / "manifest"
    for directory in (tables_dir, figures_dir, manifest_dir):
        directory.mkdir(parents=True, exist_ok=True)

    freeze = _read_json(freeze_path)
    dataset_plan = _read_json(dataset_plan_path) if dataset_plan_path.exists() else {}
    static_scores = _read_static_scores(freeze=freeze, evidence_root=evidence_root)
    run_records, qa_warnings = _build_run_metrics(
        freeze=freeze,
        dataset_plan=dataset_plan,
        evidence_root=evidence_root,
    )
    excluded_run_rows = _build_excluded_run_rows(freeze=freeze, dataset_plan=dataset_plan)
    exclusion_accounting = _build_exclusion_accounting(
        freeze=freeze,
        dataset_plan=dataset_plan,
        excluded_run_rows=excluded_run_rows,
    )
    window_reconciliation_rows = _build_window_reconciliation_rows(
        freeze=freeze,
        dataset_plan=dataset_plan,
        evidence_root=evidence_root,
    )
    static_alignment_rows = _build_static_alignment_rows(
        freeze=freeze,
        dataset_plan=dataset_plan,
        evidence_root=evidence_root,
    )
    cohort_rows = _build_cohort_rows(freeze=freeze, run_records=run_records, dataset_plan=dataset_plan)

    primary_policy = "pooled_window_weighted"
    sensitivity_rows: list[dict[str, Any]] = []
    statistics_rows: list[dict[str, Any]] = []
    results_by_policy: dict[str, dict[str, Any]] = {}
    for model in (PRIMARY_MODEL, SECONDARY_MODEL):
        for policy in ("pooled_window_weighted", "equal_run", "standard_duration_only"):
            app_values = _aggregate_app_phase_values(run_records, model=model, policy=policy)
            summary = _build_policy_summary(app_values, model=model, policy=policy, static_scores=static_scores)
            results_by_policy[f"{model}:{policy}"] = summary
            sensitivity_rows.append(_summary_to_sensitivity_row(summary))
            statistics_rows.extend(_summary_to_statistics_rows(summary, primary=(model == PRIMARY_MODEL and policy == primary_policy)))

    per_app_primary = _aggregate_app_phase_values(run_records, model=PRIMARY_MODEL, policy=primary_policy)
    per_app_secondary = _aggregate_app_phase_values(run_records, model=SECONDARY_MODEL, policy=primary_policy)
    per_app_rdi_rows = _build_per_app_rdi_rows(per_app_primary, per_app_secondary, static_scores)
    ocsvm_warning_rows = _read_ocsvm_calibration_warnings()

    qa = _build_qa(
        output_root=output_root,
        freeze=freeze,
        run_records=run_records,
        per_app_primary=per_app_primary,
        ocsvm_warning_rows=ocsvm_warning_rows,
        qa_warnings=qa_warnings,
        exclusion_accounting=exclusion_accounting,
        window_reconciliation_rows=window_reconciliation_rows,
        static_alignment_rows=static_alignment_rows,
    )

    files: list[Path] = []
    files.append(_write_csv(output_root / "paper2_cohort_v2.csv", cohort_rows))
    files.append(_write_csv(output_root / "paper2_excluded_runs_v2.csv", excluded_run_rows))
    files.append(_write_csv(output_root / "paper2_window_reconciliation_v2.csv", window_reconciliation_rows))
    files.append(_write_csv(output_root / "paper2_static_alignment_v2.csv", static_alignment_rows))
    files.append(_write_csv(output_root / "paper2_per_app_rdi_v2.csv", per_app_rdi_rows))
    files.append(_write_csv(output_root / "paper2_statistics_v2.csv", statistics_rows))
    files.append(_write_csv(output_root / "paper2_run_sensitivity_v2.csv", sensitivity_rows))
    files.append(_write_csv(output_root / "paper2_ocsvm_calibration_warnings_v2.csv", ocsvm_warning_rows))
    files.append(_write_latex_statistics(output_root / "paper2_statistics_v2.tex", statistics_rows, sensitivity_rows))
    files.extend(_write_figures(figures_dir, per_app_rdi_rows))

    publication_results = {
        "schema_version": "paper2_results_v2",
        "freeze_path": str(freeze_path),
        "freeze_sha256": _sha256(freeze_path),
        "dataset_plan_path": str(dataset_plan_path),
        "dataset_plan_sha256": _sha256(dataset_plan_path) if dataset_plan_path.exists() else None,
        "evidence_root": str(evidence_root),
        "output_root": str(output_root),
        "dataset": {
            "apps": len(freeze.get("apps") or {}),
            "included_runs": len(freeze.get("included_run_ids") or []),
            "excluded_runs": len(excluded_run_rows),
            "window": "14-day selected build groups",
            "run_duration_tiers": dict(Counter(r.duration_tier_label for r in run_records)),
        },
        "aggregation_policy": _aggregation_policy_text(),
        "selection_flow": _selection_flow_summary(freeze=freeze, excluded_run_rows=excluded_run_rows),
        "deterministic_manifest": _deterministic_manifest_fields(
            freeze=freeze,
            dataset_plan=dataset_plan,
            evidence_root=evidence_root,
            excluded_run_rows=excluded_run_rows,
            static_alignment_rows=static_alignment_rows,
        ),
        "primary_result": results_by_policy.get(f"{PRIMARY_MODEL}:{primary_policy}"),
        "sensitivity": results_by_policy,
        "generated_files": [],
    }
    results_path = output_root / "publication_results_v2.json"
    results_path.write_text(json.dumps(publication_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(results_path)

    qa_path = output_root / "paper2_qa_v2.json"
    qa_path.write_text(json.dumps(qa, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(qa_path)

    publication_results["generated_files"] = [str(p.relative_to(output_root)) for p in files]
    publication_results["hash_manifest"] = "manifest/paper2_results_v2_manifest.json"
    results_path.write_text(json.dumps(publication_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hash_manifest = _write_hash_manifest(manifest_dir / "paper2_results_v2_manifest.json", files, base_dir=output_root)
    receipt_path = _write_generation_receipt(
        manifest_dir / "generation_receipt_v2.json",
        freeze_path=freeze_path,
        dataset_plan_path=dataset_plan_path,
        evidence_root=evidence_root,
        output_root=output_root,
        hash_manifest=hash_manifest,
        qa=qa,
    )

    return {
        "output_root": str(output_root),
        "publication_results_v2": str(results_path),
        "paper2_qa_v2": str(qa_path),
        "hash_manifest": str(hash_manifest),
        "generation_receipt": str(receipt_path),
        "apps": len(freeze.get("apps") or {}),
        "runs": len(run_records),
        "qa_status": qa["status"],
        "warnings": qa["warning_count"],
    }


def _build_run_metrics(
    *,
    freeze: Mapping[str, Any],
    dataset_plan: Mapping[str, Any],
    evidence_root: Path,
) -> tuple[list[RunMetric], list[str]]:
    plan_runs = _index_plan_runs(dataset_plan)
    apps = freeze.get("apps") or {}
    warnings: list[str] = []
    records: list[RunMetric] = []
    for package_name, app in apps.items():
        baseline_ids = set(str(x) for x in app.get("baseline_run_ids") or [])
        interactive_ids = set(str(x) for x in app.get("interactive_run_ids") or [])
        for run_id in app.get("included_run_ids") or []:
            run_id = str(run_id)
            phase = "baseline" if run_id in baseline_ids else "interactive" if run_id in interactive_ids else "unknown"
            plan_run = plan_runs.get(run_id, {})
            ml_dir = evidence_root / run_id / "analysis" / "ml" / "v1"
            iforest = _read_score_metrics(ml_dir / "anomaly_scores_iforest.csv")
            ocsvm = _read_score_metrics(ml_dir / "anomaly_scores_ocsvm.csv")
            if iforest.windows == 0:
                warnings.append(f"{run_id}: missing or empty Isolation Forest score file")
            if ocsvm.windows == 0:
                warnings.append(f"{run_id}: missing or empty OC-SVM score file")
            duration_s = _float_or_none(
                plan_run.get("pcap_capture_duration_s")
                or plan_run.get("actual_sampling_seconds")
                or plan_run.get("sampling_duration_seconds")
            )
            tier = classify_duration_tier(duration_s)
            records.append(
                RunMetric(
                    package_name=package_name,
                    display_name=APP_LABELS.get(package_name, package_name),
                    category=APP_CATEGORIES.get(package_name, "Other"),
                    run_id=run_id,
                    phase=phase,
                    duration_s=duration_s,
                    duration_tier=tier.key,
                    duration_tier_label=tier.label,
                    artifact_set_hash=str(plan_run.get("artifact_set_hash") or ""),
                    base_apk_sha256=str(plan_run.get("base_apk_sha256") or app.get("selected_base_apk_sha256") or ""),
                    version_code=str(plan_run.get("version_code") or app.get("selected_version_code") or ""),
                    version_name=str(plan_run.get("version_name") or ""),
                    iforest=iforest,
                    ocsvm=ocsvm,
                    inclusion_reason="included_by_locked_14d_selected_build_group",
                    exclusion_reason="",
                    run_profile=str(plan_run.get("run_profile") or ""),
                    interaction_level=str(plan_run.get("interaction_level") or ""),
                    static_run_id=str(plan_run.get("static_run_id") or ""),
                )
            )
    return records, warnings


def _build_excluded_run_rows(
    *,
    freeze: Mapping[str, Any],
    dataset_plan: Mapping[str, Any],
) -> list[dict[str, Any]]:
    included = {str(run_id) for run_id in freeze.get("included_run_ids") or []}
    apps = dataset_plan.get("apps") or {}
    rows: list[dict[str, Any]] = []
    if not isinstance(apps, Mapping):
        return rows
    for package_name, app in apps.items():
        for run in app.get("runs") or []:
            run_id = str(run.get("run_id") or "")
            if not run_id or run_id in included:
                continue
            primary_reason = str(run.get("paper_exclusion_primary_reason_code") or "").strip()
            all_reasons = run.get("paper_exclusion_all_reason_codes") or []
            if not primary_reason and not all_reasons:
                if not bool(run.get("paper_eligible")):
                    primary_reason = "not_paper_eligible"
                elif not bool(run.get("valid_dataset_run")):
                    primary_reason = "not_valid_dataset_run"
                else:
                    primary_reason = "not_selected_for_locked_build_group"
            rows.append(
                {
                    "display_name": APP_LABELS.get(str(package_name), str(package_name)),
                    "package_name": str(package_name),
                    "run_id": run_id,
                    "version_code": run.get("version_code", ""),
                    "version_name": run.get("version_name", ""),
                    "artifact_set_hash": run.get("artifact_set_hash", ""),
                    "base_apk_sha256": run.get("base_apk_sha256", ""),
                    "run_profile": run.get("run_profile", ""),
                    "interaction_level": run.get("interaction_level", ""),
                    "duration_tier": classify_duration_tier(_float_or_none(run.get("actual_sampling_seconds") or run.get("pcap_capture_duration_s"))).label,
                    "pcap_size_bytes": run.get("pcap_size_bytes", ""),
                    "window_count": run.get("window_count_final") or run.get("window_count") or "",
                    "paper_eligible": run.get("paper_eligible", ""),
                    "valid_dataset_run": run.get("valid_dataset_run", ""),
                    "inclusion_status": "excluded_from_locked_dataset",
                    "exclusion_reason": primary_reason,
                    "all_exclusion_reasons": ";".join(str(reason) for reason in all_reasons),
                }
            )
    return sorted(rows, key=lambda row: (str(row["package_name"]), str(row["run_id"])))


def _build_exclusion_accounting(
    *,
    freeze: Mapping[str, Any],
    dataset_plan: Mapping[str, Any],
    excluded_run_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    included = {str(run_id) for run_id in freeze.get("included_run_ids") or []}
    candidate = set(_index_plan_runs(dataset_plan).keys())
    excluded = {str(row.get("run_id") or "") for row in excluded_run_rows if row.get("run_id")}
    overlap = sorted(included & excluded)
    missing_from_accounting = sorted(candidate - included - excluded)
    extra_accounted = sorted((included | excluded) - candidate)
    duplicate_exclusion_rows = [
        run_id for run_id, count in Counter(str(row.get("run_id") or "") for row in excluded_run_rows).items() if run_id and count > 1
    ]
    exact = not overlap and not missing_from_accounting and not extra_accounted and not duplicate_exclusion_rows
    primary_reasons = Counter(str(row.get("exclusion_reason") or "unknown") for row in excluded_run_rows)
    supplemental_reasons: Counter[str] = Counter()
    for row in excluded_run_rows:
        for reason in str(row.get("all_exclusion_reasons") or "").split(";"):
            reason = reason.strip()
            if reason:
                supplemental_reasons[reason] += 1
    return {
        "status": "OK" if exact else "BLOCKED",
        "total_unique_candidate_run_ids": len(candidate),
        "total_unique_included_run_ids": len(included),
        "total_unique_excluded_run_ids": len(excluded),
        "total_exclusion_rows": len(excluded_run_rows),
        "runs_can_have_multiple_exclusion_rows": False,
        "included_and_excluded_overlap_count": len(overlap),
        "included_and_excluded_overlap_run_ids": overlap,
        "missing_from_accounting_count": len(missing_from_accounting),
        "missing_from_accounting_run_ids": missing_from_accounting,
        "extra_accounted_count": len(extra_accounted),
        "extra_accounted_run_ids": extra_accounted,
        "duplicate_exclusion_row_run_ids": sorted(duplicate_exclusion_rows),
        "primary_exclusion_reason_counts": dict(sorted(primary_reasons.items())),
        "supplemental_exclusion_reason_counts": dict(sorted(supplemental_reasons.items())),
    }


def _build_window_reconciliation_rows(
    *,
    freeze: Mapping[str, Any],
    dataset_plan: Mapping[str, Any],
    evidence_root: Path,
) -> list[dict[str, Any]]:
    plan_runs = _index_plan_runs(dataset_plan)
    rows: list[dict[str, Any]] = []
    for run_id in [str(run_id) for run_id in freeze.get("included_run_ids") or []]:
        plan_run = plan_runs.get(run_id, {})
        ml_dir = evidence_root / run_id / "analysis" / "ml" / "v1"
        preflight = _read_json_or_empty(ml_dir / "ml_preflight.json")
        ml_summary = _read_json_or_empty(ml_dir / "ml_summary.json")
        planned = _int_or_none(plan_run.get("window_count_final") or plan_run.get("window_count"))
        raw_extracted = _int_or_none(plan_run.get("window_count_original") or plan_run.get("window_count"))
        eligible = _int_or_none(preflight.get("windows_total_expected") or ml_summary.get("windows_total"))
        scored = _count_csv_rows(ml_dir / "anomaly_scores_iforest.csv")
        expected_drop_from_metadata = _int_or_none(preflight.get("dropped_partial_windows_expected") or ml_summary.get("dropped_partial_windows"))
        expected_drop = (
            raw_extracted - eligible
            if raw_extracted is not None and eligible is not None
            else expected_drop_from_metadata or 0
        )
        observed_difference = (planned - scored) if planned is not None and scored is not None else None
        additional_removed = (eligible - scored) if eligible is not None and scored is not None else None
        if scored is None:
            status = "MISSING_SCORE_FILE"
            reason = "Isolation Forest score file is missing."
        elif eligible is not None and scored == eligible:
            status = "OK"
            reason = "Scored windows match ML-eligible windows."
        elif raw_extracted is None:
            status = "UNKNOWN_RAW_COUNT"
            reason = "Raw extracted window count was not persisted separately."
        else:
            status = "DIFF_EXPLAINED" if additional_removed in (0, None) else "DIFF_REVIEW"
            reason = "Difference equals expected partial-window drop." if status == "DIFF_EXPLAINED" else "Difference exceeds expected partial-window drop."
        rows.append(
            {
                "run_id": run_id,
                "package_name": plan_run.get("package_name") or _package_for_run(freeze, run_id),
                "planned_window_count": planned if planned is not None else "",
                "raw_extracted_count": raw_extracted if raw_extracted is not None else "",
                "ml_eligible_count": eligible if eligible is not None else "",
                "scored_count": scored if scored is not None else "",
                "expected_partial_window_drop": expected_drop,
                "expected_partial_window_drop_metadata": expected_drop_from_metadata if expected_drop_from_metadata is not None else "",
                "additional_removed_windows": additional_removed if additional_removed is not None else "",
                "observed_difference": observed_difference if observed_difference is not None else "",
                "reconciliation_status": status,
                "reason": reason,
            }
        )
    return rows


def _build_static_alignment_rows(
    *,
    freeze: Mapping[str, Any],
    dataset_plan: Mapping[str, Any],
    evidence_root: Path,
) -> list[dict[str, Any]]:
    plan_runs = _index_plan_runs(dataset_plan)
    rows: list[dict[str, Any]] = []
    static_score_source = "locked freeze static_dynamic_plan.json inputs"
    for package_name, app in sorted((freeze.get("apps") or {}).items()):
        included = [str(run_id) for run_id in app.get("included_run_ids") or []]
        selected_run = plan_runs.get(included[0], {}) if included else {}
        static_plan = _read_json_or_empty(evidence_root / included[0] / "inputs" / "static_dynamic_plan.json") if included else {}
        dynamic_version = str(app.get("selected_version_code") or selected_run.get("version_code") or "")
        dynamic_sha = str(app.get("selected_base_apk_sha256") or selected_run.get("base_apk_sha256") or "")
        static_version = str(static_plan.get("version_code") or "")
        static_sha = str((static_plan.get("hashes") or {}).get("sha256") or "")
        exact = bool(dynamic_version and static_version and dynamic_sha and static_sha and dynamic_version == static_version and dynamic_sha == static_sha)
        if exact:
            mismatch_reason = ""
        elif not static_plan:
            mismatch_reason = "missing_static_dynamic_plan"
        elif dynamic_version != static_version:
            mismatch_reason = "version_code_mismatch"
        elif dynamic_sha != static_sha:
            mismatch_reason = "base_apk_sha256_mismatch"
        else:
            mismatch_reason = "metadata_incomplete"
        rows.append(
            {
                "display_name": APP_LABELS.get(str(package_name), str(package_name)),
                "package_name": str(package_name),
                "selected_dynamic_version_code": dynamic_version,
                "dynamic_apk_sha256": dynamic_sha,
                "static_run_id": static_plan.get("static_run_id") or selected_run.get("static_run_id") or "",
                "static_session": "",
                "static_version_code": static_version,
                "static_apk_sha256": static_sha,
                "exact_match": str(exact).lower(),
                "static_score_source": str(static_score_source),
                "mismatch_reason": mismatch_reason,
            }
        )
    return rows


def _build_cohort_rows(
    *,
    freeze: Mapping[str, Any],
    run_records: Sequence[RunMetric],
    dataset_plan: Mapping[str, Any],
) -> list[dict[str, Any]]:
    by_pkg: dict[str, list[RunMetric]] = defaultdict(list)
    for record in run_records:
        by_pkg[record.package_name].append(record)
    excluded = freeze.get("excluded_reason_counts_by_app") or {}
    rows: list[dict[str, Any]] = []
    for package_name, app in (freeze.get("apps") or {}).items():
        records = by_pkg.get(package_name, [])
        baseline = [r for r in records if r.phase == "baseline"]
        interactive = [r for r in records if r.phase == "interactive"]
        tier_counts = Counter(r.duration_tier_label for r in records)
        phase_window_counts = {
            "baseline": sum(r.iforest.windows for r in baseline),
            "interactive": sum(r.iforest.windows for r in interactive),
        }
        artifact_hashes = sorted({r.artifact_set_hash for r in records if r.artifact_set_hash})
        version_codes = sorted({r.version_code for r in records if r.version_code})
        base_hashes = sorted({r.base_apk_sha256 for r in records if r.base_apk_sha256})
        rows.append(
            {
                "display_name": APP_LABELS.get(package_name, package_name),
                "package_name": package_name,
                "category": APP_CATEGORIES.get(package_name, "Other"),
                "selected_version_code": app.get("selected_version_code") or ",".join(version_codes),
                "selected_base_apk_sha256": app.get("selected_base_apk_sha256") or (base_hashes[0] if base_hashes else ""),
                "artifact_set_hashes": ";".join(artifact_hashes),
                "baseline_run_ids": ";".join(r.run_id for r in baseline),
                "interactive_run_ids": ";".join(r.run_id for r in interactive),
                "baseline_run_count": len(baseline),
                "interactive_run_count": len(interactive),
                "included_run_count": len(records),
                "run_counts_by_duration_tier": json.dumps(dict(sorted(tier_counts.items())), sort_keys=True),
                "baseline_windows_iforest": phase_window_counts["baseline"],
                "interactive_windows_iforest": phase_window_counts["interactive"],
                "inclusion_reason": "included_by_locked_14d_selected_build_group",
                "exclusion_reasons": json.dumps(excluded.get(package_name) or {}, sort_keys=True),
            }
        )
    return rows


def _build_per_app_rows(
    *,
    freeze: Mapping[str, Any],
    run_records: Sequence[RunMetric],
    static_scores: Mapping[str, float],
) -> list[dict[str, Any]]:
    primary = _aggregate_app_phase_values(run_records, model=PRIMARY_MODEL, policy="pooled_window_weighted")
    secondary = _aggregate_app_phase_values(run_records, model=SECONDARY_MODEL, policy="pooled_window_weighted")
    return _build_per_app_rdi_rows(primary, secondary, static_scores)


def _build_per_app_rdi_rows(
    primary: Mapping[str, Mapping[str, Any]],
    secondary: Mapping[str, Mapping[str, Any]],
    static_scores: Mapping[str, float],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for package_name in sorted(primary, key=lambda p: APP_LABELS.get(p, p)):
        p = primary[package_name]
        s = secondary.get(package_name, {})
        rows.append(
            {
                "display_name": APP_LABELS.get(package_name, package_name),
                "package_name": package_name,
                "category": APP_CATEGORIES.get(package_name, "Other"),
                "if_baseline_rdi": _float_str(p.get("baseline_rdi")),
                "if_interactive_rdi": _float_str(p.get("interactive_rdi")),
                "if_delta_rdi": _float_str(p.get("delta")),
                "ocsvm_baseline_rdi": _float_str(s.get("baseline_rdi")),
                "ocsvm_interactive_rdi": _float_str(s.get("interactive_rdi")),
                "ocsvm_delta_rdi": _float_str(s.get("delta")),
                "baseline_runs": p.get("baseline_runs", 0),
                "interactive_runs": p.get("interactive_runs", 0),
                "baseline_windows": p.get("baseline_windows", 0),
                "interactive_windows": p.get("interactive_windows", 0),
                "static_exposure_score": _float_str(static_scores.get(package_name)),
            }
        )
    return rows


def _aggregate_app_phase_values(
    run_records: Sequence[RunMetric],
    *,
    model: str,
    policy: str,
) -> dict[str, dict[str, Any]]:
    by_pkg_phase: dict[str, dict[str, list[RunMetric]]] = defaultdict(lambda: defaultdict(list))
    for record in run_records:
        if record.phase not in {"baseline", "interactive"}:
            continue
        if policy == "standard_duration_only" and record.duration_tier != "standard":
            continue
        by_pkg_phase[record.package_name][record.phase].append(record)

    out: dict[str, dict[str, Any]] = {}
    for package_name, phases in by_pkg_phase.items():
        baseline = phases.get("baseline") or []
        interactive = phases.get("interactive") or []
        if not baseline or not interactive:
            continue
        b_rdi, b_windows = _phase_rdi(baseline, model=model, policy=policy)
        i_rdi, i_windows = _phase_rdi(interactive, model=model, policy=policy)
        if b_rdi is None or i_rdi is None:
            continue
        out[package_name] = {
            "package_name": package_name,
            "display_name": APP_LABELS.get(package_name, package_name),
            "category": APP_CATEGORIES.get(package_name, "Other"),
            "baseline_rdi": b_rdi,
            "interactive_rdi": i_rdi,
            "delta": i_rdi - b_rdi,
            "baseline_windows": b_windows,
            "interactive_windows": i_windows,
            "baseline_runs": len(baseline),
            "interactive_runs": len(interactive),
        }
    return out


def _phase_rdi(records: Sequence[RunMetric], *, model: str, policy: str) -> tuple[float | None, int]:
    metrics = [getattr(r, model) for r in records]
    windows = sum(m.windows for m in metrics)
    if policy in {"pooled_window_weighted", "standard_duration_only"}:
        anomalous = sum(m.anomalous_windows for m in metrics)
        return (anomalous / windows if windows else None), windows
    if policy == "equal_run":
        values = [m.rdi for m in metrics if m.rdi is not None]
        return (sum(values) / len(values) if values else None), windows
    raise ValueError(f"unknown aggregation policy: {policy}")


def _build_policy_summary(
    app_values: Mapping[str, Mapping[str, Any]],
    *,
    model: str,
    policy: str,
    static_scores: Mapping[str, float],
) -> dict[str, Any]:
    rows = list(app_values.values())
    deltas = [float(r["delta"]) for r in rows]
    baseline = [float(r["baseline_rdi"]) for r in rows]
    interactive = [float(r["interactive_rdi"]) for r in rows]
    paired = _paired_stats(deltas)
    static_corr = _static_spearman(rows, static_scores)
    return {
        "model": model,
        "aggregation_policy": policy,
        "included_apps": len(rows),
        "excluded_apps": sorted(set(APP_LABELS) - {str(r["package_name"]) for r in rows}),
        "baseline_runs": sum(int(r["baseline_runs"]) for r in rows),
        "interactive_runs": sum(int(r["interactive_runs"]) for r in rows),
        "baseline_windows": sum(int(r["baseline_windows"]) for r in rows),
        "interactive_windows": sum(int(r["interactive_windows"]) for r in rows),
        "baseline_phase_summary": _summary_stats(baseline),
        "interactive_phase_summary": _summary_stats(interactive),
        "delta_summary": _summary_stats(deltas),
        "paired_test": paired,
        "static_rdi_spearman": static_corr,
    }


def _paired_stats(deltas: Sequence[float]) -> dict[str, Any]:
    values = [float(x) for x in deltas if math.isfinite(float(x))]
    positives = sum(1 for x in values if x > 0)
    negatives = sum(1 for x in values if x < 0)
    zeroes = sum(1 for x in values if x == 0)
    nonzero = [x for x in values if x != 0]
    if nonzero:
        w = stats.wilcoxon(nonzero, alternative="two-sided", zero_method="wilcox", method="exact")
        w_greater = stats.wilcoxon(nonzero, alternative="greater", zero_method="wilcox", method="exact")
        ranks = stats.rankdata([abs(x) for x in nonzero])
        pos_rank = float(sum(rank for rank, x in zip(ranks, nonzero, strict=True) if x > 0))
        neg_rank = float(sum(rank for rank, x in zip(ranks, nonzero, strict=True) if x < 0))
        denom = float(len(nonzero) * (len(nonzero) + 1) / 2)
        rank_biserial = (pos_rank - neg_rank) / denom if denom else None
    else:
        w = w_greater = None
        rank_biserial = None
    dz = _cohens_dz(values)
    dz_ci = _bootstrap_dz_ci(values)
    return {
        "n_pairs": len(values),
        "positive_differences": positives,
        "negative_differences": negatives,
        "zero_differences": zeroes,
        "wilcoxon_w_statistic": float(w.statistic) if w is not None else None,
        "wilcoxon_alternative": "two-sided",
        "wilcoxon_method": "exact",
        "wilcoxon_zero_method": "wilcox",
        "wilcoxon_p_value_full_precision": float(w.pvalue) if w is not None else None,
        "wilcoxon_greater_p_value_reference": float(w_greater.pvalue) if w_greater is not None else None,
        "cohens_dz": dz,
        "cohens_dz_bootstrap_ci_low": dz_ci[0],
        "cohens_dz_bootstrap_ci_high": dz_ci[1],
        "cohens_dz_bootstrap_method": f"app-level paired bootstrap, {BOOTSTRAP_N} resamples, seed={BOOTSTRAP_SEED}",
        "matched_pairs_rank_biserial": rank_biserial,
    }


def _summary_stats(values: Sequence[float]) -> dict[str, Any]:
    vals = sorted(float(v) for v in values if math.isfinite(float(v)))
    if not vals:
        return {"n": 0}
    q1, median, q3 = np.percentile(vals, [25, 50, 75], method="linear")
    return {
        "n": len(vals),
        "median": float(median),
        "iqr": float(q3 - q1),
        "q1": float(q1),
        "q3": float(q3),
        "range_min": float(min(vals)),
        "range_max": float(max(vals)),
        "mean": float(statistics.fmean(vals)),
        "sd": float(statistics.stdev(vals)) if len(vals) > 1 else 0.0,
    }


def _static_spearman(rows: Sequence[Mapping[str, Any]], static_scores: Mapping[str, float]) -> dict[str, Any]:
    xs: list[float] = []
    ys: list[float] = []
    for row in rows:
        package_name = str(row["package_name"])
        if package_name in static_scores:
            xs.append(float(static_scores[package_name]))
            ys.append(float(row["interactive_rdi"]))
    if len(xs) < 3:
        return {"n": len(xs), "rho": None, "p_value": None, "ci_low": None, "ci_high": None}
    sp = stats.spearmanr(xs, ys)
    ci_low, ci_high = _bootstrap_spearman_ci(xs, ys)
    return {
        "n": len(xs),
        "rho": float(sp.statistic),
        "p_value": float(sp.pvalue),
        "ci_low": ci_low,
        "ci_high": ci_high,
        "ci_method": f"paired app bootstrap, {BOOTSTRAP_N} resamples, seed={BOOTSTRAP_SEED}",
        "static_score_source": "locked freeze static_dynamic_plan.json inputs",
    }


def _summary_to_sensitivity_row(summary: Mapping[str, Any]) -> dict[str, Any]:
    paired = summary["paired_test"]
    delta = summary["delta_summary"]
    base = summary["baseline_phase_summary"]
    inter = summary["interactive_phase_summary"]
    return {
        "model": summary["model"],
        "aggregation_policy": summary["aggregation_policy"],
        "included_apps": summary["included_apps"],
        "excluded_apps": ";".join(summary["excluded_apps"]),
        "baseline_runs": summary["baseline_runs"],
        "interactive_runs": summary["interactive_runs"],
        "baseline_windows": summary["baseline_windows"],
        "interactive_windows": summary["interactive_windows"],
        "baseline_median_rdi": _float_str(base.get("median")),
        "interactive_median_rdi": _float_str(inter.get("median")),
        "delta_median": _float_str(delta.get("median")),
        "delta_mean": _float_str(delta.get("mean")),
        "delta_sd": _float_str(delta.get("sd")),
        "positive_differences": paired["positive_differences"],
        "negative_differences": paired["negative_differences"],
        "zero_differences": paired["zero_differences"],
        "wilcoxon_w": _float_str(paired["wilcoxon_w_statistic"]),
        "wilcoxon_p_two_sided": _float_str(paired["wilcoxon_p_value_full_precision"]),
        "cohens_dz": _float_str(paired["cohens_dz"]),
        "rank_biserial": _float_str(paired["matched_pairs_rank_biserial"]),
    }


def _summary_to_statistics_rows(summary: Mapping[str, Any], *, primary: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    model = summary["model"]
    policy = summary["aggregation_policy"]
    for phase_key, label in (("baseline_phase_summary", "baseline"), ("interactive_phase_summary", "interactive"), ("delta_summary", "delta")):
        s = summary[phase_key]
        rows.append(
            {
                "section": "phase_summary",
                "primary": str(primary).lower(),
                "model": model,
                "aggregation_policy": policy,
                "metric": label,
                "n": s.get("n"),
                "median": _float_str(s.get("median")),
                "iqr": _float_str(s.get("iqr")),
                "range_min": _float_str(s.get("range_min")),
                "range_max": _float_str(s.get("range_max")),
                "mean": _float_str(s.get("mean")),
                "sd": _float_str(s.get("sd")),
                "value": "",
                "notes": "",
            }
        )
    paired = summary["paired_test"]
    for key in (
        "wilcoxon_w_statistic",
        "wilcoxon_p_value_full_precision",
        "wilcoxon_greater_p_value_reference",
        "cohens_dz",
        "cohens_dz_bootstrap_ci_low",
        "cohens_dz_bootstrap_ci_high",
        "matched_pairs_rank_biserial",
        "positive_differences",
        "negative_differences",
        "zero_differences",
    ):
        rows.append(
            {
                "section": "paired_test",
                "primary": str(primary).lower(),
                "model": model,
                "aggregation_policy": policy,
                "metric": key,
                "n": paired.get("n_pairs"),
                "median": "",
                "iqr": "",
                "range_min": "",
                "range_max": "",
                "mean": "",
                "sd": "",
                "value": _float_str(paired.get(key)),
                "notes": f"alternative={paired.get('wilcoxon_alternative')}; method={paired.get('wilcoxon_method')}; zero_method={paired.get('wilcoxon_zero_method')}",
            }
        )
    spearman = summary["static_rdi_spearman"]
    for key in ("rho", "p_value", "ci_low", "ci_high"):
        rows.append(
            {
                "section": "static_rdi_spearman",
                "primary": str(primary).lower(),
                "model": model,
                "aggregation_policy": policy,
                "metric": key,
                "n": spearman.get("n"),
                "median": "",
                "iqr": "",
                "range_min": "",
                "range_max": "",
                "mean": "",
                "sd": "",
                "value": _float_str(spearman.get(key)),
                "notes": spearman.get("ci_method", ""),
            }
        )
    return rows


def _build_qa(
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    freeze: Mapping[str, Any],
    run_records: Sequence[RunMetric],
    per_app_primary: Mapping[str, Mapping[str, Any]],
    ocsvm_warning_rows: Sequence[Mapping[str, Any]],
    qa_warnings: Sequence[str],
    exclusion_accounting: Mapping[str, Any],
    window_reconciliation_rows: Sequence[Mapping[str, Any]],
    static_alignment_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    app_count = len(freeze.get("apps") or {})
    run_count = len(run_records)
    label_counts = Counter(r.interaction_level or "unknown" for r in run_records)
    heldout_possible = {
        pkg: bool(vals.get("baseline_runs", 0) >= 2)
        for pkg, vals in per_app_primary.items()
    }
    warnings = list(qa_warnings)
    if label_counts.get("unknown", 0):
        warnings.append("scripted/manual primary table omitted because interaction labels include unknown values")
    window_status_counts = Counter(str(row.get("reconciliation_status") or "UNKNOWN") for row in window_reconciliation_rows)
    static_mismatches = [row for row in static_alignment_rows if str(row.get("exact_match") or "").lower() != "true"]
    static_run_ids = [r.static_run_id for r in run_records if r.static_run_id]
    missing_static_runs = sorted({r.package_name for r in run_records if not r.static_run_id})
    package_integrity_status = "OK" if exclusion_accounting.get("status") == "OK" and not missing_static_runs else "BLOCKED"
    provenance_status = "OK" if not static_mismatches and not missing_static_runs and not [k for k in window_status_counts if k not in {"OK", "DIFF_EXPLAINED"}] else "WARN"
    minimum_validation = _read_minimum_validation_status(output_root=output_root, expected_apps=app_count)
    scientific_validation_status = "MINIMUM_COMPLETE" if minimum_validation["status"] == "OK" else "INCOMPLETE"
    manuscript_readiness_status = (
        "RESULTS_PACKAGE_READY"
        if scientific_validation_status == "MINIMUM_COMPLETE" and package_integrity_status == "OK"
        else "NOT_READY"
    )
    status = package_integrity_status if scientific_validation_status == "MINIMUM_COMPLETE" else "NOT_READY"
    completed_validation = [
        "full-precision per-window RDI aggregation",
        "paired Wilcoxon exact two-sided test",
        "equal-run and standard-duration sensitivity rows",
        "independent results/statistics recomputation from score files",
    ]
    incomplete_validation = [
        "baseline-to-baseline controls",
        "phase-label permutation controls",
    ]
    if minimum_validation["status"] == "OK":
        completed_validation.extend(
            [
                "leave-one-baseline-run-out held-out baseline validation",
                "compact feature ablation",
                "simple bytes/sec P95 control",
                "20-seed Isolation Forest stability check",
            ]
        )
        if minimum_validation.get("temporal_order_status") == "OK":
            completed_validation.append("temporal-order control")
        else:
            incomplete_validation.append("temporal-order controls")
    else:
        incomplete_validation[:0] = [
            "held-out baseline validation",
            "feature ablation",
            "simple-volume controls",
            "multi-seed stability",
            "temporal-order controls",
        ]
    return {
        "schema_version": "paper2_qa_v2",
        "status": status,
        "package_integrity_status": package_integrity_status,
        "provenance_status": provenance_status,
        "scientific_validation_status": scientific_validation_status,
        "manuscript_readiness_status": manuscript_readiness_status,
        "warning_count": len(warnings),
        "warnings": warnings,
        "cohort": {
            "apps": app_count,
            "included_runs": run_count,
            "expected_apps": 15,
            "expected_runs_from_anchor": len(freeze.get("included_run_ids") or []),
            "apps_with_primary_rdi_pairs": len(per_app_primary),
        },
        "exclusion_accounting": dict(exclusion_accounting),
        "window_reconciliation": {
            "rows": len(window_reconciliation_rows),
            "status_counts": dict(sorted(window_status_counts.items())),
            "path": "paper2_window_reconciliation_v2.csv",
        },
        "static_alignment": {
            "run_records_with_static_run_id": len(static_run_ids),
            "unique_static_run_ids": len(set(static_run_ids)),
            "packages_missing_static_run_id": missing_static_runs,
            "app_rows": len(static_alignment_rows),
            "mismatch_count": len(static_mismatches),
            "mismatched_packages": [str(row.get("package_name") or "") for row in static_mismatches],
            "path": "paper2_static_alignment_v2.csv",
            "status": "OK" if not static_mismatches and not missing_static_runs else "WARN",
        },
        "scientific_validation_scope": {
            "completed": completed_validation,
            "incomplete": incomplete_validation,
            "minimum_validation": minimum_validation,
        },
        "score_source_policy": {
            "rdi_source": "per-run analysis/ml/v1/anomaly_scores_*.csv full-precision window rows",
            "rounded_table_1_used_for_statistics": False,
        },
        "baseline_interpretation": {
            "idle_rdi_claim": "in-sample calibration prevalence, not independent baseline stability proof",
            "held_out_baseline_outputs_present": minimum_validation["status"] == "OK",
            "held_out_baseline_possible_by_app": heldout_possible,
            "held_out_baseline_note": (
                "Leave-one-baseline-run-out validation is reported in the minimum_validation package; "
                "canonical primary RDI remains baseline-calibrated and should not be described as independent baseline proof."
                if minimum_validation["status"] == "OK"
                else "Multiple baseline runs make held-out evaluation possible for some apps, but the current canonical output scores use baseline-only training/calibration and do not include leave-one-run-out held-out baseline tables."
            ),
        },
        "interaction_label_policy": {
            "label_counts": dict(label_counts),
            "scripted_manual_primary_table_included": False,
            "reason": (
                "omitted from primary results by policy; the v2 package is phase-focused "
                "and does not make scripted/manual subtype claims"
            ),
        },
        "ocsvm_secondary_appendix": {
            "calibration_warning_count": len(ocsvm_warning_rows),
            "path": "paper2_ocsvm_calibration_warnings_v2.csv",
            "interpretation": "OC-SVM is retained only as a secondary robustness appendix because baseline calibration warnings are present.",
        },
    }


def _read_minimum_validation_status(*, output_root: Path, expected_apps: int) -> dict[str, Any]:
    validation_dir = Path(output_root) / "minimum_validation"
    summary_path = validation_dir / "summary.json"
    required_files = [
        "heldout_baseline_folds_v2.csv",
        "heldout_baseline_by_app_v2.csv",
        "heldout_baseline_summary_v2.csv",
        "feature_ablation_v2.csv",
        "feature_ablation_by_app_v2.csv",
        "bytes_p95_control_by_app_v2.csv",
        "bytes_p95_control_summary_v2.csv",
        "seed_stability_by_app_v2.csv",
        "seed_stability_by_seed_v2.csv",
        "seed_stability_summary_v2.csv",
        "paper2_temporal_order_control_v2.csv",
        "paper2_temporal_order_control_v2.json",
        "paper2_minimum_validation_tables_v2.tex",
        "manifest.sha256.json",
    ]
    if not summary_path.exists():
        return {
            "status": "MISSING",
            "path": str(summary_path),
            "reason": "minimum validation package has not been generated",
            "required_files": required_files,
        }
    try:
        summary = _read_json(summary_path)
    except Exception as exc:  # pragma: no cover - defensive corruption path
        return {
            "status": "BLOCKED",
            "path": str(summary_path),
            "reason": f"minimum validation summary is unreadable: {exc}",
            "required_files": required_files,
        }
    missing_files = [name for name in required_files if not (validation_dir / name).exists()]
    checks = {
        "summary_status_ok": str(summary.get("status") or "").upper() == "OK",
        "apps_match": int(summary.get("apps") or 0) == int(expected_apps),
        "heldout_apps_match": int(summary.get("heldout_eligible_apps") or 0) == int(expected_apps),
        "seed_count_at_least_20": int(summary.get("seed_count") or 0) >= 20,
        "required_files_present": not missing_files,
    }
    status = "OK" if all(checks.values()) else "BLOCKED"
    return {
        "status": status,
        "path": str(summary_path),
        "checks": checks,
        "missing_files": missing_files,
        "apps": summary.get("apps"),
        "heldout_eligible_apps": summary.get("heldout_eligible_apps"),
        "heldout_fold_count": summary.get("heldout_fold_count"),
        "seed_count": summary.get("seed_count"),
        "bytes_control_positive_apps": summary.get("bytes_control_positive_apps"),
        "feature_ablation_profiles": summary.get("feature_ablation_profiles"),
        "temporal_order_status": summary.get("temporal_order_status"),
    }


def _aggregation_policy_text() -> dict[str, str]:
    return {
        "primary": "pooled_window_weighted Isolation Forest app-level RDI",
        "primary_reason": "Uses full-precision per-window scores across all locked runs while preserving one paired app-level baseline and interactive value for inference.",
        "equal_run_sensitivity": "Averages each run's RDI equally before app-level pairing so long runs do not dominate.",
        "standard_duration_only_sensitivity": "Restricts to 4 to under 8 minute runs to check whether extended, long observation, or soak runs drive the result.",
        "long_run_policy": "Standard, extended, long observation, and soak runs are included in the primary locked-dataset analysis and disclosed through run-tier sensitivity tables.",
    }


def _selection_flow_summary(*, freeze: Mapping[str, Any], excluded_run_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    reason_counts = Counter(str(row.get("exclusion_reason") or "unknown") for row in excluded_run_rows)
    selected_contracts = freeze.get("selected_run_contracts") or {}
    return {
        "anchor": "locked 14-day selected build groups",
        "source_dataset_plan": freeze.get("source_dataset_plan"),
        "included_run_ids": len(freeze.get("included_run_ids") or []),
        "excluded_run_rows": len(excluded_run_rows),
        "excluded_reason_counts": dict(sorted(reason_counts.items())),
        "selected_run_contract_count": len(selected_contracts) if isinstance(selected_contracts, Mapping) else 0,
        "selected_build_group_policy": "do not mix baseline and interactive runs across app builds",
    }


def _deterministic_manifest_fields(
    *,
    freeze: Mapping[str, Any],
    dataset_plan: Mapping[str, Any],
    evidence_root: Path,
    excluded_run_rows: Sequence[Mapping[str, Any]],
    static_alignment_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    included_run_ids = sorted(str(run_id) for run_id in freeze.get("included_run_ids") or [])
    plan_runs = _index_plan_runs(dataset_plan)
    included_plan_runs = [plan_runs.get(run_id, {}) for run_id in included_run_ids]
    starts = sorted(str(run.get("started_at") or "") for run in included_plan_runs if run.get("started_at"))
    ends = sorted(str(run.get("ended_at") or "") for run in included_plan_runs if run.get("ended_at"))
    score_hashes: dict[str, dict[str, str | None]] = {}
    feature_hashes: dict[str, str | None] = {}
    model_manifest_hashes: dict[str, str | None] = {}
    ml_config_fingerprints: dict[str, str] = {}
    feature_schema_versions: set[str] = set()
    for run_id in included_run_ids:
        ml_dir = evidence_root / run_id / "analysis" / "ml" / "v1"
        score_hashes[run_id] = {
            "iforest": _sha256_optional(ml_dir / "anomaly_scores_iforest.csv"),
            "ocsvm": _sha256_optional(ml_dir / "anomaly_scores_ocsvm.csv"),
        }
        feature_hashes[run_id] = _sha256_optional(evidence_root / run_id / "analysis" / "pcap_features.json")
        model_manifest_path = ml_dir / "model_manifest.json"
        model_manifest_hashes[run_id] = _sha256_optional(model_manifest_path)
        manifest = _read_json_or_empty(model_manifest_path)
        if manifest.get("ml_config_fingerprint"):
            ml_config_fingerprints[run_id] = str(manifest.get("ml_config_fingerprint"))
        if manifest.get("feature_schema_version"):
            feature_schema_versions.add(str(manifest.get("feature_schema_version")))
    static_source_hashes = {
        "static_posture_scores": _hash_jsonable(_compute_static_posture_score_rows(freeze=freeze, evidence_root=evidence_root)),
        "static_alignment_rows_hash": _hash_jsonable(static_alignment_rows),
    }
    return {
        "dataset_lock_id": str(freeze.get("freeze_dataset_hash") or ""),
        "dataset_lock_sha256": str(freeze.get("freeze_dataset_hash") or ""),
        "lock_window_started_at": starts[0] if starts else "",
        "lock_window_ended_at": ends[-1] if ends else "",
        "selected_build_policy_version": str(freeze.get("freeze_contract_version") or freeze.get("freeze_dataset_identity_version") or ""),
        "ml_scoring_run_id": _hash_jsonable({"score_hashes": score_hashes, "model_manifest_hashes": model_manifest_hashes}),
        "feature_contract_hash": _hash_jsonable(
            {
                "feature_schema_versions": sorted(feature_schema_versions),
                "feature_hashes": feature_hashes,
            }
        ),
        "model_parameter_hash": _hash_jsonable(ml_config_fingerprints),
        "score_file_hashes": score_hashes,
        "included_run_set_hash": _hash_jsonable(included_run_ids),
        "exclusion_set_hash": _hash_jsonable(excluded_run_rows),
        "static_source_hashes": static_source_hashes,
    }


def _read_score_metrics(path: Path) -> ScoreMetrics:
    if not path.exists():
        return ScoreMetrics(windows=0, anomalous_windows=0, rdi=None)
    windows = 0
    anomalous = 0
    threshold: float | None = None
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            windows += 1
            if _truthy(row.get("is_anomalous") or row.get("is_exceedance")):
                anomalous += 1
            if threshold is None:
                threshold = _float_or_none(row.get("threshold"))
    return ScoreMetrics(
        windows=windows,
        anomalous_windows=anomalous,
        rdi=(anomalous / windows if windows else None),
        threshold=threshold,
    )


def _index_plan_runs(dataset_plan: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    out: dict[str, Mapping[str, Any]] = {}
    apps = dataset_plan.get("apps") or {}
    if isinstance(apps, Mapping):
        for app in apps.values():
            for run in app.get("runs") or []:
                run_id = str(run.get("run_id") or "")
                if run_id:
                    out[run_id] = run
    return out


def _read_static_scores(*, freeze: Mapping[str, Any], evidence_root: Path) -> dict[str, float]:
    scores: dict[str, float] = {}
    for row in _compute_static_posture_score_rows(freeze=freeze, evidence_root=evidence_root):
        value = _float_or_none(row.get("static_posture_score"))
        if row["package_name"] and value is not None and "missing_plan" not in str(row.get("notes") or ""):
            scores[str(row["package_name"])] = value
    return scores


def _compute_static_posture_score_rows(*, freeze: Mapping[str, Any], evidence_root: Path) -> list[dict[str, Any]]:
    """Compute context-only static posture scores from locked freeze inputs."""

    raw: list[tuple[str, int, int, int, float, list[str]]] = []
    for package_name, app in sorted((freeze.get("apps") or {}).items()):
        baseline_run_ids = [str(run_id) for run_id in app.get("baseline_run_ids") or []]
        baseline_run_id = baseline_run_ids[0] if baseline_run_ids else ""
        if not baseline_run_id:
            raw.append((str(package_name), 0, 0, 0, 0.0, ["missing_baseline_run"]))
            continue
        plan_path = evidence_root / baseline_run_id / "inputs" / "static_dynamic_plan.json"
        if not plan_path.exists():
            raw.append((str(package_name), 0, 0, 0, 0.0, ["missing_plan"]))
            continue
        obj = _read_json_or_empty(plan_path)
        notes: list[str] = []

        exported_components = obj.get("exported_components") if isinstance(obj.get("exported_components"), dict) else {}
        exported_total = exported_components.get("total")
        if exported_total is None:
            exported_total = sum(len(exported_components.get(key) or []) for key in ("activities", "services", "receivers", "providers"))
            notes.append("exported_missing")

        permissions = obj.get("permissions") if isinstance(obj.get("permissions"), dict) else {}
        dangerous_permissions = permissions.get("dangerous")
        if isinstance(dangerous_permissions, list):
            dangerous_count = len(dangerous_permissions)
        else:
            dangerous_count = 0
            notes.append("dangerous_perms_missing")

        risk_flags = obj.get("risk_flags") if isinstance(obj.get("risk_flags"), dict) else {}
        cleartext_flag = 1 if risk_flags.get("uses_cleartext_traffic") is True else 0

        sdk_score = 0.0
        sdk_indicators = obj.get("sdk_indicators") if isinstance(obj.get("sdk_indicators"), dict) else None
        if isinstance(sdk_indicators, dict) and sdk_indicators.get("score") is not None:
            try:
                sdk_score = float(sdk_indicators.get("score") or 0.0)
            except Exception:
                sdk_score = 0.0
                notes.append("sdk_indicators_invalid")
        else:
            notes.append("sdk_indicators_missing")

        raw.append((str(package_name), int(exported_total or 0), int(dangerous_count or 0), cleartext_flag, sdk_score, notes))

    exported_values = [row[1] for row in raw]
    dangerous_values = [row[2] for row in raw]
    exported_min, exported_max = (min(exported_values), max(exported_values)) if exported_values else (0, 0)
    dangerous_min, dangerous_max = (min(dangerous_values), max(dangerous_values)) if dangerous_values else (0, 0)

    rows: list[dict[str, Any]] = []
    for package_name, exported_total, dangerous_count, cleartext_flag, sdk_score, notes in raw:
        exported_norm = (
            float(exported_total - exported_min) / float(exported_max - exported_min)
            if exported_max > exported_min
            else 0.0
        )
        dangerous_norm = (
            float(dangerous_count - dangerous_min) / float(dangerous_max - dangerous_min)
            if dangerous_max > dangerous_min
            else 0.0
        )
        static_posture_score = 100.0 * (
            0.25 * exported_norm
            + 0.25 * dangerous_norm
            + 0.25 * float(cleartext_flag)
            + 0.25 * float(sdk_score)
        )
        rows.append(
            {
                "package_name": package_name,
                "exported_components": exported_total,
                "dangerous_permissions": dangerous_count,
                "cleartext_flag": cleartext_flag,
                "sdk_score": sdk_score,
                "exported_norm": exported_norm,
                "dangerous_norm": dangerous_norm,
                "static_posture_score": static_posture_score,
                "notes": ";".join(notes),
            }
        )
    return rows


def _read_ocsvm_calibration_warnings() -> list[dict[str, Any]]:
    path = REPO_ROOT / "output" / "publication" / "qa" / "ml_audit_report_v1.json"
    if not path.exists():
        return []
    payload = _read_json(path)
    rows: list[dict[str, Any]] = []
    for row in payload.get("baseline_calibration") or []:
        if row.get("model") != "one_class_svm":
            continue
        if bool(row.get("baseline_exceedance_ok")):
            continue
        rows.append(
            {
                "package_name": row.get("package_name", ""),
                "display_name": APP_LABELS.get(str(row.get("package_name") or ""), str(row.get("package_name") or "")),
                "model": row.get("model", ""),
                "baseline_run_count": row.get("baseline_run_count", ""),
                "baseline_scores_n": row.get("baseline_scores_n", ""),
                "baseline_exceedance_ratio": _float_str(row.get("baseline_exceedance_ratio")),
                "baseline_expected_exceedance": _float_str(row.get("baseline_expected_exceedance")),
                "baseline_exceedance_abs_error": _float_str(row.get("baseline_exceedance_abs_error")),
                "threshold_value": _float_str(row.get("threshold_value")),
                "warning": "OC-SVM baseline calibration outside expected exceedance tolerance",
            }
        )
    return rows


def _write_figures(figures_dir: Path, per_app_rows: Sequence[Mapping[str, Any]]) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = sorted(per_app_rows, key=lambda r: float(r["if_delta_rdi"]))
    labels = [str(r["display_name"]) for r in rows]
    deltas = [float(r["if_delta_rdi"]) for r in rows]
    fig, ax = plt.subplots(figsize=(9.5, 5.2))
    ax.barh(labels, deltas, color="#2878b5")
    ax.set_xlabel("Interactive RDI - baseline RDI")
    ax.set_title("Per-app Runtime Deviation Shift (Isolation Forest)")
    ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    png = figures_dir / "paper2_delta_sorted_v2.png"
    fig.savefig(png, dpi=240)
    plt.close(fig)

    source = figures_dir / "paper2_delta_sorted_v2_source.csv"
    _write_csv(source, rows)
    return [png, source]


def _write_latex_statistics(path: Path, statistics_rows: Sequence[Mapping[str, Any]], sensitivity_rows: Sequence[Mapping[str, Any]]) -> Path:
    primary = [
        row
        for row in sensitivity_rows
        if row.get("model") == PRIMARY_MODEL and row.get("aggregation_policy") == "pooled_window_weighted"
    ][0]
    lines = [
        "% Auto-generated by paper2_results_v2_service.py; do not edit by hand.",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Paper 2 v2 runtime deviation statistics (Isolation Forest primary).}",
        "\\begin{tabular}{lr}",
        "\\hline",
        "Metric & Value \\\\",
        "\\hline",
        f"Apps & {primary['included_apps']} \\\\",
        f"Baseline runs & {primary['baseline_runs']} \\\\",
        f"Interactive runs & {primary['interactive_runs']} \\\\",
        f"Median baseline RDI & {float(primary['baseline_median_rdi']):.6f} \\\\",
        f"Median interactive RDI & {float(primary['interactive_median_rdi']):.6f} \\\\",
        f"Median $\\Delta$RDI & {float(primary['delta_median']):.6f} \\\\",
        f"Wilcoxon $p$ (two-sided exact) & {float(primary['wilcoxon_p_two_sided']):.8f} \\\\",
        f"Cohen's $d_z$ & {float(primary['cohens_dz']):.3f} \\\\",
        f"Rank-biserial & {float(primary['rank_biserial']):.3f} \\\\",
        "\\hline",
        "\\end{tabular}",
        "\\label{tab:paper2-v2-runtime-stats}",
        "\\end{table}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _write_hash_manifest(path: Path, files: Sequence[Path], *, base_dir: Path | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    base = Path(base_dir) if base_dir is not None else None
    for file in files:
        if file.exists():
            try:
                display_path = str(file.relative_to(base)) if base is not None else str(file)
            except ValueError:
                display_path = str(file)
            rows.append({"path": display_path, "sha256": _sha256(file), "bytes": file.stat().st_size})
    path.write_text(json.dumps({"schema_version": "paper2_results_v2_hash_manifest", "files": rows}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_generation_receipt(
    path: Path,
    *,
    freeze_path: Path,
    dataset_plan_path: Path,
    evidence_root: Path,
    output_root: Path,
    hash_manifest: Path,
    qa: Mapping[str, Any],
) -> Path:
    payload = {
        "schema_version": "paper2_results_v2_generation_receipt",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_path": str(freeze_path),
        "freeze_sha256": _sha256(freeze_path),
        "dataset_plan_path": str(dataset_plan_path),
        "dataset_plan_sha256": _sha256(dataset_plan_path) if dataset_plan_path.exists() else None,
        "evidence_root": str(evidence_root),
        "output_root": str(output_root),
        "hash_manifest": str(hash_manifest),
        "hash_manifest_sha256": _sha256(hash_manifest),
        "qa_status": qa.get("status"),
        "qa_warning_count": qa.get("warning_count"),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        content = "".join(line for line in fh if not line.startswith("#"))
    return list(csv.DictReader(content.splitlines()))


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json_or_empty(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_optional(path: Path) -> str | None:
    return _sha256(path) if path.exists() else None


def _hash_jsonable(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _float_or_none(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _count_csv_rows(path: Path) -> int | None:
    if not path.exists():
        return None
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for row in reader if any(str(cell).strip() for cell in row))


def _package_for_run(freeze: Mapping[str, Any], run_id: str) -> str:
    for package_name, app in (freeze.get("apps") or {}).items():
        if run_id in {str(rid) for rid in app.get("included_run_ids") or []}:
            return str(package_name)
    return ""


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _float_str(value: Any) -> str:
    if value is None or value == "":
        return ""
    try:
        return format(float(value), ".17g")
    except (TypeError, ValueError):
        return str(value)


def _cohens_dz(values: Sequence[float]) -> float | None:
    vals = [float(v) for v in values if math.isfinite(float(v))]
    if len(vals) < 2:
        return None
    sd = statistics.stdev(vals)
    return statistics.fmean(vals) / sd if sd else None


def _bootstrap_dz_ci(values: Sequence[float]) -> tuple[float | None, float | None]:
    vals = np.asarray([float(v) for v in values if math.isfinite(float(v))], dtype=float)
    if len(vals) < 2:
        return None, None
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    boots = []
    for _ in range(BOOTSTRAP_N):
        sample = rng.choice(vals, size=len(vals), replace=True)
        sd = float(np.std(sample, ddof=1))
        if sd:
            boots.append(float(np.mean(sample) / sd))
    if not boots:
        return None, None
    return tuple(float(x) for x in np.percentile(boots, [2.5, 97.5]))


def _bootstrap_spearman_ci(xs: Sequence[float], ys: Sequence[float]) -> tuple[float | None, float | None]:
    x = np.asarray(xs, dtype=float)
    y = np.asarray(ys, dtype=float)
    if len(x) < 3:
        return None, None
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    boots = []
    for _ in range(BOOTSTRAP_N):
        idx = rng.integers(0, len(x), len(x))
        if len(set(x[idx])) < 2 or len(set(y[idx])) < 2:
            continue
        rho = stats.spearmanr(x[idx], y[idx]).statistic
        if math.isfinite(float(rho)):
            boots.append(float(rho))
    if not boots:
        return None, None
    return tuple(float(v) for v in np.percentile(boots, [2.5, 97.5]))


__all__ = ["generate_paper2_results_v2"]
