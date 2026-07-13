"""Paper 2 v2 runtime ML results package writer.

This writer is intentionally separate from the older publication export path,
which encoded the original 12-app/36-run contract.  The v2 package is built
from the locked dataset freeze and per-window ML score files so statistical
results are not derived from rounded publication tables.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
from scipy import stats

from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_freeze_read_path
from scytaledroid.DynamicAnalysis.run_duration_tiers import classify_duration_tier

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVIDENCE_ROOT = REPO_ROOT / "data" / "evidence" / "dynamic"
DEFAULT_DATASET_PLAN = REPO_ROOT / "data" / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_plan.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "_internal" / "publication" / "paper2_v2"
LEGACY_EXPORT_SERVICE = REPO_ROOT / "scytaledroid" / "Reporting" / "services" / "publication_exports_service.py"
LEGACY_QA_SERVICE = REPO_ROOT / "scytaledroid" / "Reporting" / "services" / "publication_scientific_qa_service.py"

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
    static_scores = _read_static_scores()
    run_records, qa_warnings = _build_run_metrics(
        freeze=freeze,
        dataset_plan=dataset_plan,
        evidence_root=evidence_root,
    )
    per_app_rows = _build_per_app_rows(freeze=freeze, run_records=run_records, static_scores=static_scores)
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

    legacy_contract = _audit_legacy_contract()
    qa = _build_qa(
        freeze=freeze,
        run_records=run_records,
        per_app_primary=per_app_primary,
        ocsvm_warning_rows=ocsvm_warning_rows,
        qa_warnings=qa_warnings,
        legacy_contract=legacy_contract,
    )

    files: list[Path] = []
    files.append(_write_csv(output_root / "paper2_cohort_v2.csv", cohort_rows))
    files.append(_write_csv(output_root / "paper2_per_app_rdi_v2.csv", per_app_rdi_rows))
    files.append(_write_csv(output_root / "paper2_statistics_v2.csv", statistics_rows))
    files.append(_write_csv(output_root / "paper2_run_sensitivity_v2.csv", sensitivity_rows))
    files.append(_write_csv(output_root / "paper2_ocsvm_calibration_warnings_v2.csv", ocsvm_warning_rows))
    files.append(_write_latex_statistics(output_root / "paper2_statistics_v2.tex", statistics_rows, sensitivity_rows))
    files.extend(_write_figures(figures_dir, per_app_rdi_rows))

    publication_results = {
        "schema_version": "paper2_results_v2",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_path": str(freeze_path),
        "freeze_sha256": _sha256(freeze_path),
        "dataset_plan_path": str(dataset_plan_path),
        "dataset_plan_sha256": _sha256(dataset_plan_path) if dataset_plan_path.exists() else None,
        "evidence_root": str(evidence_root),
        "output_root": str(output_root),
        "dataset": {
            "apps": len(freeze.get("apps") or {}),
            "included_runs": len(freeze.get("included_run_ids") or []),
            "window": "14-day selected build groups",
            "run_duration_tiers": dict(Counter(r.duration_tier_label for r in run_records)),
        },
        "aggregation_policy": _aggregation_policy_text(),
        "primary_result": results_by_policy.get(f"{PRIMARY_MODEL}:{primary_policy}"),
        "sensitivity": results_by_policy,
        "legacy_pipeline_reconciliation": legacy_contract,
        "generated_files": [],
    }
    results_path = output_root / "publication_results_v2.json"
    results_path.write_text(json.dumps(publication_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(results_path)

    qa_path = output_root / "paper2_qa_v2.json"
    qa_path.write_text(json.dumps(qa, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(qa_path)

    hash_manifest = _write_hash_manifest(manifest_dir / "paper2_results_v2_manifest.json", files)
    publication_results["generated_files"] = [str(p.relative_to(output_root)) for p in files]
    publication_results["hash_manifest"] = str(hash_manifest.relative_to(output_root))
    results_path.write_text(json.dumps(publication_results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_hash_manifest(manifest_dir / "paper2_results_v2_manifest.json", files)

    return {
        "output_root": str(output_root),
        "publication_results_v2": str(results_path),
        "paper2_qa_v2": str(qa_path),
        "hash_manifest": str(hash_manifest),
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
        "static_score_source": "output/_internal/publication/baseline/tables/table_6_static_posture_scores.csv",
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
    freeze: Mapping[str, Any],
    run_records: Sequence[RunMetric],
    per_app_primary: Mapping[str, Mapping[str, Any]],
    ocsvm_warning_rows: Sequence[Mapping[str, Any]],
    qa_warnings: Sequence[str],
    legacy_contract: Mapping[str, Any],
) -> dict[str, Any]:
    app_count = len(freeze.get("apps") or {})
    run_count = len(run_records)
    label_counts = Counter(r.interaction_level or "unknown" for r in run_records)
    heldout_possible = {
        pkg: bool(vals.get("baseline_runs", 0) >= 2)
        for pkg, vals in per_app_primary.items()
    }
    warnings = list(qa_warnings)
    if legacy_contract.get("contains_36_run_guard"):
        warnings.append("legacy publication_exports_service contains 36-run guard and is retired for Paper 2 v2")
    if label_counts.get("unknown", 0):
        warnings.append("scripted/manual primary table omitted because interaction labels include unknown values")
    status = "OK" if not [w for w in warnings if not w.startswith("scripted/manual")] else "OK_WITH_WARNINGS"
    return {
        "schema_version": "paper2_qa_v2",
        "status": status,
        "warning_count": len(warnings),
        "warnings": warnings,
        "cohort": {
            "apps": app_count,
            "included_runs": run_count,
            "expected_apps": 15,
            "expected_runs_current_lock": 112,
            "apps_with_primary_rdi_pairs": len(per_app_primary),
        },
        "score_source_policy": {
            "rdi_source": "per-run analysis/ml/v1/anomaly_scores_*.csv full-precision window rows",
            "rounded_table_1_used_for_statistics": False,
        },
        "baseline_interpretation": {
            "idle_rdi_claim": "in-sample calibration prevalence, not independent baseline stability proof",
            "held_out_baseline_outputs_present": False,
            "held_out_baseline_possible_by_app": heldout_possible,
            "held_out_baseline_note": "Multiple baseline runs make held-out evaluation possible for some apps, but the current canonical output scores use baseline-only training/calibration and do not include leave-one-run-out held-out baseline tables.",
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
        "legacy_pipeline_reconciliation": legacy_contract,
    }


def _aggregation_policy_text() -> dict[str, str]:
    return {
        "primary": "pooled_window_weighted Isolation Forest app-level RDI",
        "primary_reason": "Uses full-precision per-window scores across all locked runs while preserving one paired app-level baseline and interactive value for inference.",
        "equal_run_sensitivity": "Averages each run's RDI equally before app-level pairing so long runs do not dominate.",
        "standard_duration_only_sensitivity": "Restricts to 4 to under 8 minute runs to check whether extended, long observation, or soak runs drive the result.",
        "long_run_policy": "Standard, extended, long observation, and soak runs are included in the primary locked-dataset analysis and disclosed through run-tier sensitivity tables.",
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


def _read_static_scores() -> dict[str, float]:
    path = REPO_ROOT / "output" / "_internal" / "publication" / "baseline" / "tables" / "table_6_static_posture_scores.csv"
    scores: dict[str, float] = {}
    if not path.exists():
        return scores
    for row in _read_csv_rows(path):
        pkg = str(row.get("package_name") or "")
        value = _float_or_none(row.get("static_posture_score"))
        if pkg and value is not None:
            scores[pkg] = value
    return scores


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


def _audit_legacy_contract() -> dict[str, Any]:
    findings = {}
    for name, path in (("publication_exports_service", LEGACY_EXPORT_SERVICE), ("publication_scientific_qa_service", LEGACY_QA_SERVICE)):
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        findings[name] = {
            "path": str(path),
            "exists": path.exists(),
            "contains_36_run_guard": "expected 36" in text or "len(included_run_ids) != 36" in text,
        }
    return {
        "status": "retired_for_paper2_v2" if any(v["contains_36_run_guard"] for v in findings.values()) else "generalized_or_absent",
        "contains_36_run_guard": any(v["contains_36_run_guard"] for v in findings.values()),
        "services": findings,
        "canonical_v2_writer": "scytaledroid.Reporting.services.paper2_results_v2_service.generate_paper2_results_v2",
    }


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


def _write_hash_manifest(path: Path, files: Sequence[Path]) -> Path:
    rows = []
    for file in files:
        if file.exists():
            rows.append({"path": str(file), "sha256": _sha256(file), "bytes": file.stat().st_size})
    path.write_text(json.dumps({"generated_at_utc": datetime.now(UTC).isoformat(), "files": rows}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _float_or_none(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


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
