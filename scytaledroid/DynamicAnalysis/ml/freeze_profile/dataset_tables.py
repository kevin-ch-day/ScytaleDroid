"""Dataset-level ML reporting tables for freeze-profile runs."""

from __future__ import annotations

import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.run_duration_tiers import classify_duration_tier

from .. import ml_parameters_profile as config
from ..evidence_pack_ml_preflight import RunInputs
from ..numpy_percentile import percentile as np_percentile
from ..operational_risk import build_static_inputs_from_plan


def fallback_phase(run_profile: str | None) -> str:
    if not run_profile:
        return "interactive"
    p = run_profile.lower()
    if "baseline" in p or "idle" in p:
        return "idle"
    return "interactive"


def run_duration_seconds(run_inputs: RunInputs) -> float | None:
    summary = run_inputs.summary if isinstance(run_inputs.summary, dict) else {}
    telemetry = summary.get("telemetry") if isinstance(summary.get("telemetry"), dict) else {}
    stats = telemetry.get("stats") if isinstance(telemetry.get("stats"), dict) else {}
    for value in (
        stats.get("sampling_duration_seconds"),
        stats.get("duration_seconds"),
    ):
        resolved = safe_float(value)
        if resolved is not None and resolved >= 0:
            return resolved
    ds = run_inputs.manifest.get("dataset") if isinstance(run_inputs.manifest.get("dataset"), dict) else {}
    for value in (
        ds.get("sampling_duration_seconds"),
        ds.get("actual_duration_seconds"),
        ds.get("duration_seconds"),
    ):
        resolved = safe_float(value)
        if resolved is not None and resolved >= 0:
            return resolved
    return None


def compute_phase_rows(
    *,
    identity_key: str,
    package_name: str,
    app_runs: list[RunInputs],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
    per_run_phase: dict[str, str],
    per_run_tag: dict[str, str | None],
    training_mode: str,
    per_run_empty_windows: dict[str, int],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for model_name, scores_by_run in per_model_scores_by_run.items():
        threshold = float(per_model_thresholds.get(model_name) or 0.0)
        for r in app_runs:
            run_scores = scores_by_run.get(r.run_id) or []
            if not run_scores:
                continue
            arr = np.asarray(run_scores, dtype=float)
            phase = per_run_phase.get(r.run_id) or fallback_phase(r.run_profile)
            tag = per_run_tag.get(r.run_id) or ""
            ds = r.manifest.get("dataset") if isinstance(r.manifest.get("dataset"), dict) else {}
            duration_s = run_duration_seconds(r)
            duration_tier = classify_duration_tier(duration_s)
            anomalous = int(sum(1 for s in run_scores if float(s) >= threshold))
            rows.append(
                {
                    "identity_key": identity_key,
                    "package_name": package_name,
                    "run_id": r.run_id,
                    "phase": phase,
                    "interaction_tag": tag,
                    "duration_s": duration_s,
                    "duration_tier": duration_tier.key,
                    "duration_tier_label": duration_tier.label,
                    "model": model_name,
                    "training_mode": training_mode,
                    "is_fallback_mode": bool(training_mode == "union_fallback"),
                    "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
                    "windows_total": int(arr.shape[0]),
                    "empty_windows": int(per_run_empty_windows.get(r.run_id, 0)),
                    "empty_windows_pct": (
                        float(per_run_empty_windows.get(r.run_id, 0)) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0
                    ),
                    "median": float(statistics.median(run_scores)),
                    "p95": float(np_percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)),
                    "max": float(np.max(arr)),
                    "anomalous_windows": anomalous,
                    "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                    "threshold_value": float(threshold),
                    "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )
    return rows


def compute_dars_component_rows(
    *,
    package_name: str,
    app_runs: list[RunInputs],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
    per_run_phase: dict[str, str],
    per_run_tag: dict[str, str | None],
    training_mode: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for model_name, scores_by_run in per_model_scores_by_run.items():
        tau = float(per_model_thresholds.get(model_name) or 0.0)
        for r in app_runs:
            run_scores = scores_by_run.get(r.run_id) or []
            n = int(len(run_scores))
            if n <= 0:
                continue
            exceed_n = int(sum(1 for s in run_scores if float(s) >= tau))
            exceed_ratio = float(exceed_n) / float(n)
            k = int(max(1, math.ceil(0.10 * float(n))))
            topk = sorted((float(s) for s in run_scores), reverse=True)[:k]
            topk_mean = float(sum(topk) / float(len(topk))) if topk else 0.0
            if tau > 0.0:
                severity_ratio = float(topk_mean / tau)
                dars = float(
                    100.0
                    * max(
                        0.0,
                        min(
                            1.0,
                            0.5 * exceed_ratio + 0.5 * max(0.0, min(1.0, severity_ratio / 2.0)),
                        ),
                    )
                )
            else:
                severity_ratio = None
                dars = float(100.0 * max(0.0, min(1.0, 0.5 * exceed_ratio)))
            phase = per_run_phase.get(r.run_id) or fallback_phase(r.run_profile)
            rows.append(
                {
                    "package_name": package_name,
                    "run_id": r.run_id,
                    "phase": phase,
                    "interaction_tag": per_run_tag.get(r.run_id) or "",
                    "model": model_name,
                    "training_mode": training_mode,
                    "windows_total_n": n,
                    "threshold_tau": tau,
                    "operator": ">=",
                    "exceedance_n": exceed_n,
                    "exceedance_ratio": exceed_ratio,
                    "top_k_policy": "ceil_10pct_n",
                    "top_k_value": int(k),
                    "top_k_mean_score": topk_mean,
                    "severity_ratio": severity_ratio,
                    "dars_v1": dars,
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )
    return rows


def extract_static_snapshot(app_runs: list[RunInputs]) -> dict[str, Any]:
    baseline = next((r for r in app_runs if fallback_phase(r.run_profile) == "idle"), None)
    ref = baseline or (app_runs[0] if app_runs else None)
    if not ref:
        return {}
    plan = ref.plan if isinstance(ref.plan, dict) else {}
    static_inputs = build_static_inputs_from_plan(plan)
    out: dict[str, Any] = {}
    if static_inputs is not None:
        out.update(
            {
                "exported_components_total": int(static_inputs.exported_components_total),
                "dangerous_permission_count": int(static_inputs.dangerous_permission_count),
                "uses_cleartext_traffic": int(static_inputs.uses_cleartext_traffic),
                "sdk_indicator_score": float(static_inputs.sdk_indicator_score),
            }
        )
    static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
    out["masvs_total_score"] = safe_float(static_features.get("masvs_total_score"))
    out["static_risk_score"] = safe_float(static_features.get("static_risk_score"))
    out["static_risk_band"] = (
        str(static_features.get("static_risk_band") or "").strip() or None
        if isinstance(static_features, dict)
        else None
    )
    return out


def compute_static_dynamic_stratification_row(
    *,
    package_name: str,
    static_snapshot: dict[str, Any],
    dars_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    if_rows = [
        r
        for r in dars_rows
        if str(r.get("model") or "") == config.MODEL_IFOREST
        and str(r.get("phase") or "").lower().startswith("interactive")
    ]
    dars_interactive_mean = None
    dars_interactive_max = None
    exceed_interactive_mean = None
    if if_rows:
        dars_vals = [float(r.get("dars_v1") or 0.0) for r in if_rows]
        ex_vals = [float(r.get("exceedance_ratio") or 0.0) for r in if_rows]
        dars_interactive_mean = float(sum(dars_vals) / float(len(dars_vals)))
        dars_interactive_max = float(max(dars_vals))
        exceed_interactive_mean = float(sum(ex_vals) / float(len(ex_vals)))
    return {
        "package_name": package_name,
        "masvs_total_score": static_snapshot.get("masvs_total_score"),
        "static_risk_score": static_snapshot.get("static_risk_score"),
        "static_risk_band": static_snapshot.get("static_risk_band"),
        "exported_components_total": static_snapshot.get("exported_components_total"),
        "dangerous_permission_count": static_snapshot.get("dangerous_permission_count"),
        "uses_cleartext_traffic": static_snapshot.get("uses_cleartext_traffic"),
        "sdk_indicator_score": static_snapshot.get("sdk_indicator_score"),
        "interactive_iforest_runs": int(len(if_rows)),
        "interactive_iforest_exceedance_mean": exceed_interactive_mean,
        "interactive_iforest_dars_mean": dars_interactive_mean,
        "interactive_iforest_dars_max": dars_interactive_max,
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
    }


def compute_baseline_stability_rows(
    *,
    package_name: str,
    baseline_run_ids: list[str],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
    training_mode: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for model_name, scores_by_run in per_model_scores_by_run.items():
        base_scores = [
            float(s)
            for rid in baseline_run_ids
            for s in (scores_by_run.get(str(rid)) or [])
        ]
        n = int(len(base_scores))
        if n <= 0:
            continue
        arr = np.asarray(base_scores, dtype=float)
        mean_v = float(np.mean(arr))
        std_v = float(np.std(arr))
        cv_v = (std_v / abs(mean_v)) if abs(mean_v) > 1e-12 else None
        tau = float(per_model_thresholds.get(model_name) or 0.0)
        rows.append(
            {
                "package_name": package_name,
                "model": model_name,
                "training_mode": training_mode,
                "baseline_run_id": ",".join(str(rid) for rid in baseline_run_ids),
                "baseline_run_count": int(len(baseline_run_ids)),
                "baseline_windows_n": n,
                "baseline_score_mean": mean_v,
                "baseline_score_std": std_v,
                "baseline_score_cv": cv_v,
                "baseline_score_p95": float(np_percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)),
                "baseline_score_min": float(np.min(arr)),
                "baseline_score_max": float(np.max(arr)),
                "threshold_tau": tau,
                "tau_minus_mean": float(tau - mean_v),
                "tau_over_mean_abs": (float(tau / abs(mean_v)) if abs(mean_v) > 1e-12 else None),
                "ml_schema_version": int(config.ML_SCHEMA_VERSION),
            }
        )
    return rows


def write_prevalence_csvs(rows: list[dict[str, Any]]) -> None:
    """Write dataset-level anomaly prevalence tables."""
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    main_path = out_dir / "anomaly_prevalence_per_app_phase.csv"
    appendix_path = out_dir / "anomaly_prevalence_per_run.csv"

    appendix_fields = [
        "identity_key",
        "package_name",
        "run_id",
        "phase",
        "interaction_tag",
        "duration_s",
        "duration_tier",
        "duration_tier_label",
        "model",
        "training_mode",
        "is_fallback_mode",
        "low_signal",
        "windows_total",
        "empty_windows",
        "empty_windows_pct",
        "median",
        "p95",
        "max",
        "anomalous_windows",
        "anomalous_pct",
        "threshold_value",
        "threshold_percentile",
        "ml_schema_version",
    ]
    with appendix_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=appendix_fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in appendix_fields})

    agg: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        pkg = str(row.get("package_name") or "").strip()
        model = str(row.get("model") or "").strip()
        if not pkg or not model:
            continue
        phase = str(row.get("phase") or "").strip().lower()
        phase2 = "idle" if phase == "idle" else "interactive"
        key = (pkg, phase2, model)
        cur = agg.get(key)
        if not cur:
            cur = {
                "package_name": pkg,
                "phase": phase2,
                "model": model,
                "windows_total": 0,
                "windows_flagged": 0,
                "empty_windows": 0,
                "training_mode": row.get("training_mode"),
                "is_fallback_mode": row.get("is_fallback_mode"),
                "ml_schema_version": row.get("ml_schema_version"),
            }
            agg[key] = cur
        try:
            cur["windows_total"] += int(row.get("windows_total") or 0)
            cur["windows_flagged"] += int(row.get("anomalous_windows") or 0)
            cur["empty_windows"] += int(row.get("empty_windows") or 0)
        except Exception:
            continue

    main_fields = [
        "package_name",
        "phase",
        "model",
        "windows_total",
        "windows_flagged",
        "empty_windows",
        "empty_windows_pct",
        "flagged_pct",
        "training_mode",
        "is_fallback_mode",
        "ml_schema_version",
    ]
    rows_out: list[dict[str, Any]] = []
    for (_, _, _), cur in sorted(agg.items(), key=lambda kv: (kv[1]["package_name"], kv[1]["phase"], kv[1]["model"])):
        total = int(cur.get("windows_total") or 0)
        flagged = int(cur.get("windows_flagged") or 0)
        pct = (float(flagged) / float(total)) if total > 0 else 0.0
        empty = int(cur.get("empty_windows") or 0)
        empty_pct = (float(empty) / float(total)) if total > 0 else 0.0
        out = dict(cur)
        out["flagged_pct"] = pct
        out["empty_windows_pct"] = empty_pct
        rows_out.append(out)
    with main_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=main_fields)
        writer.writeheader()
        for row in rows_out:
            writer.writerow({k: row.get(k) for k in main_fields})


def compute_model_overlap_rows(
    *,
    package_name: str,
    app_runs: list[RunInputs],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
    per_run_phase: dict[str, str],
    per_run_tag: dict[str, str | None],
    training_mode: str,
) -> list[dict[str, Any]]:
    if config.MODEL_IFOREST not in per_model_scores_by_run or config.MODEL_OCSVM not in per_model_scores_by_run:
        return []
    if_thr = float(per_model_thresholds.get(config.MODEL_IFOREST) or 0.0)
    oc_thr = float(per_model_thresholds.get(config.MODEL_OCSVM) or 0.0)
    rows: list[dict[str, Any]] = []
    for r in app_runs:
        if_scores = per_model_scores_by_run[config.MODEL_IFOREST].get(r.run_id) or []
        oc_scores = per_model_scores_by_run[config.MODEL_OCSVM].get(r.run_id) or []
        n = min(len(if_scores), len(oc_scores))
        if n <= 0:
            continue
        a = {i for i in range(n) if float(if_scores[i]) >= if_thr}
        b = {i for i in range(n) if float(oc_scores[i]) >= oc_thr}
        union = a.union(b)
        inter = a.intersection(b)
        jaccard = (float(len(inter)) / float(len(union))) if union else 0.0
        phase = per_run_phase.get(r.run_id) or fallback_phase(r.run_profile)
        tag = per_run_tag.get(r.run_id) or ""
        rows.append(
            {
                "package_name": package_name,
                "run_id": r.run_id,
                "phase": phase,
                "interaction_tag": tag,
                "training_mode": training_mode,
                "is_fallback_mode": bool(training_mode == "union_fallback"),
                "windows_total": int(n),
                "iforest_flagged": int(len(a)),
                "ocsvm_flagged": int(len(b)),
                "both_flagged": int(len(inter)),
                "either_flagged": int(len(union)),
                "jaccard": float(jaccard),
                "ml_schema_version": int(config.ML_SCHEMA_VERSION),
            }
        )
    return rows


def write_model_overlap_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "model_overlap_per_run.csv"
    fieldnames = [
        "package_name",
        "run_id",
        "phase",
        "interaction_tag",
        "training_mode",
        "is_fallback_mode",
        "windows_total",
        "iforest_flagged",
        "ocsvm_flagged",
        "both_flagged",
        "either_flagged",
        "jaccard",
        "ml_schema_version",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_ml_audit_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ml_audit_per_app_model.csv"
    fieldnames = [
        "package_name",
        "model",
        "training_mode",
        "training_samples",
        "training_samples_warning",
        "threshold_value",
        "threshold_percentile",
        "np_percentile_method",
        "threshold_equals_max",
        "baseline_windows",
        "baseline_pcap_bytes",
        "baseline_min_pcap_bytes",
        "baseline_pcap_bytes_ok",
        "baseline_windows_ok",
        "windows_scored",
        "windows_dropped_partial",
        "feature_transform",
        "feature_scaling",
        "ml_schema_version",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_dars_components_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "dars_components_per_run.csv"
    fieldnames = [
        "package_name",
        "run_id",
        "phase",
        "interaction_tag",
        "model",
        "training_mode",
        "windows_total_n",
        "threshold_tau",
        "operator",
        "exceedance_n",
        "exceedance_ratio",
        "top_k_policy",
        "top_k_value",
        "top_k_mean_score",
        "severity_ratio",
        "dars_v1",
        "ml_schema_version",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_baseline_stability_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "baseline_score_stability_per_app_model.csv"
    fieldnames = [
        "package_name",
        "model",
        "training_mode",
        "baseline_run_id",
        "baseline_run_count",
        "baseline_windows_n",
        "baseline_score_mean",
        "baseline_score_std",
        "baseline_score_cv",
        "baseline_score_p95",
        "baseline_score_min",
        "baseline_score_max",
        "threshold_tau",
        "tau_minus_mean",
        "tau_over_mean_abs",
        "ml_schema_version",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_static_dynamic_stratification_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "static_dynamic_stratification_per_app.csv"
    fieldnames = [
        "package_name",
        "masvs_total_score",
        "static_risk_score",
        "static_risk_band",
        "exported_components_total",
        "dangerous_permission_count",
        "uses_cleartext_traffic",
        "sdk_indicator_score",
        "interactive_iforest_runs",
        "interactive_iforest_exceedance_mean",
        "interactive_iforest_dars_mean",
        "interactive_iforest_dars_max",
        "ml_schema_version",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def compute_transport_mix_rows(
    *,
    package_name: str,
    app_runs: list[RunInputs],
    per_run_phase: dict[str, str],
    per_run_tag: dict[str, str | None],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in app_runs:
        tls, quic, tcp, udp = transport_ratios_from_inputs(r)
        phase = per_run_phase.get(r.run_id) or fallback_phase(r.run_profile)
        tag = per_run_tag.get(r.run_id) or ""
        pcap_bytes = pcap_size_bytes_from_inputs(r)
        rows.append(
            {
                "package_name": package_name,
                "run_id": r.run_id,
                "phase": phase,
                "interaction_tag": tag,
                "tls_ratio": tls,
                "quic_ratio": quic,
                "tcp_ratio": tcp,
                "udp_ratio": udp,
                "pcap_bytes": pcap_bytes,
            }
        )
    return rows


def write_transport_mix_csvs(rows: list[dict[str, Any]]) -> None:
    """Write transport mix tables."""
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    main_path = out_dir / "transport_mix_by_phase.csv"
    appendix_path = out_dir / "transport_mix_per_run.csv"

    appendix_fields = [
        "package_name",
        "run_id",
        "phase",
        "interaction_tag",
        "tls_ratio",
        "quic_ratio",
        "tcp_ratio",
        "udp_ratio",
        "pcap_bytes",
    ]
    with appendix_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=appendix_fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in appendix_fields})

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        pkg = str(row.get("package_name") or "").strip()
        if not pkg:
            continue
        phase = str(row.get("phase") or "").strip().lower()
        phase2 = "idle" if phase == "idle" else "interactive"
        groups[(pkg, phase2)].append(row)

    main_fields = [
        "package_name",
        "phase",
        "runs_in_phase",
        "weight_bytes_total",
        "tls_ratio",
        "quic_ratio",
        "tcp_ratio",
        "udp_ratio",
    ]

    def wavg(vals: list[tuple[float | None, int]]) -> float | None:
        num = 0.0
        den = 0.0
        for v, w in vals:
            if v is None:
                continue
            ww = max(int(w), 0)
            if ww <= 0:
                continue
            num += float(v) * float(ww)
            den += float(ww)
        if den > 0:
            return float(num) / float(den)
        xs = [float(v) for v, _ in vals if v is not None]
        if not xs:
            return None
        return float(sum(xs)) / float(len(xs))

    out_rows: list[dict[str, Any]] = []
    for (pkg, phase), rs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        weights = [int(r.get("pcap_bytes") or 0) for r in rs]
        weight_total = int(sum(max(w, 0) for w in weights))
        out_rows.append(
            {
                "package_name": pkg,
                "phase": phase,
                "runs_in_phase": int(len(rs)),
                "weight_bytes_total": int(weight_total),
                "tls_ratio": wavg([(safe_float(r.get("tls_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                "quic_ratio": wavg([(safe_float(r.get("quic_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                "tcp_ratio": wavg([(safe_float(r.get("tcp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                "udp_ratio": wavg([(safe_float(r.get("udp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
            }
        )
    with main_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=main_fields)
        writer.writeheader()
        for row in out_rows:
            writer.writerow({k: row.get(k) for k in main_fields})


def pcap_size_bytes_from_inputs(inputs: RunInputs) -> int | None:
    if isinstance(inputs.pcap_report, dict):
        v = inputs.pcap_report.get("pcap_size_bytes")
        try:
            if v is not None:
                return int(v)
        except Exception:
            pass
    if inputs.pcap_path and inputs.pcap_path.exists():
        try:
            return int(inputs.pcap_path.stat().st_size)
        except Exception:
            return None
    return None


def transport_ratios_from_inputs(inputs: RunInputs) -> tuple[float | None, float | None, float | None, float | None]:
    proxies = None
    if isinstance(inputs.pcap_features, dict):
        p = inputs.pcap_features.get("proxies")
        if isinstance(p, dict):
            proxies = p
    if proxies:
        return (
            safe_float(proxies.get("tls_ratio")),
            safe_float(proxies.get("quic_ratio")),
            safe_float(proxies.get("tcp_ratio")),
            safe_float(proxies.get("udp_ratio")),
        )

    if not isinstance(inputs.pcap_report, dict):
        return None, None, None, None
    pb: dict[str, int] = {}
    for row in inputs.pcap_report.get("protocol_hierarchy") or []:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").strip().lower()
        if not proto:
            continue
        try:
            b = int(row.get("bytes") or 0)
        except Exception:
            b = 0
        pb[proto] = pb.get(proto, 0) + max(b, 0)
    tcp_b = pb.get("tcp") or 0
    udp_b = pb.get("udp") or 0
    tls_b = pb.get("tls") or 0
    quic_b = (pb.get("quic") or 0) + (pb.get("gquic") or 0)
    total = float(tcp_b + udp_b) if (tcp_b + udp_b) > 0 else 0.0
    tls_ratio = float(min(tls_b, tcp_b)) / float(tcp_b) if tcp_b > 0 else None
    quic_denom = float(max(udp_b, quic_b))
    quic_ratio = (float(quic_b) / quic_denom) if quic_denom > 0 else None
    tcp_ratio = float(tcp_b) / total if total > 0 else None
    udp_ratio = float(udp_b) / total if total > 0 else None
    tls_ratio = clamp01(tls_ratio)
    quic_ratio = clamp01(quic_ratio)
    tcp_ratio = clamp01(tcp_ratio)
    udp_ratio = clamp01(udp_ratio)
    return tls_ratio, quic_ratio, tcp_ratio, udp_ratio


def clamp01(v: float | None) -> float | None:
    if v is None:
        return None
    try:
        x = float(v)
    except Exception:
        return None
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def safe_float(v: object) -> float | None:
    try:
        if v is None:
            return None
        f = float(v)
        if f < 0.0:
            return None
        return f
    except Exception:
        return None


__all__ = [
    "clamp01",
    "compute_baseline_stability_rows",
    "compute_dars_component_rows",
    "compute_model_overlap_rows",
    "compute_phase_rows",
    "compute_static_dynamic_stratification_row",
    "compute_transport_mix_rows",
    "extract_static_snapshot",
    "fallback_phase",
    "pcap_size_bytes_from_inputs",
    "safe_float",
    "transport_ratios_from_inputs",
    "write_baseline_stability_csv",
    "write_dars_components_csv",
    "write_ml_audit_csv",
    "write_model_overlap_csv",
    "write_prevalence_csvs",
    "write_static_dynamic_stratification_csv",
    "write_transport_mix_csvs",
]
