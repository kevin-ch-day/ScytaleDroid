"""Per-run ML summary, DARS, and window attribution artifacts."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any

import numpy as np
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from .. import ml_parameters_profile as config
from ..evidence_pack_ml_preflight import RunInputs
from ..feature_matrix import rows_to_basic_matrix
from ..numpy_percentile import percentile as np_percentile
from ..telemetry_windowing import WindowSpec


def model_csv_label(model_name: str) -> str:
    """Stable model label used in output filenames."""
    if model_name == config.MODEL_IFOREST:
        return "iforest"
    if model_name == config.MODEL_OCSVM:
        return "ocsvm"
    return model_name


def baseline_feature_stats(X_train: np.ndarray, *, feature_names: list[str]) -> dict[str, Any]:
    if X_train.size == 0:
        return {"feature_names": feature_names, "mu": [0.0] * len(feature_names), "sigma": [1.0] * len(feature_names)}
    mu = np.mean(X_train, axis=0)
    sigma = np.std(X_train, axis=0, ddof=0)
    sigma = np.maximum(np.asarray(sigma, dtype=float), 1e-9)
    return {
        "feature_names": list(feature_names),
        "mu": [float(x) for x in mu],
        "sigma": [float(x) for x in sigma],
    }


def write_ml_summary(
    path: Path,
    *,
    run_inputs: RunInputs,
    phase: str,
    interaction_tag: str | None,
    window_rows: list[dict[str, Any]],
    dropped_partial_windows: int,
    model_outputs: dict[str, dict[str, Any]],
    out_dir: Path,
    baseline_feature_stats: dict[str, Any],
) -> None:
    ds = run_inputs.manifest.get("dataset") if isinstance(run_inputs.manifest.get("dataset"), dict) else {}
    payload: dict[str, Any] = {
        "ml_schema_version": config.ML_SCHEMA_VERSION,
        "run_id": run_inputs.run_id,
        "package_name": run_inputs.package_name,
        "run_profile": run_inputs.run_profile,
        "phase": phase,
        "interaction_tag": interaction_tag,
        "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
        "low_signal_reasons": ds.get("low_signal_reasons") if isinstance(ds.get("low_signal_reasons"), list) else [],
        "windows_total": len(window_rows),
        "dropped_partial_windows": int(dropped_partial_windows),
        "models": {},
        "dars_v1_path": "dars_v1.json",
        "skip": None,
    }
    threshold_payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
        "models": {},
    }
    dars_payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "dars_version": "v1",
        "primary_model": config.MODEL_IFOREST,
        "operator": ">=",
        "k_policy": "ceil_10pct_windows",
        "run_id": run_inputs.run_id,
        "package_name": run_inputs.package_name,
        "gates": {
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(config.MIN_PCAP_BYTES),
        },
        "scores": {},
    }
    run_matrix, _ = rows_to_basic_matrix(
        window_rows,
        window_spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S),
        feature_log1p=bool(config.FEATURE_LOG1P),
    )
    for model_name, meta in model_outputs.items():
        model_label = model_csv_label(model_name)
        csv_path = out_dir / f"anomaly_scores_{model_csv_label(model_name)}.csv"
        if not csv_path.exists():
            continue
        scores = load_scores(csv_path)
        if not scores:
            continue
        threshold = float(meta.get("threshold_value") or 0.0)
        threshold_payload["models"][model_name] = {
            "threshold_value": float(threshold),
            "threshold_percentile": float(meta.get("threshold_percentile") or config.THRESHOLD_PERCENTILE),
        }
        streak_count, longest_streak = anomaly_streak_metrics(scores, threshold)
        dars_row = compute_dars_v1(scores=scores, threshold=threshold)
        dars_row["threshold_value"] = float(round(threshold, 6))
        dars_row["model"] = str(model_name)
        dars_row["k_policy"] = "top_10_percent"
        topk_rows, zscore_rows = build_topk_and_zscores(
            window_rows=window_rows,
            run_matrix=run_matrix,
            scores=scores,
            threshold=threshold,
            baseline_feature_stats=baseline_feature_stats,
            top_k=int(dars_row["top_k"]),
        )
        topk_path = out_dir / f"top_k_windows_{model_label}.csv"
        zscore_path = out_dir / f"feature_zscores_per_top_window_{model_label}.csv"
        if not topk_path.exists():
            write_csv_dicts(topk_path, topk_rows)
        if not zscore_path.exists():
            write_csv_dicts(zscore_path, zscore_rows)
        if model_name == config.MODEL_IFOREST:
            _write_canonical_iforest_outputs(
                out_dir=out_dir,
                window_rows=window_rows,
                scores=scores,
                threshold=threshold,
                topk_rows=topk_rows,
                zscore_rows=zscore_rows,
            )
        payload["models"][model_name] = {
            "median": float(statistics.median(scores)),
            "p95": float(
                np_percentile(
                    np.asarray(scores, dtype=float),
                    95.0,
                    method=config.NP_PERCENTILE_METHOD,
                )
            ),
            "max": float(max(scores)),
            "anomalous_windows": int(sum(1 for s in scores if float(s) >= threshold)),
            "anomalous_streaks": {"count": streak_count, "longest": longest_streak},
            "threshold_value": float(threshold),
            "threshold_percentile": float(meta.get("threshold_percentile") or config.THRESHOLD_PERCENTILE),
            "training_mode": meta.get("training_mode"),
            "training_samples": int(meta.get("training_samples") or 0),
            "training_samples_warning": bool(meta.get("training_samples_warning")),
            "threshold_equals_max": bool(meta.get("threshold_equals_max")),
            "dars_v1": dars_row,
        }
        dars_payload["scores"][model_name] = dars_row
    threshold_path = out_dir / "baseline_threshold.json"
    if not threshold_path.exists():
        atomic_write_text(threshold_path, json.dumps(threshold_payload, indent=2, sort_keys=True) + "\n")
    dars_path = out_dir / "dars_v1.json"
    dars_hash_path = out_dir / "dars_v1.sha256"
    if dars_payload.get("scores"):
        if not dars_path.exists():
            dars_body = json.dumps(dars_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            dars_hash = hashlib.sha256(dars_body).hexdigest()
            dars_emit = dict(dars_payload)
            dars_emit["hash_of_dars_artifact"] = dars_hash
            atomic_write_text(dars_path, json.dumps(dars_emit, indent=2, sort_keys=True) + "\n")
        if not dars_hash_path.exists():
            atomic_write_text(dars_hash_path, _sha256_file(dars_path) + "\n")
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_scores(csv_path: Path) -> list[float]:
    scores: list[float] = []
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                scores.append(float(row.get("score") or 0.0))
            except Exception:
                continue
    return scores


def write_csv_dicts(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        atomic_write_text(path, "")
        return
    fieldnames = list(rows[0].keys())
    import io

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    atomic_write_text(path, buf.getvalue())


def compute_dars_v1(*, scores: list[float], threshold: float) -> dict[str, Any]:
    if not scores:
        return {
            "operator": ">=",
            "windows_total_n": 0,
            "top_k": 0,
            "k_policy": "ceil_10pct_windows",
            "exceedance_ratio": 0.0,
            "severity_ratio": 0.0,
            "dars_v1": 0.0,
        }
    t = int(len(scores))
    top_k = max(1, int(math.ceil(0.10 * float(t))))
    exceedance_count = int(sum(1 for s in scores if float(s) >= float(threshold)))
    exceedance_ratio = float(exceedance_count) / float(t) if t > 0 else 0.0
    top_scores = sorted((float(s) for s in scores), reverse=True)[:top_k]
    top_mean = float(sum(top_scores) / float(len(top_scores))) if top_scores else 0.0
    severity_ratio = (top_mean / float(threshold)) if float(threshold) > 0.0 else 0.0
    severity_clipped = min(1.0, max(0.0, severity_ratio / 2.0))
    dars_unit = min(1.0, max(0.0, 0.5 * exceedance_ratio + 0.5 * severity_clipped))
    return {
        "operator": ">=",
        "windows_total_n": t,
        "top_k": int(top_k),
        "k_policy": "ceil_10pct_windows",
        "exceedance_ratio": float(round(exceedance_ratio, 6)),
        "severity_ratio": float(round(severity_ratio, 6)),
        "dars_v1": float(round(100.0 * dars_unit, 6)),
    }


def build_topk_and_zscores(
    *,
    window_rows: list[dict[str, Any]],
    run_matrix: np.ndarray,
    scores: list[float],
    threshold: float,
    baseline_feature_stats: dict[str, Any],
    top_k: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not scores or run_matrix.size == 0:
        return [], []
    n = min(len(scores), int(run_matrix.shape[0]), len(window_rows))
    idx = sorted(range(n), key=lambda i: float(scores[i]), reverse=True)[: max(1, int(top_k))]
    feature_names = list(
        baseline_feature_stats.get("feature_names")
        or ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"]
    )
    mu = np.asarray(baseline_feature_stats.get("mu") or [0.0, 0.0, 0.0], dtype=float)
    sigma = np.asarray(baseline_feature_stats.get("sigma") or [1.0, 1.0, 1.0], dtype=float)
    sigma = np.maximum(sigma, 1e-9)
    topk_rows: list[dict[str, Any]] = []
    z_rows: list[dict[str, Any]] = []
    for rank, i in enumerate(idx, start=1):
        wr = window_rows[i]
        score = float(scores[i])
        topk_rows.append(
            {
                "rank": int(rank),
                "window_start_s": float(wr.get("window_start_s") or 0.0),
                "window_end_s": float(wr.get("window_end_s") or 0.0),
                "score": score,
                "threshold": float(threshold),
                "is_exceedance": bool(score >= float(threshold)),
            }
        )
        vec = np.asarray(run_matrix[i], dtype=float)
        z = (vec - mu) / sigma
        z_row: dict[str, Any] = {
            "rank": int(rank),
            "window_start_s": float(wr.get("window_start_s") or 0.0),
            "window_end_s": float(wr.get("window_end_s") or 0.0),
            "score": score,
            "dominant_feature": feature_names[int(np.argmax(np.abs(z)))],
        }
        for j, name in enumerate(feature_names):
            z_row[f"{name}_z"] = float(round(float(z[j]), 6))
        z_rows.append(z_row)
    return topk_rows, z_rows


def anomaly_streak_metrics(scores: list[float], threshold: float) -> tuple[int, int]:
    streaks = 0
    longest = 0
    current = 0
    thr = float(threshold)
    for score in scores:
        if float(score) >= thr:
            current += 1
            if current == 1:
                streaks += 1
            if current > longest:
                longest = current
        else:
            current = 0
    return streaks, longest


def _write_canonical_iforest_outputs(
    *,
    out_dir: Path,
    window_rows: list[dict[str, Any]],
    scores: list[float],
    threshold: float,
    topk_rows: list[dict[str, Any]],
    zscore_rows: list[dict[str, Any]],
) -> None:
    canonical_scores_path = out_dir / "window_scores.csv"
    canonical_topk_path = out_dir / "top_anomalous_windows.csv"
    canonical_attr_path = out_dir / "attribution_proxy.csv"
    if not canonical_scores_path.exists():
        canonical_rows: list[dict[str, Any]] = []
        n = min(len(window_rows), len(scores))
        for i in range(n):
            wr = window_rows[i]
            s = float(scores[i])
            canonical_rows.append(
                {
                    "window_index": int(i),
                    "window_start_s": float(wr.get("window_start_s") or 0.0),
                    "window_end_s": float(wr.get("window_end_s") or 0.0),
                    "score": s,
                    "threshold": float(threshold),
                    "is_exceedance": bool(s >= float(threshold)),
                }
            )
        write_csv_dicts(canonical_scores_path, canonical_rows)
    if not canonical_topk_path.exists():
        write_csv_dicts(canonical_topk_path, topk_rows)
    if not canonical_attr_path.exists():
        write_csv_dicts(canonical_attr_path, zscore_rows)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


__all__ = [
    "anomaly_streak_metrics",
    "baseline_feature_stats",
    "build_topk_and_zscores",
    "compute_dars_v1",
    "load_scores",
    "model_csv_label",
    "write_csv_dicts",
    "write_ml_summary",
]
