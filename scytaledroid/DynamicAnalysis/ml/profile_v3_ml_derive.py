"""Profile v3 per-package ML artifact derivation (Phase 2 enabler).

Profile v3 publication metrics are computed from per-run ML artifacts under:
  <run_dir>/analysis/ml/v1/{window_scores.csv, baseline_threshold.json}

Paper #2 generates these via freeze-anchored batch ML. Profile v3 needs the
same artifact contract, but the cohort is populated operationally during Phase 2.

This module derives the required artifacts for the *latest* baseline_idle and
interaction_scripted runs for a given package by:
1) windowing the run PCAPs (tshark-backed extract_packet_timeline)
2) training fixed-parameter models on baseline windows (baseline-only training)
3) scoring baseline + scripted windows
4) writing canonical outputs to each run directory

It is intentionally filesystem-driven and does not require the DB.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
from scytaledroid.DynamicAnalysis.ml.anomaly_model_training import (
    anomaly_scores,
    fit_model,
    fixed_model_specs,
)
from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import (
    get_sampling_duration_seconds,
    load_run_inputs,
)
from scytaledroid.DynamicAnalysis.ml.io.ml_output_paths import MLOutputPaths
from scytaledroid.DynamicAnalysis.ml.numpy_percentile import percentile as np_percentile
from scytaledroid.DynamicAnalysis.ml.pcap_window_features import (
    build_window_features,
    extract_packet_timeline,
)
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec
from scytaledroid.DynamicAnalysis.run_profile_norm import (
    normalize_run_profile,
    phase_from_normalized_profile,
)


@dataclass(frozen=True)
class V3MlDeriveResult:
    package: str
    baseline_run_id: str | None
    scripted_run_id: str | None
    trained: bool
    wrote_baseline: bool
    wrote_scripted: bool
    threshold_iforest: float | None
    errors: tuple[str, ...]


def _rows_to_matrix_v3(rows: list[dict[str, Any]], *, window_spec: WindowSpec) -> tuple[np.ndarray, list[str]]:
    """Feature matrix for v3 per-window scoring (aligned with query_mode_runner semantics)."""

    denom = float(window_spec.window_size_s) if float(window_spec.window_size_s) > 0 else 1.0
    feature_names = ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"]
    data: list[list[float]] = []

    def _f(value: Any) -> float:
        try:
            return float(value or 0.0)
        except Exception:
            return 0.0

    for row in rows:
        byte_count = _f(row.get("byte_count"))
        pkt_count = _f(row.get("packet_count"))
        avg_pkt = _f(row.get("avg_packet_size_bytes"))
        bytes_per_sec = byte_count / denom
        packets_per_sec = pkt_count / denom
        if bool(getattr(config, "FEATURE_LOG1P", False)):
            bytes_per_sec = float(np.log1p(bytes_per_sec))
            packets_per_sec = float(np.log1p(packets_per_sec))
        data.append([bytes_per_sec, packets_per_sec, avg_pkt])
    if not data:
        return np.zeros((0, len(feature_names)), dtype=float), feature_names
    return np.asarray(data, dtype=float), feature_names


def _find_latest_runs_for_package(*, evidence_root: Path, package: str) -> tuple[str | None, str | None]:
    """Return (latest_baseline_run_id, latest_scripted_run_id) by ended_at timestamp."""

    latest_baseline: tuple[str, str] | None = None  # (ended_at, run_id)
    latest_scripted: tuple[str, str] | None = None
    accept_manual = str(os.environ.get("SCYTALEDROID_V3_ACCEPT_MANUAL_INTERACTIVE") or "").strip().lower() in {"1", "true", "yes", "on"}

    for mf in sorted(evidence_root.glob("*/run_manifest.json")):
        run_dir = mf.parent
        inputs = load_run_inputs(run_dir)
        if not inputs:
            continue
        if str(inputs.package_name or "").strip() != str(package).strip():
            continue
        rp = normalize_run_profile(inputs.run_profile or "")
        phase = phase_from_normalized_profile(rp)
        # Use scenario ended_at when available; fall back to manifest ended_at.
        ended_at = None
        if isinstance(inputs.manifest, dict):
            scen = inputs.manifest.get("scenario") if isinstance(inputs.manifest.get("scenario"), dict) else {}
            ended_at = str(scen.get("ended_at") or inputs.manifest.get("ended_at") or "").strip()
        ended_key = ended_at or "0000-00-00T00:00:00Z"
        if phase == "idle":
            if latest_baseline is None or ended_key > latest_baseline[0]:
                latest_baseline = (ended_key, inputs.run_id)
        if rp == "interaction_scripted" or (accept_manual and rp == "interaction_manual"):
            if latest_scripted is None or ended_key > latest_scripted[0]:
                latest_scripted = (ended_key, inputs.run_id)

    return (latest_baseline[1] if latest_baseline else None, latest_scripted[1] if latest_scripted else None)


def _window_rows_for_run(*, run_dir: Path) -> tuple[list[dict[str, Any]], int]:
    inputs = load_run_inputs(run_dir)
    if not inputs:
        raise RuntimeError(f"invalid run inputs: {run_dir}")
    dur = get_sampling_duration_seconds(inputs)
    if dur is None or float(dur) <= 0:
        raise RuntimeError("missing sampling_duration_seconds (analysis/summary.json)")
    if not inputs.pcap_path or not inputs.pcap_path.exists():
        raise RuntimeError("missing pcap artifact")
    packets = extract_packet_timeline(inputs.pcap_path)
    rows, dropped = build_window_features(
        packets,
        duration_s=float(dur),
        spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S),
    )
    return rows, int(dropped)


def _write_window_scores_csv(path: Path, *, rows: list[dict[str, Any]], scores: np.ndarray, threshold: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = min(len(rows), int(scores.shape[0]))
    out: list[dict[str, Any]] = []
    for i in range(n):
        wr = rows[i]
        s = float(scores[i])
        out.append(
            {
                "window_index": int(i),
                "window_start_s": float(wr.get("window_start_s") or 0.0),
                "window_end_s": float(wr.get("window_end_s") or 0.0),
                "engine": "iforest",
                "score": s,
                "threshold": float(threshold),
                "is_exceedance": bool(s >= float(threshold)),
            }
        )
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()) if out else ["window_index", "score", "threshold", "is_exceedance"])
        w.writeheader()
        for r in out:
            w.writerow(r)


def _write_baseline_threshold(path: Path, *, thresholds: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    iforest_thr = float(thresholds.get(config.MODEL_IFOREST) or thresholds.get("iforest") or 0.0)
    payload: dict[str, Any] = {
        "ml_schema_version": int(getattr(config, "ML_SCHEMA_VERSION", 1)),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        # Preferred simple keys (Profile v3 reader accepts these).
        "threshold": float(iforest_thr),
        "thresholds": {"iforest": float(iforest_thr)},
        # Multi-model layout (back-compat with Phase E style).
        "models": {
            "iforest": {"threshold": float(iforest_thr), "threshold_value": float(iforest_thr)},
        },
    }
    for name, thr in thresholds.items():
        n = str(name).strip().lower()
        if n == "iforest":
            continue
        payload["models"][n] = {"threshold": float(thr), "threshold_value": float(thr)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def derive_profile_v3_ml_for_package(*, package: str, evidence_root: Path | None = None) -> V3MlDeriveResult:
    """Derive ML artifacts for the latest baseline+scripted runs of a package."""

    root = evidence_root or (Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic")
    pkg = str(package).strip()
    errors: list[str] = []
    baseline_rid, scripted_rid = _find_latest_runs_for_package(evidence_root=root, package=pkg)
    if not baseline_rid:
        return V3MlDeriveResult(
            package=pkg,
            baseline_run_id=None,
            scripted_run_id=scripted_rid,
            trained=False,
            wrote_baseline=False,
            wrote_scripted=False,
            threshold_iforest=None,
            errors=("missing_baseline_idle_run",),
        )

    baseline_dir = root / baseline_rid
    scripted_dir = (root / scripted_rid) if scripted_rid else None

    try:
        base_rows, _ = _window_rows_for_run(run_dir=baseline_dir)
    except Exception as exc:  # noqa: BLE001
        return V3MlDeriveResult(
            package=pkg,
            baseline_run_id=baseline_rid,
            scripted_run_id=scripted_rid,
            trained=False,
            wrote_baseline=False,
            wrote_scripted=False,
            threshold_iforest=None,
            errors=(f"baseline_windowing_failed:{type(exc).__name__}:{exc}",),
        )

    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)
    X_train, _ = _rows_to_matrix_v3(base_rows, window_spec=window_spec)
    if X_train.size == 0:
        return V3MlDeriveResult(
            package=pkg,
            baseline_run_id=baseline_rid,
            scripted_run_id=scripted_rid,
            trained=False,
            wrote_baseline=False,
            wrote_scripted=False,
            threshold_iforest=None,
            errors=("empty_feature_matrix",),
        )

    baseline_inputs = load_run_inputs(baseline_dir)
    identity_key = baseline_inputs.identity_key if baseline_inputs else None
    seed = 1337
    try:
        if identity_key:
            from scytaledroid.DynamicAnalysis.ml.seed_identity import derive_seed

            seed = int(derive_seed(str(identity_key)))
    except Exception:
        seed = 1337

    specs = fixed_model_specs(seed, ml_config=config)
    thresholds: dict[str, float] = {}
    trained = False

    # Train models on baseline windows only and compute baseline thresholds.
    try:
        for spec in specs:
            model = fit_model(spec, X_train)
            scores_train = anomaly_scores(spec.name, model, X_train)
            thr = float(np_percentile(scores_train, float(config.THRESHOLD_PERCENTILE), method=config.NP_PERCENTILE_METHOD))
            thresholds[spec.name] = thr
        trained = True
    except Exception as exc:  # noqa: BLE001
        errors.append(f"training_failed:{type(exc).__name__}:{exc}")

    if not trained or config.MODEL_IFOREST not in thresholds:
        return V3MlDeriveResult(
            package=pkg,
            baseline_run_id=baseline_rid,
            scripted_run_id=scripted_rid,
            trained=False,
            wrote_baseline=False,
            wrote_scripted=False,
            threshold_iforest=None,
            errors=tuple(errors) or ("training_failed",),
        )

    thr_if = float(thresholds[config.MODEL_IFOREST])

    wrote_baseline = False
    wrote_scripted = False

    # Score and write baseline outputs.
    try:
        iforest_spec = next(s for s in specs if s.name == config.MODEL_IFOREST)
        model_if = fit_model(iforest_spec, X_train)
        scores_base = anomaly_scores(iforest_spec.name, model_if, X_train)
        out_base = MLOutputPaths(run_dir=baseline_dir, schema_label=config.ML_SCHEMA_LABEL).output_dir
        _write_window_scores_csv(out_base / "window_scores.csv", rows=base_rows, scores=scores_base, threshold=thr_if)
        _write_baseline_threshold(out_base / "baseline_threshold.json", thresholds={k: float(v) for k, v in thresholds.items()})
        wrote_baseline = True
    except Exception as exc:  # noqa: BLE001
        errors.append(f"write_baseline_failed:{type(exc).__name__}:{exc}")

    # Score and write scripted outputs if present.
    if scripted_dir and scripted_dir.exists():
        try:
            scr_rows, _ = _window_rows_for_run(run_dir=scripted_dir)
            X_scr, _ = _rows_to_matrix_v3(scr_rows, window_spec=window_spec)
            iforest_spec = next(s for s in specs if s.name == config.MODEL_IFOREST)
            model_if = fit_model(iforest_spec, X_train)
            scores_scr = anomaly_scores(iforest_spec.name, model_if, X_scr)
            out_scr = MLOutputPaths(run_dir=scripted_dir, schema_label=config.ML_SCHEMA_LABEL).output_dir
            _write_window_scores_csv(out_scr / "window_scores.csv", rows=scr_rows, scores=scores_scr, threshold=thr_if)
            _write_baseline_threshold(out_scr / "baseline_threshold.json", thresholds={k: float(v) for k, v in thresholds.items()})
            wrote_scripted = True
        except Exception as exc:  # noqa: BLE001
            errors.append(f"write_scripted_failed:{type(exc).__name__}:{exc}")

    return V3MlDeriveResult(
        package=pkg,
        baseline_run_id=baseline_rid,
        scripted_run_id=scripted_rid,
        trained=trained,
        wrote_baseline=wrote_baseline,
        wrote_scripted=wrote_scripted,
        threshold_iforest=thr_if,
        errors=tuple(errors),
    )


__all__ = ["V3MlDeriveResult", "derive_profile_v3_ml_for_package"]
