"""Batch ML runner over evidence packs (Paper #2, DB-free)."""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from scytaledroid.Config import app_config

from . import config
from .identity import derive_seed, salt_metadata
from .models import anomaly_scores, fit_model, fixed_model_specs
from .pcap_windows import build_window_features, extract_packet_timeline, write_anomaly_scores_csv
from .preflight import (
    RunInputs,
    compute_ml_preflight,
    get_sampling_duration_seconds,
    is_valid_dataset_run,
    load_run_inputs,
    write_ml_preflight,
)
from .windowing import WindowSpec


DATASET_FREEZE_MARKER = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"


@dataclass(frozen=True)
class MlRunStats:
    apps_seen: int
    apps_trained: int
    runs_scored: int
    runs_skipped: int
    generated_at: str


def run_ml_on_evidence_packs(*, output_root: Path | None = None) -> MlRunStats:
    """Run ML over evidence packs.

    Contract:
    - Reads evidence packs only (DB-free).
    - Writes per-run outputs under analysis/ml/v<ml_schema_version>/ after freeze,
      otherwise under analysis/ml_provisional/v<ml_schema_version>/.
    """
    root = output_root or (Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic")
    if not root.exists():
        return MlRunStats(0, 0, 0, 0, datetime.now(UTC).isoformat())

    frozen = DATASET_FREEZE_MARKER.exists()
    freeze_included: set[str] | None = None
    if frozen:
        freeze_included = _load_frozen_run_ids(DATASET_FREEZE_MARKER)
    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)

    runs: list[RunInputs] = []
    for run_dir in sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name):
        if freeze_included is not None and run_dir.name not in freeze_included:
            continue
        inputs = load_run_inputs(run_dir)
        if not inputs:
            continue
        if not is_valid_dataset_run(inputs):
            continue
        runs.append(inputs)

    # Group by identity key (preferred) or package fallback.
    by_app: dict[str, list[RunInputs]] = {}
    for r in runs:
        key = r.identity_key or (r.package_name or "_unknown")
        by_app.setdefault(key, []).append(r)

    apps_trained = 0
    runs_scored = 0
    runs_skipped = 0
    dataset_app_rows: list[dict[str, Any]] = []

    for app_key, app_runs in sorted(by_app.items(), key=lambda item: item[0]):
        # Require >=3 VALID runs per PM.
        if len(app_runs) < 3:
            _write_app_skip(app_runs, frozen=frozen, reason="ML_SKIPPED_INSUFFICIENT_RUNS")
            runs_skipped += len(app_runs)
            continue

        # Deterministic ordering for training set construction.
        app_runs_sorted = sorted(app_runs, key=lambda r: r.run_id)

        seed = derive_seed(app_key)
        specs = fixed_model_specs(seed)

        # Build training matrix from all windows of all runs (union baseline+interactive).
        all_rows: list[dict[str, Any]] = []
        train_rows: list[dict[str, Any]] = []
        per_run_rows: dict[str, tuple[list[dict[str, Any]], int]] = {}
        per_run_duration: dict[str, float] = {}
        per_model_scores_by_run: dict[str, dict[str, list[float]]] = {}
        per_model_thresholds: dict[str, float] = {}
        for r in app_runs_sorted:
            # Always write deterministic preflight output for operator debugging.
            preflight = compute_ml_preflight(r)
            out_dir_pf = _ml_output_dir(r.run_dir, frozen=frozen)
            out_dir_pf.mkdir(parents=True, exist_ok=True)
            pf_path = out_dir_pf / "ml_preflight.json"
            if not (frozen and pf_path.exists()):
                write_ml_preflight(pf_path, preflight)

            duration = get_sampling_duration_seconds(r)
            if duration is None:
                _write_run_skip(r, frozen=frozen, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                runs_skipped += 1
                continue
            if not r.pcap_path or not r.pcap_path.exists():
                _write_run_skip(r, frozen=frozen, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                runs_skipped += 1
                continue
            if not isinstance(r.pcap_report, dict):
                _write_run_skip(r, frozen=frozen, reason="ML_SKIPPED_MISSING_PROTOCOL_FEATURES")
                runs_skipped += 1
                continue
            packets = extract_packet_timeline(r.pcap_path)
            rows, dropped = build_window_features(packets, duration_s=float(duration), spec=window_spec)
            if not rows:
                _write_run_skip(r, frozen=frozen, reason="ML_SKIPPED_INSUFFICIENT_WINDOWS")
                runs_skipped += 1
                continue
            per_run_rows[r.run_id] = (rows, dropped)
            per_run_duration[r.run_id] = float(duration)
            for row in rows:
                row["_run_id"] = r.run_id
                all_rows.append(row)
                # Valid != trainable: low-signal is excluded from training deterministically,
                # but the run is still scored for reporting (Paper #2 contract).
                if not _is_low_signal(r):
                    train_rows.append(row)

        if len({rid for rid, _ in per_run_rows.items()}) < 3:
            # After per-run preflight, we may drop below the required run count.
            _write_app_skip(app_runs_sorted, frozen=frozen, reason="ML_SKIPPED_INSUFFICIENT_RUNS")
            runs_skipped += len(app_runs_sorted)
            continue

        # Training set is a strict subset (excludes low_signal). If nothing remains,
        # skip ML training for this app deterministically.
        if not train_rows:
            _write_app_skip(app_runs_sorted, frozen=frozen, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
            runs_skipped += len(app_runs_sorted)
            continue

        X_train, feature_names = _rows_to_matrix(train_rows)
        if X_train.size == 0 or X_train.shape[0] < 3:
            _write_app_skip(app_runs_sorted, frozen=frozen, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
            runs_skipped += len(app_runs_sorted)
            continue
        X_all, _ = _rows_to_matrix(all_rows)
        if X_all.size == 0:
            _write_app_skip(app_runs_sorted, frozen=frozen, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
            runs_skipped += len(app_runs_sorted)
            continue

        apps_trained += 1

        # Fit and score for each model.
        model_outputs: dict[str, dict[str, Any]] = {}
        for spec in specs:
            model = fit_model(spec, X_train)
            scores_train = anomaly_scores(spec.name, model, X_train)
            scores_all = anomaly_scores(spec.name, model, X_all)
            threshold = float(np.percentile(scores_train, config.THRESHOLD_PERCENTILE))
            per_model_thresholds[spec.name] = float(threshold)
            model_outputs[spec.name] = {
                "threshold_percentile": config.THRESHOLD_PERCENTILE,
                "threshold_value": threshold,
                "training_samples": int(X_train.shape[0]),
                "feature_names": list(feature_names),
                "params": dict(spec.params),
            }

            # Write per-run anomaly scores.
            by_run: dict[str, list[dict[str, Any]]] = {}
            scores_by_run: dict[str, list[float]] = {}
            for row, score in zip(all_rows, scores_all, strict=True):
                rid = row.get("_run_id")
                if not rid:
                    continue
                scores_by_run.setdefault(str(rid), []).append(float(score))
                by_run.setdefault(str(rid), []).append(
                    {
                        "window_start_s": row["window_start_s"],
                        "window_end_s": row["window_end_s"],
                        "score": float(score),
                        "threshold": float(threshold),
                        "is_anomalous": bool(float(score) >= float(threshold)),
                    }
                )

            per_model_scores_by_run[spec.name] = scores_by_run

            for r in app_runs_sorted:
                if r.run_id not in by_run:
                    continue
                out_dir = _ml_output_dir(r.run_dir, frozen=frozen)
                out_dir.mkdir(parents=True, exist_ok=True)
                scores_path = out_dir / f"anomaly_scores_{spec.name}.csv"
                if scores_path.exists():
                    # Immutable after freeze; do not overwrite.
                    continue
                write_anomaly_scores_csv(scores_path, by_run[r.run_id])

        if frozen:
            dataset_app_rows.extend(
                _compute_app_dataset_rows(
                    app_identity_key=app_key,
                    app_runs=app_runs_sorted,
                    per_model_scores_by_run=per_model_scores_by_run,
                    per_model_thresholds=per_model_thresholds,
                )
            )

        # Write manifests and summaries per run.
        for r in app_runs_sorted:
            if r.run_id not in per_run_rows:
                continue
            out_dir = _ml_output_dir(r.run_dir, frozen=frozen)
            out_dir.mkdir(parents=True, exist_ok=True)
            manifest_path = out_dir / "model_manifest.json"
            summary_path = out_dir / "ml_summary.json"
            if frozen and (manifest_path.exists() or summary_path.exists()):
                # Immutable after freeze; skip.
                continue
            _write_model_manifest(
                manifest_path,
                run_inputs=r,
                app_identity_key=app_key,
                seed=seed,
                window_spec=window_spec,
                model_outputs=model_outputs,
            )
            _write_ml_summary(
                summary_path,
                run_inputs=r,
                window_rows=per_run_rows[r.run_id][0],
                dropped_partial_windows=per_run_rows[r.run_id][1],
                model_outputs=model_outputs,
                out_dir=out_dir,
            )
            runs_scored += 1

    if frozen:
        _write_dataset_summary_csv(dataset_app_rows)

    return MlRunStats(
        apps_seen=len(by_app),
        apps_trained=apps_trained,
        runs_scored=runs_scored,
        runs_skipped=runs_skipped,
        generated_at=datetime.now(UTC).isoformat(),
    )


def _load_frozen_run_ids(path: Path) -> set[str] | None:
    """Return included run_ids from dataset_freeze.json, or None if unreadable.

    When frozen, ML must score only the included run set to prevent accidental
    inclusion of extra valid runs (Paper #2 contract).
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    ids = payload.get("included_run_ids")
    if not isinstance(ids, list):
        return None
    out: set[str] = set()
    for rid in ids:
        if isinstance(rid, str) and rid:
            out.add(rid)
    return out or None


def _is_low_signal(run_inputs: RunInputs) -> bool:
    ds = run_inputs.manifest.get("dataset") if isinstance(run_inputs.manifest, dict) else None
    if not isinstance(ds, dict):
        return False
    return ds.get("low_signal") is True


def _rows_to_matrix(rows: list[dict[str, Any]]) -> tuple[np.ndarray, list[str]]:
    # Minimal, stable numeric features (PCAP window intensity).
    feature_names = ["packet_count", "byte_count", "avg_packet_size_bytes"]
    data = []
    for row in rows:
        try:
            data.append([float(row.get(name) or 0.0) for name in feature_names])
        except Exception:
            continue
    if not data:
        return np.zeros((0, len(feature_names)), dtype=float), feature_names
    return np.asarray(data, dtype=float), feature_names


def _ml_output_dir(run_dir: Path, *, frozen: bool) -> Path:
    if frozen:
        return run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL
    return run_dir / "analysis" / "ml_provisional" / config.ML_SCHEMA_LABEL


def _is_baseline_profile(profile: str | None) -> bool:
    if not profile:
        return False
    p = profile.lower()
    return ("baseline" in p) or ("idle" in p) or ("minimal" in p)


def _is_interactive_profile(profile: str | None) -> bool:
    if not profile:
        return False
    return "interactive" in profile.lower()


def _compute_app_dataset_rows(
    *,
    app_identity_key: str,
    app_runs: list[RunInputs],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
) -> list[dict[str, Any]]:
    """Compute minimal per-app dataset summary rows (Paper #2)."""
    package = next((r.package_name for r in app_runs if r.package_name), None)
    rows: list[dict[str, Any]] = []
    for model_name, scores_by_run in per_model_scores_by_run.items():
        threshold = float(per_model_thresholds.get(model_name) or 0.0)
        for stratum in ("baseline", "interactive"):
            score_list: list[float] = []
            runs_included = 0
            for r in app_runs:
                if stratum == "baseline" and not _is_baseline_profile(r.run_profile):
                    continue
                if stratum == "interactive" and not _is_interactive_profile(r.run_profile):
                    continue
                run_scores = scores_by_run.get(r.run_id) or []
                if not run_scores:
                    continue
                runs_included += 1
                score_list.extend([float(s) for s in run_scores])
            if not score_list:
                continue
            arr = np.asarray(score_list, dtype=float)
            rows.append(
                {
                    "identity_key": app_identity_key,
                    "package_name": package or "",
                    "model": model_name,
                    "stratum": stratum,
                    "runs_included": runs_included,
                    "windows_total": int(arr.shape[0]),
                    "median": float(statistics.median(score_list)),
                    "p95": float(np.percentile(arr, 95.0)),
                    "max": float(np.max(arr)),
                    "anomalous_windows": int(sum(1 for s in score_list if float(s) >= threshold)),
                    "threshold_value": float(threshold),
                    "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )
    return rows


def _write_dataset_summary_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR) / "archive" / "ml"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"dataset_ml_summary_{config.ML_SCHEMA_LABEL}.csv"
    fieldnames = [
        "identity_key",
        "package_name",
        "model",
        "stratum",
        "runs_included",
        "windows_total",
        "median",
        "p95",
        "max",
        "anomalous_windows",
        "threshold_value",
        "threshold_percentile",
        "ml_schema_version",
    ]
    import csv

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def _write_model_manifest(
    path: Path,
    *,
    run_inputs: RunInputs,
    app_identity_key: str,
    seed: int,
    window_spec: WindowSpec,
    model_outputs: dict[str, dict[str, Any]],
) -> None:
    env = run_inputs.manifest.get("environment") or {}
    host_tools = env.get("host_tools") if isinstance(env, dict) else None
    try:
        import numpy
        import sklearn

        deps = {"numpy": numpy.__version__, "sklearn": sklearn.__version__}
    except Exception:
        deps = {}
    payload: dict[str, Any] = {
        "ml_schema_version": config.ML_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "frozen": bool(DATASET_FREEZE_MARKER.exists()),
        "identity_key_used": app_identity_key,
        "seed": int(seed),
        **salt_metadata(),
        "windowing": {
            "window_size_s": float(window_spec.window_size_s),
            "stride_s": float(window_spec.stride_s),
            "drop_partial_windows": True,
            "timebase": "pcap_time_relative_seconds",
        },
        "inputs": {
            "run_id": run_inputs.run_id,
            "package_name": run_inputs.package_name,
            "run_profile": run_inputs.run_profile,
            "plan_path": "inputs/static_dynamic_plan.json",
            "summary_path": "analysis/summary.json",
            "pcap_report_path": "analysis/pcap_report.json",
            "pcap_features_path": "analysis/pcap_features.json",
        },
        "environment": {
            "python_version": env.get("python_version") if isinstance(env, dict) else None,
            "host_tools": host_tools,
            "deps": deps,
        },
        "models": model_outputs,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_ml_summary(
    path: Path,
    *,
    run_inputs: RunInputs,
    window_rows: list[dict[str, Any]],
    dropped_partial_windows: int,
    model_outputs: dict[str, dict[str, Any]],
    out_dir: Path,
) -> None:
    payload: dict[str, Any] = {
        "ml_schema_version": config.ML_SCHEMA_VERSION,
        "run_id": run_inputs.run_id,
        "package_name": run_inputs.package_name,
        "run_profile": run_inputs.run_profile,
        "windows_total": len(window_rows),
        "dropped_partial_windows": int(dropped_partial_windows),
        "models": {},
        "skip": None,
    }
    # Compute per-model run stats from written per-window CSVs.
    for model_name, meta in model_outputs.items():
        csv_path = out_dir / f"anomaly_scores_{model_name}.csv"
        if not csv_path.exists():
            continue
        scores = _load_scores(csv_path)
        if not scores:
            continue
        payload["models"][model_name] = {
            "median": float(statistics.median(scores)),
            "p95": float(np.percentile(np.asarray(scores, dtype=float), 95.0)),
            "max": float(max(scores)),
            "anomalous_windows": int(sum(1 for s in scores if float(s) >= float(meta.get("threshold_value")))),
        }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _load_scores(csv_path: Path) -> list[float]:
    import csv

    scores: list[float] = []
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                scores.append(float(row.get("score") or 0.0))
            except Exception:
                continue
    return scores


def _write_run_skip(run: RunInputs, *, frozen: bool, reason: str) -> None:
    out_dir = _ml_output_dir(run.run_dir, frozen=frozen)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "ml_summary.json"
    if frozen and summary_path.exists():
        return
    payload = {
        "ml_schema_version": config.ML_SCHEMA_VERSION,
        "run_id": run.run_id,
        "package_name": run.package_name,
        "run_profile": run.run_profile,
        "skip": {"reason": reason},
    }
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_app_skip(app_runs: list[RunInputs], *, frozen: bool, reason: str) -> None:
    for r in app_runs:
        _write_run_skip(r, frozen=frozen, reason=reason)
