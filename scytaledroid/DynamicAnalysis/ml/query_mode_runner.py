"""Query-mode ML execution (Phase F1).

Goals:
- No ML math changes relative to Phase E (same windowing/features/models/thresholding).
- Selection is explicit and provenance is written to output/operational/<snapshot_id>/selection_manifest.json.
- Per-run outputs are written under the operational snapshot:
  output/operational/<snapshot_id>/runs/<run_id>/...
"""

from __future__ import annotations

import csv
import json
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from scytaledroid.Config import app_config

from . import ml_parameters_paper2 as config
from .anomaly_model_training import anomaly_scores, fit_model, fixed_model_specs
from .evidence_pack_ml_preflight import (
    RunInputs,
    compute_ml_preflight,
    derive_run_mode,
    get_sampling_duration_seconds,
    load_run_inputs,
    write_ml_preflight,
)
from .numpy_percentile import percentile as np_percentile
from .pcap_window_features import build_window_features, extract_packet_timeline, write_anomaly_scores_csv
from .seed_identity import derive_seed
from .telemetry_windowing import WindowSpec
from .selectors.models import SelectionResult, write_selection_manifest


@dataclass(frozen=True)
class QueryMlRunStats:
    groups_seen: int
    groups_trained: int
    runs_scored: int
    runs_skipped: int
    snapshot_id: str
    snapshot_dir: Path
    generated_at_utc: str


def _snapshot_id(*, selector_type: str) -> str:
    return f"{selector_type}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"


def _mode_rank(mode: str) -> int:
    return 0 if mode == "baseline" else (1 if mode == "interactive" else 2)


def _rows_to_matrix(rows: list[dict[str, Any]], *, window_spec: WindowSpec) -> tuple[np.ndarray, list[str]]:
    denom = float(window_spec.window_size_s) if window_spec.window_size_s > 0 else 1.0
    feature_names = ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"]
    data: list[list[float]] = []
    for row in rows:
        try:
            byte_count = float(row.get("byte_count") or 0.0)
            pkt_count = float(row.get("packet_count") or 0.0)
            avg_pkt = float(row.get("avg_packet_size_bytes") or 0.0)
            bytes_per_sec = byte_count / denom
            packets_per_sec = pkt_count / denom
            if config.FEATURE_LOG1P:
                bytes_per_sec = float(np.log1p(bytes_per_sec))
                packets_per_sec = float(np.log1p(packets_per_sec))
            data.append([bytes_per_sec, packets_per_sec, avg_pkt])
        except Exception:
            continue
    if not data:
        return np.zeros((0, len(feature_names)), dtype=float), feature_names
    return np.asarray(data, dtype=float), feature_names


def _apply_robust_scaling(
    X_train: np.ndarray, X_all: np.ndarray
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    if X_train.size == 0:
        return X_train, X_all, {"method": "none"}
    q1 = np_percentile(X_train, 25.0, axis=0, method=config.NP_PERCENTILE_METHOD)
    q3 = np_percentile(X_train, 75.0, axis=0, method=config.NP_PERCENTILE_METHOD)
    med = np.median(X_train, axis=0)
    iqr = np.maximum(np.asarray(q3) - np.asarray(q1), 1e-9)
    X_train_scaled = (X_train - med) / iqr
    X_all_scaled = (X_all - med) / iqr
    return (
        X_train_scaled,
        X_all_scaled,
        {
            "method": "robust_zscore",
            "median": [float(v) for v in med],
            "iqr": [float(v) for v in iqr],
        },
    )


def _run_output_dir(snapshot_dir: Path, run_id: str) -> Path:
    # Keep this entirely separate from evidence packs to avoid polluting archival inputs.
    return snapshot_dir / "runs" / run_id / "ml" / config.ML_SCHEMA_LABEL


def _pcap_size_bytes(inputs: RunInputs) -> int | None:
    if isinstance(inputs.pcap_report, dict):
        try:
            v = inputs.pcap_report.get("pcap_size_bytes")
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


def _clamp01(v: float | None) -> float | None:
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


def _safe_float(v: object) -> float | None:
    try:
        return float(v)  # type: ignore[arg-type]
    except Exception:
        return None


def _transport_ratios_from_inputs(inputs: RunInputs) -> tuple[float | None, float | None, float | None, float | None]:
    proxies = None
    if isinstance(inputs.pcap_features, dict):
        p = inputs.pcap_features.get("proxies")
        if isinstance(p, dict):
            proxies = p
    if proxies:
        return (
            _safe_float(proxies.get("tls_ratio")),
            _safe_float(proxies.get("quic_ratio")),
            _safe_float(proxies.get("tcp_ratio")),
            _safe_float(proxies.get("udp_ratio")),
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
    return _clamp01(tls_ratio), _clamp01(quic_ratio), _clamp01(tcp_ratio), _clamp01(udp_ratio)


def _write_json_if_missing(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_model_manifest(
    path: Path,
    *,
    run_inputs: RunInputs,
    identity_key_used: str,
    seed: int,
    window_spec: WindowSpec,
    model_outputs: dict[str, dict[str, Any]],
    selection_manifest_path: Path,
) -> None:
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "identity_key_used": identity_key_used,
        "seed": int(seed),
        "seed_salt": {"label": config.SEED_SALT_LABEL},
        "windowing": {"window_size_s": window_spec.window_size_s, "stride_s": window_spec.stride_s},
        "selection_manifest_path": str(selection_manifest_path),
        "run": {
            "run_id": run_inputs.run_id,
            "package_name": run_inputs.package_name,
            "run_profile": run_inputs.run_profile,
        },
        "models": model_outputs,
    }
    _write_json_if_missing(path, payload)


def _anomaly_streak_metrics(scores: list[float], threshold: float) -> tuple[int, int]:
    streak = 0
    longest = 0
    streaks = 0
    for s in scores:
        if float(s) >= float(threshold):
            streak += 1
            longest = max(longest, streak)
        else:
            if streak:
                streaks += 1
            streak = 0
    if streak:
        streaks += 1
    return streaks, longest


def _write_ml_summary(
    path: Path,
    *,
    run_inputs: RunInputs,
    mode: str,
    window_rows: list[dict[str, Any]],
    dropped_partial_windows: int,
    model_outputs: dict[str, dict[str, Any]],
    out_dir: Path,
) -> None:
    ds = run_inputs.manifest.get("dataset") if isinstance(run_inputs.manifest.get("dataset"), dict) else {}
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "run_id": run_inputs.run_id,
        "package_name": run_inputs.package_name,
        "run_profile": run_inputs.run_profile,
        "mode": mode,
        "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
        "windows_total": len(window_rows),
        "dropped_partial_windows": int(dropped_partial_windows),
        "models": {},
        "skip": None,
    }
    for model_name, meta in model_outputs.items():
        csv_path = out_dir / f"anomaly_scores_{model_name}.csv"
        if not csv_path.exists():
            continue
        scores: list[float] = []
        with csv_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                try:
                    scores.append(float(row.get("score") or 0.0))
                except Exception:
                    continue
        if not scores:
            continue
        threshold = float(meta.get("threshold_value") or 0.0)
        streak_count, longest_streak = _anomaly_streak_metrics(scores, threshold)
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
            "np_percentile_method": str(meta.get("np_percentile_method") or config.NP_PERCENTILE_METHOD),
            "training_mode": meta.get("training_mode"),
            "training_samples": int(meta.get("training_samples") or 0),
            "training_samples_warning": bool(meta.get("training_samples_warning")),
            "threshold_equals_max": bool(meta.get("threshold_equals_max")),
        }
    _write_json_if_missing(path, payload)


def _write_tables(
    snapshot_dir: Path,
    *,
    per_run_rows: list[dict[str, Any]],
    per_group_mode_rows: list[dict[str, Any]],
    overlap_rows: list[dict[str, Any]],
    transport_rows: list[dict[str, Any]],
    transport_group_mode_rows: list[dict[str, Any]],
) -> None:
    tables = snapshot_dir / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    def _write(path: Path, rows: list[dict[str, Any]]) -> None:
        fields: list[str] = []
        for r in rows:
            for k in r.keys():
                if k not in fields:
                    fields.append(k)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k) for k in fields})

    _write(tables / "anomaly_prevalence_per_run.csv", per_run_rows)
    _write(tables / "anomaly_prevalence_per_group_mode.csv", per_group_mode_rows)
    _write(tables / "model_overlap_per_run.csv", overlap_rows)
    _write(tables / "transport_mix_per_run.csv", transport_rows)
    _write(tables / "transport_mix_per_group_mode.csv", transport_group_mode_rows)


def _write_snapshot_summary(snapshot_dir: Path, summary: dict[str, Any]) -> None:
    path = snapshot_dir / "snapshot_summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_ml_query_mode(
    *,
    selection: SelectionResult,
    snapshot_root: Path | None = None,
    reuse_existing_outputs: bool = True,
) -> QueryMlRunStats:
    """Run ML in query mode and write operational snapshot outputs."""

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not evidence_root.exists():
        raise RuntimeError(f"Evidence root missing: {evidence_root}")

    snap_root = snapshot_root or (Path(app_config.OUTPUT_DIR) / "operational")
    sid = _snapshot_id(selector_type=selection.selector_type)
    snapshot_dir = snap_root / sid
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = snapshot_dir / "selection_manifest.json"
    write_selection_manifest(manifest_path, result=selection)

    # Group by base_apk_sha256 (default policy).
    groups: dict[str, list[RunInputs]] = defaultdict(list)
    skipped_runs = 0
    for ref in selection.included:
        inputs = load_run_inputs(ref.evidence_dir)
        if not inputs:
            skipped_runs += 1
            continue
        base_sha = ref.base_apk_sha256 or ""
        if not base_sha:
            base_sha = ref.package_name or "unknown"
        groups[base_sha].append(inputs)

    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)

    per_run_prevalence: list[dict[str, Any]] = []
    per_group_mode_prevalence: list[dict[str, Any]] = []
    overlap_rows: list[dict[str, Any]] = []
    transport_rows: list[dict[str, Any]] = []
    transport_group_mode_rows: list[dict[str, Any]] = []

    groups_seen = len(groups)
    groups_trained = 0
    runs_scored = 0
    runs_skipped = 0
    groups_skipped_no_baseline = 0
    groups_union_fallback = 0
    groups_baseline_thin = 0

    for group_key in sorted(groups.keys()):
        runs = groups[group_key]
        # Sort runs deterministically.
        runs = sorted(
            runs,
            key=lambda r: (
                str(r.package_name or ""),
                _mode_rank(derive_run_mode(r)[0]),
                str(r.manifest.get("ended_at") or ""),
                r.run_id,
            ),
        )
        pkg = next((r.package_name for r in runs if r.package_name), None) or "<unknown>"

        # Preflight + windowing per run.
        by_run_rows: dict[str, tuple[list[dict[str, Any]], int, str]] = {}
        all_rows: list[dict[str, Any]] = []
        for r in runs:
            out_dir = _run_output_dir(snapshot_dir, r.run_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            pf_path = out_dir / "ml_preflight.json"
            if not pf_path.exists():
                write_ml_preflight(pf_path, compute_ml_preflight(r))

            duration = get_sampling_duration_seconds(r)
            if duration is None or duration <= 0 or not r.pcap_path or not r.pcap_path.exists():
                runs_skipped += 1
                continue
            try:
                packets = extract_packet_timeline(r.pcap_path)
                rows, dropped = build_window_features(packets, duration_s=float(duration), spec=window_spec)
            except Exception:
                runs_skipped += 1
                continue
            if not rows:
                runs_skipped += 1
                continue
            mode, _ = derive_run_mode(r)
            for row in rows:
                row["_run_id"] = r.run_id
                row["_mode"] = mode
            by_run_rows[r.run_id] = (rows, dropped, mode)
            all_rows.extend(rows)

            # Transport mix per run (best-effort; independent of ML scoring).
            tls, quic, tcp, udp = _transport_ratios_from_inputs(r)
            transport_rows.append(
                {
                    "group_key": group_key,
                    "package_name": pkg,
                    "run_id": r.run_id,
                    "mode": mode,
                    "tls_ratio": tls,
                    "quic_ratio": quic,
                    "tcp_ratio": tcp,
                    "udp_ratio": udp,
                    "pcap_bytes": _pcap_size_bytes(r),
                }
            )

        if not by_run_rows:
            continue

        # Split by mode.
        baseline_rows: list[dict[str, Any]] = []
        interactive_rows: list[dict[str, Any]] = []
        unknown_rows: list[dict[str, Any]] = []
        for rid, (rows, _, mode) in by_run_rows.items():
            if mode == "baseline":
                baseline_rows.extend(rows)
            elif mode == "interactive":
                interactive_rows.extend(rows)
            else:
                unknown_rows.extend(rows)

        if not baseline_rows:
            # Policy: need >=1 baseline to train.
            groups_skipped_no_baseline += 1
            continue
        baseline_run_count = sum(1 for _, (_, _, m) in by_run_rows.items() if m == "baseline")
        if baseline_run_count < 2:
            groups_baseline_thin += 1

        # Training selection (F1 policy): concat baseline windows; union fallback uses baseline+interactive.
        baseline_windows_ok = len(baseline_rows) >= int(config.MIN_WINDOWS_BASELINE)
        min_bytes = int(config.MIN_PCAP_BYTES_FALLBACK)
        baseline_pcap_bytes_total = 0
        for r in runs:
            mode, _ = derive_run_mode(r)
            if mode != "baseline":
                continue
            if r.pcap_path and r.pcap_path.exists():
                baseline_pcap_bytes_total += int(r.pcap_path.stat().st_size)
            ds = r.manifest.get("dataset") if isinstance(r.manifest.get("dataset"), dict) else {}
            try:
                mb = int(ds.get("min_pcap_bytes") or 0)
                if mb > min_bytes:
                    min_bytes = mb
            except Exception:
                pass
        baseline_bytes_ok = baseline_pcap_bytes_total >= int(min_bytes)
        if baseline_bytes_ok and baseline_windows_ok:
            training_mode = "baseline_only"
            train_rows = baseline_rows
        else:
            training_mode = "union_fallback"
            groups_union_fallback += 1
            train_rows = baseline_rows + interactive_rows

        X_train, feature_names = _rows_to_matrix(train_rows, window_spec=window_spec)
        X_all, _ = _rows_to_matrix(all_rows, window_spec=window_spec)
        if X_train.size == 0 or X_train.shape[0] < 3 or X_all.size == 0:
            continue

        feature_scaling: dict[str, Any] | None = None
        if config.FEATURE_ROBUST_SCALE:
            X_train, X_all, feature_scaling = _apply_robust_scaling(X_train, X_all)

        # Seed: stable per group key.
        identity_key = f"group:{group_key}"
        seed = derive_seed(identity_key)
        specs = fixed_model_specs(seed)
        groups_trained += 1

        per_model_thresholds: dict[str, float] = {}
        model_outputs: dict[str, dict[str, Any]] = {}
        per_model_scores_by_run: dict[str, dict[str, list[float]]] = {}

        for spec in specs:
            model = fit_model(spec, X_train)
            scores_train = anomaly_scores(spec.name, model, X_train)
            scores_all = anomaly_scores(spec.name, model, X_all)
            threshold = float(
                np_percentile(
                    scores_train,
                    config.THRESHOLD_PERCENTILE,
                    method=config.NP_PERCENTILE_METHOD,
                )
            )
            train_max = float(np.max(scores_train)) if scores_train.size else 0.0
            threshold_equals_max = bool(abs(threshold - train_max) <= 1e-9)
            training_samples = int(X_train.shape[0])
            training_samples_warning = bool(training_samples < int(config.MIN_TRAINING_SAMPLES_WARNING))

            per_model_thresholds[spec.name] = threshold
            model_outputs[spec.name] = {
                "threshold_percentile": config.THRESHOLD_PERCENTILE,
                "threshold_value": threshold,
                "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                "training_samples": training_samples,
                "training_samples_warning": training_samples_warning,
                "threshold_equals_max": threshold_equals_max,
                "feature_transform": "log1p_bytes_packets" if config.FEATURE_LOG1P else "none",
                "feature_scaling": feature_scaling,
                "feature_names": list(feature_names),
                "params": dict(spec.params),
                "score_semantics": "higher_is_more_anomalous",
                "training_mode": training_mode,
                "quality_gates": {
                    "baseline_min_pcap_bytes": int(min_bytes),
                    "baseline_pcap_bytes_total": int(baseline_pcap_bytes_total),
                    "baseline_pcap_bytes_ok": bool(baseline_bytes_ok),
                    "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
                    "baseline_windows_total": int(len(baseline_rows)),
                    "baseline_windows_ok": bool(baseline_windows_ok),
                },
            }

            # Split per-run scores in deterministic order.
            scores_by_run: dict[str, list[float]] = defaultdict(list)
            rows_by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row, score in zip(all_rows, scores_all, strict=True):
                rid = str(row.get("_run_id") or "")
                if not rid:
                    continue
                scores_by_run[rid].append(float(score))
                rows_by_run[rid].append(
                    {
                        "window_start_s": row["window_start_s"],
                        "window_end_s": row["window_end_s"],
                        "score": float(score),
                        "threshold": float(threshold),
                        "is_anomalous": bool(float(score) >= float(threshold)),
                    }
                )
            per_model_scores_by_run[spec.name] = dict(scores_by_run)

            for r in runs:
                out_dir = _run_output_dir(snapshot_dir, r.run_id)
                out_dir.mkdir(parents=True, exist_ok=True)
                scores_path = out_dir / f"anomaly_scores_{spec.name}.csv"
                if reuse_existing_outputs and scores_path.exists():
                    continue
                write_anomaly_scores_csv(scores_path, rows_by_run.get(r.run_id) or [])

        # Write per-run manifests/summaries.
        for r in runs:
            out_dir = _run_output_dir(snapshot_dir, r.run_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            manifest_out = out_dir / "model_manifest.json"
            summary_out = out_dir / "ml_summary.json"
            mode, _ = derive_run_mode(r)
            if not (reuse_existing_outputs and manifest_out.exists()):
                _write_model_manifest(
                    manifest_out,
                    run_inputs=r,
                    identity_key_used=identity_key,
                    seed=seed,
                    window_spec=window_spec,
                    model_outputs=model_outputs,
                    selection_manifest_path=manifest_path,
                )
            if not (reuse_existing_outputs and summary_out.exists()):
                window_rows = by_run_rows.get(r.run_id, ([], 0, mode))[0]
                dropped = by_run_rows.get(r.run_id, ([], 0, mode))[1]
                _write_ml_summary(
                    summary_out,
                    run_inputs=r,
                    mode=mode,
                    window_rows=window_rows,
                    dropped_partial_windows=int(dropped),
                    model_outputs=model_outputs,
                    out_dir=out_dir,
                )

        # Model overlap per run (IF vs OC-SVM).
        if config.MODEL_IFOREST in per_model_scores_by_run and config.MODEL_OCSVM in per_model_scores_by_run:
            if_thr = float(per_model_thresholds.get(config.MODEL_IFOREST) or 0.0)
            oc_thr = float(per_model_thresholds.get(config.MODEL_OCSVM) or 0.0)
            for rid in sorted(by_run_rows.keys()):
                if_scores = per_model_scores_by_run[config.MODEL_IFOREST].get(rid) or []
                oc_scores = per_model_scores_by_run[config.MODEL_OCSVM].get(rid) or []
                n = min(len(if_scores), len(oc_scores))
                if n <= 0:
                    continue
                a = {i for i in range(n) if float(if_scores[i]) >= if_thr}
                b = {i for i in range(n) if float(oc_scores[i]) >= oc_thr}
                union = a.union(b)
                inter = a.intersection(b)
                jaccard = (float(len(inter)) / float(len(union))) if union else 0.0
                overlap_rows.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "run_id": rid,
                        "mode": by_run_rows[rid][2],
                        "training_mode": training_mode,
                        "windows_total": int(n),
                        "iforest_flagged": int(len(a)),
                        "ocsvm_flagged": int(len(b)),
                        "both_flagged": int(len(inter)),
                        "either_flagged": int(len(union)),
                        "jaccard": float(jaccard),
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

        # Per-run prevalence rows.
        for model_name, scores_by_run in per_model_scores_by_run.items():
            thr = float(per_model_thresholds.get(model_name) or 0.0)
            for rid, scores in scores_by_run.items():
                if not scores:
                    continue
                mode = by_run_rows.get(rid, ([], 0, "unknown"))[2]
                anomalous = int(sum(1 for s in scores if float(s) >= thr))
                arr = np.asarray(scores, dtype=float)
                per_run_prevalence.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "run_id": rid,
                        "mode": mode,
                        "model": model_name,
                        "training_mode": training_mode,
                        "windows_total": int(arr.shape[0]),
                        "median": float(statistics.median(scores)),
                        "p95": float(np_percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)),
                        "max": float(np.max(arr)),
                        "anomalous_windows": anomalous,
                        "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                        "threshold_value": float(thr),
                        "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                        "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

        # Per-group-mode aggregate prevalence rows (concatenate windows by mode).
        for model_name, scores_by_run in per_model_scores_by_run.items():
            thr = float(per_model_thresholds.get(model_name) or 0.0)
            mode_scores: dict[str, list[float]] = {"baseline": [], "interactive": [], "unknown": []}
            for rid, scores in scores_by_run.items():
                mode = by_run_rows.get(rid, ([], 0, "unknown"))[2]
                mode_scores.setdefault(mode, []).extend(scores)
            for mode, scores in sorted(mode_scores.items(), key=lambda kv: _mode_rank(kv[0])):
                if not scores:
                    continue
                anomalous = int(sum(1 for s in scores if float(s) >= thr))
                arr = np.asarray(scores, dtype=float)
                per_group_mode_prevalence.append(
                    {
                        "group_key": group_key,
                        "package_name": pkg,
                        "mode": mode,
                        "model": model_name,
                        "training_mode": training_mode,
                        "windows_total": int(arr.shape[0]),
                        "median": float(statistics.median(scores)),
                        "p95": float(np_percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)),
                        "max": float(np.max(arr)),
                        "anomalous_windows": anomalous,
                        "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                        "threshold_value": float(thr),
                        "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                        "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

        # Transport mix group-mode rollup (weighted by pcap_bytes).
        by_mode: dict[str, list[dict[str, Any]]] = {"baseline": [], "interactive": [], "unknown": []}
        for tr in transport_rows:
            if tr.get("group_key") == group_key:
                by_mode.setdefault(str(tr.get("mode") or "unknown"), []).append(tr)

        def _wavg(pairs: list[tuple[float | None, int]]) -> float | None:
            num = 0.0
            den = 0.0
            for v, w in pairs:
                if v is None:
                    continue
                if w <= 0:
                    continue
                num += float(v) * float(w)
                den += float(w)
            return (num / den) if den > 0 else None

        for mode, rs in sorted(by_mode.items(), key=lambda kv: _mode_rank(kv[0])):
            if not rs:
                continue
            transport_group_mode_rows.append(
                {
                    "group_key": group_key,
                    "package_name": pkg,
                    "mode": mode,
                    "tls_ratio": _wavg([(_safe_float(r.get("tls_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "quic_ratio": _wavg([(_safe_float(r.get("quic_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "tcp_ratio": _wavg([(_safe_float(r.get("tcp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "udp_ratio": _wavg([(_safe_float(r.get("udp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                    "pcap_bytes_total": int(sum(int(r.get("pcap_bytes") or 0) for r in rs)),
                }
            )

        runs_scored += len(by_run_rows)

    _write_tables(
        snapshot_dir,
        per_run_rows=per_run_prevalence,
        per_group_mode_rows=per_group_mode_prevalence,
        overlap_rows=overlap_rows,
        transport_rows=transport_rows,
        transport_group_mode_rows=transport_group_mode_rows,
    )
    _write_snapshot_summary(
        snapshot_dir,
        {
            "snapshot_id": sid,
            "selector_type": selection.selector_type,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "groups_seen": int(groups_seen),
            "groups_trained": int(groups_trained),
            "groups_skipped_no_baseline": int(groups_skipped_no_baseline),
            "groups_union_fallback": int(groups_union_fallback),
            "groups_baseline_thin": int(groups_baseline_thin),
            "runs_selected": int(len(selection.included)),
            "runs_scored": int(runs_scored),
            "runs_skipped": int(runs_skipped + skipped_runs),
            "outputs": {
                "selection_manifest": str(manifest_path),
                "tables_dir": str(snapshot_dir / "tables"),
                "runs_dir": str(snapshot_dir / "runs"),
            },
        },
    )

    return QueryMlRunStats(
        groups_seen=int(groups_seen),
        groups_trained=int(groups_trained),
        runs_scored=int(runs_scored),
        runs_skipped=int(runs_skipped + skipped_runs),
        snapshot_id=sid,
        snapshot_dir=snapshot_dir,
        generated_at_utc=datetime.now(UTC).isoformat(),
    )


__all__ = ["QueryMlRunStats", "run_ml_query_mode"]
