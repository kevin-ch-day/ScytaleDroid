"""Batch ML runner over evidence packs (Paper #2, DB-free).

Phase E v1.2 (locked posture):
- Selector is the checksummed freeze manifest (included_run_ids).
- Evidence packs remain authoritative; ML never reads DB.
- Windowing is deterministic (10s/5s, drop partials).
- Per-app models: IsolationForest + OneClassSVM (fixed params).
- Training: baseline-only per app; fallback to union if baseline fails quality gates.
- Thresholding: 95th percentile of training distribution (per model x app).
- Output is immutable after freeze (no overwrite; versioned paths).
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import shutil

from scytaledroid.Config import app_config

from . import ml_parameters_paper2 as config
from .seed_identity import derive_seed, salt_metadata
from .anomaly_model_training import anomaly_scores, fit_model, fixed_model_specs
from .pcap_window_features import build_window_features, extract_packet_timeline, write_anomaly_scores_csv
from .evidence_pack_ml_preflight import (
    RunInputs,
    compute_ml_preflight,
    get_sampling_duration_seconds,
    is_valid_dataset_run,
    load_run_inputs,
    write_ml_preflight,
)
from .telemetry_windowing import WindowSpec


FREEZE_DIR = Path(app_config.DATA_DIR) / "archive"
DATASET_FREEZE_CANONICAL = FREEZE_DIR / config.FREEZE_CANONICAL_FILENAME


@dataclass(frozen=True)
class MlRunStats:
    apps_seen: int
    apps_trained: int
    runs_scored: int
    runs_skipped: int
    generated_at: str


@dataclass(frozen=True)
class _ExemplarCandidate:
    run_id: str
    package_name: str
    interaction_tag: str
    ended_at: str | None
    sustained_bytes_per_sec_k6: float
    iforest_flagged_pct: float
    ocsvm_flagged_pct: float


def run_ml_on_evidence_packs(
    *,
    output_root: Path | None = None,
    freeze_manifest_path: Path | None = None,
    reuse_existing_outputs: bool = True,
) -> MlRunStats:
    """Run Paper #2 ML over evidence packs.

    Selector (PM/reviewer locked):
    - Use the canonical freeze anchor unless an explicit freeze_manifest_path is provided.
    - Fail closed if the freeze manifest is missing required checksum fields.

    Hard rules (Paper #2):
    - No DB reads for selection/training/scoring.
    - No exploratory-mode fallback.
    """

    root = output_root or (Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic")
    if not root.exists():
        return MlRunStats(0, 0, 0, 0, datetime.now(UTC).isoformat())

    freeze_path = freeze_manifest_path or DATASET_FREEZE_CANONICAL
    if not freeze_path.exists():
        raise RuntimeError(f"Freeze manifest missing (fail-closed): {freeze_path}")
    frozen = True

    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)

    apps_trained = 0
    runs_scored = 0
    runs_skipped = 0

    dataset_phase_rows: list[dict[str, Any]] = []
    model_overlap_rows: list[dict[str, Any]] = []
    transport_mix_rows: list[dict[str, Any]] = []
    exemplar_candidate: _ExemplarCandidate | None = None

    if frozen:
        assert freeze_path is not None
        freeze = _load_freeze_payload(freeze_path)
        included_run_ids = _load_frozen_run_ids_from_payload(freeze)
        freeze_apps = freeze.get("apps") if isinstance(freeze.get("apps"), dict) else None
        checksums = freeze.get("included_run_checksums") if isinstance(freeze.get("included_run_checksums"), dict) else None
        if included_run_ids is None or freeze_apps is None or checksums is None:
            raise RuntimeError(f"Freeze manifest missing required fields: {freeze_path}")

        # Fast path: if all per-run v1 outputs already exist, do not re-run tshark/modeling.
        # This keeps "run Phase E" idempotent and avoids accidental long reprocessing runs.
        if reuse_existing_outputs and _all_frozen_v1_outputs_exist(root, included_run_ids):
            apps_seen = 0
            for pkg, entry in sorted(freeze_apps.items()):
                if not isinstance(entry, dict):
                    continue
                base_ids = entry.get("baseline_run_ids") or []
                inter_ids = entry.get("interactive_run_ids") or []
                if isinstance(base_ids, list) and isinstance(inter_ids, list) and len(base_ids) >= 1 and len(inter_ids) >= 2:
                    apps_seen += 1
            return MlRunStats(
                apps_seen=apps_seen,
                apps_trained=apps_seen,
                runs_scored=len(included_run_ids),
                runs_skipped=0,
                generated_at=datetime.now(UTC).isoformat(),
            )

        apps_seen = 0
        for pkg in sorted(freeze_apps.keys()):
            entry = freeze_apps.get(pkg)
            if not isinstance(entry, dict):
                continue
            base_ids = entry.get("baseline_run_ids") or []
            inter_ids = entry.get("interactive_run_ids") or []
            if not (isinstance(base_ids, list) and isinstance(inter_ids, list)):
                continue
            if len(base_ids) < 1 or len(inter_ids) < 2:
                continue

            baseline_id = str(base_ids[0])
            interactive_ids = [str(x) for x in inter_ids[:2]]
            interactive_ids = sorted(
                interactive_ids,
                key=lambda rid: (_parse_ended_at_epoch((checksums.get(rid) or {}).get("ended_at")), rid),
            )
            run_ids = [baseline_id] + interactive_ids

            # Load runs (freeze is fail-closed: these must exist and be VALID).
            app_runs: list[RunInputs] = []
            for rid in run_ids:
                if rid not in included_run_ids:
                    raise RuntimeError(f"Freeze manifest inconsistency: {rid} not in included_run_ids")
                run_dir = root / rid
                inputs = load_run_inputs(run_dir)
                if not inputs:
                    raise RuntimeError(f"Included run missing/invalid run_manifest.json: {rid}")
                if not is_valid_dataset_run(inputs):
                    raise RuntimeError(f"Included run is not VALID dataset run: {rid}")
                app_runs.append(inputs)

            apps_seen += 1
            # Seed identity key contract: plan identity key preferred, fall back to package.
            identity_key = next((r.identity_key for r in app_runs if r.identity_key), None) or pkg
            seed = derive_seed(identity_key)
            specs = fixed_model_specs(seed)

            # Phase labels are freeze-derived and deterministic.
            per_run_phase = {
                baseline_id: "idle",
                interactive_ids[0]: "interactive_a",
                interactive_ids[1]: "interactive_b",
            }
            per_run_tag = {r.run_id: _interaction_tag_from_manifest(r.manifest) for r in app_runs}

            # Extract windows for each run (always write ML preflight).
            per_run_rows: dict[str, tuple[list[dict[str, Any]], int]] = {}
            all_rows: list[dict[str, Any]] = []

            for r in sorted(app_runs, key=lambda rr: rr.run_id):
                out_dir_pf = _ml_output_dir(r.run_dir, frozen=True)
                out_dir_pf.mkdir(parents=True, exist_ok=True)
                pf_path = out_dir_pf / "ml_preflight.json"
                if not pf_path.exists():
                    write_ml_preflight(pf_path, compute_ml_preflight(r))
                # Back-compat: some earlier v1 outputs used internal model names in filenames.
                # Copy them to the canonical paper-facing filenames without recomputation.
                _ensure_score_csv_aliases(out_dir_pf)

                duration = get_sampling_duration_seconds(r)
                if duration is None or duration <= 0:
                    _write_run_skip(r, frozen=True, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                    runs_skipped += 1
                    continue
                if not r.pcap_path or not r.pcap_path.exists():
                    _write_run_skip(r, frozen=True, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                    runs_skipped += 1
                    continue

                packets = extract_packet_timeline(r.pcap_path)
                rows, dropped = build_window_features(packets, duration_s=float(duration), spec=window_spec)
                if not rows:
                    _write_run_skip(r, frozen=True, reason="ML_SKIPPED_INSUFFICIENT_WINDOWS")
                    runs_skipped += 1
                    continue

                # Attach deterministic metadata for downstream grouping.
                for row in rows:
                    row["_run_id"] = r.run_id
                    row["_phase"] = per_run_phase.get(r.run_id) or _fallback_phase(r.run_profile)

                per_run_rows[r.run_id] = (rows, dropped)
                all_rows.extend(rows)

            # Require all three included runs windowed for Phase E outputs.
            if len(per_run_rows) < 3:
                _write_app_skip(app_runs, frozen=True, reason="ML_SKIPPED_INSUFFICIENT_RUNS")
                runs_skipped += len(app_runs)
                continue

            # Training selection (v1.2):
            # Primary: baseline-only; fallback: union if baseline fails bytes/windows gates.
            baseline_rows = per_run_rows.get(baseline_id, ([], 0))[0]
            bytes_ok, min_bytes = _baseline_bytes_gate_ok(app_runs, baseline_rid=baseline_id)
            windows_ok = len(baseline_rows) >= int(config.MIN_WINDOWS_BASELINE)
            if bytes_ok and windows_ok and baseline_rows:
                training_mode = "baseline_only"
                train_rows = baseline_rows
            else:
                training_mode = "union_fallback"
                train_rows = []
                for rid, (rows, _) in per_run_rows.items():
                    train_rows.extend(rows)

            X_train, feature_names = _rows_to_matrix(train_rows, window_spec=window_spec)
            X_all, _ = _rows_to_matrix(all_rows, window_spec=window_spec)
            if X_train.size == 0 or X_train.shape[0] < 3 or X_all.size == 0:
                _write_app_skip(app_runs, frozen=True, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                runs_skipped += len(app_runs)
                continue

            apps_trained += 1

            per_model_scores_by_run: dict[str, dict[str, list[float]]] = {}
            per_model_thresholds: dict[str, float] = {}
            model_outputs: dict[str, dict[str, Any]] = {}

            for spec in specs:
                model = fit_model(spec, X_train)
                scores_train = anomaly_scores(spec.name, model, X_train)
                scores_all = anomaly_scores(spec.name, model, X_all)
                threshold = float(np.percentile(scores_train, config.THRESHOLD_PERCENTILE))

                per_model_thresholds[spec.name] = threshold
                model_outputs[spec.name] = {
                    "threshold_percentile": config.THRESHOLD_PERCENTILE,
                    "threshold_value": threshold,
                    "training_samples": int(X_train.shape[0]),
                    "feature_names": list(feature_names),
                    "params": dict(spec.params),
                    "score_semantics": "higher_is_more_anomalous",
                    "training_mode": training_mode,
                    "quality_gates": {
                        "baseline_min_pcap_bytes": int(min_bytes),
                        "baseline_pcap_bytes_ok": bool(bytes_ok),
                        "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
                        "baseline_windows_ok": bool(windows_ok),
                    },
                }

                # Split score stream back into per-run rows (deterministic order).
                by_run_rows: dict[str, list[dict[str, Any]]] = {}
                by_run_scores: dict[str, list[float]] = {}
                for row, score in zip(all_rows, scores_all, strict=True):
                    rid = str(row.get("_run_id") or "")
                    if not rid:
                        continue
                    by_run_scores.setdefault(rid, []).append(float(score))
                    by_run_rows.setdefault(rid, []).append(
                        {
                            "window_start_s": row["window_start_s"],
                            "window_end_s": row["window_end_s"],
                            "score": float(score),
                            "threshold": float(threshold),
                            "is_anomalous": bool(float(score) >= float(threshold)),
                        }
                    )
                per_model_scores_by_run[spec.name] = by_run_scores

                for r in app_runs:
                    out_dir = _ml_output_dir(r.run_dir, frozen=True)
                    out_dir.mkdir(parents=True, exist_ok=True)
                    scores_path = out_dir / f"anomaly_scores_{_model_csv_label(spec.name)}.csv"
                    if scores_path.exists():
                        continue  # immutable
                    write_anomaly_scores_csv(scores_path, by_run_rows.get(r.run_id) or [])

            # Write per-run manifests/summaries.
            for r in app_runs:
                out_dir = _ml_output_dir(r.run_dir, frozen=True)
                out_dir.mkdir(parents=True, exist_ok=True)
                manifest_path = out_dir / "model_manifest.json"
                summary_path = out_dir / "ml_summary.json"
                if manifest_path.exists() or summary_path.exists():
                    continue  # immutable

                _write_model_manifest(
                    manifest_path,
                    run_inputs=r,
                    identity_key_used=identity_key,
                    seed=seed,
                    window_spec=window_spec,
                    model_outputs=model_outputs,
                    freeze_manifest_path=str(freeze_path),
                )
                _write_ml_summary(
                    summary_path,
                    run_inputs=r,
                    phase=per_run_phase.get(r.run_id) or _fallback_phase(r.run_profile),
                    interaction_tag=per_run_tag.get(r.run_id),
                    window_rows=per_run_rows[r.run_id][0],
                    dropped_partial_windows=per_run_rows[r.run_id][1],
                    model_outputs=model_outputs,
                    out_dir=out_dir,
                )
                runs_scored += 1

            # Dataset-level derived outputs (not frozen inputs).
            dataset_phase_rows.extend(
                _compute_phase_rows(
                    identity_key=identity_key,
                    package_name=pkg,
                    app_runs=app_runs,
                    per_model_scores_by_run=per_model_scores_by_run,
                    per_model_thresholds=per_model_thresholds,
                    per_run_phase=per_run_phase,
                    per_run_tag=per_run_tag,
                    training_mode=training_mode,
                )
            )
            model_overlap_rows.extend(
                _compute_model_overlap_rows(
                    package_name=pkg,
                    app_runs=app_runs,
                    per_model_scores_by_run=per_model_scores_by_run,
                    per_model_thresholds=per_model_thresholds,
                    per_run_phase=per_run_phase,
                    per_run_tag=per_run_tag,
                    training_mode=training_mode,
                )
            )
            transport_mix_rows.extend(
                _compute_transport_mix_rows(
                    package_name=pkg,
                    app_runs=app_runs,
                    per_run_phase=per_run_phase,
                    per_run_tag=per_run_tag,
                )
            )
            exemplar_candidate = _select_fig_b1_exemplar_candidate(
                current=exemplar_candidate,
                package_name=pkg,
                interactive_run_ids=interactive_ids,
                per_run_rows=per_run_rows,
                per_run_tag=per_run_tag,
                per_model_scores_by_run=per_model_scores_by_run,
                per_model_thresholds=per_model_thresholds,
                checksums=checksums,
            )

        _write_prevalence_csvs(dataset_phase_rows)
        _write_model_overlap_csv(model_overlap_rows)
        _write_transport_mix_csvs(transport_mix_rows)
        _maybe_write_paper_artifacts_json(
            candidate=exemplar_candidate,
            freeze_manifest_path=freeze_path,
        )
        return MlRunStats(
            apps_seen=apps_seen,
            apps_trained=apps_trained,
            runs_scored=runs_scored,
            runs_skipped=runs_skipped,
            generated_at=datetime.now(UTC).isoformat(),
        )


def _all_frozen_v1_outputs_exist(root: Path, included_run_ids: set[str]) -> bool:
    """Return True if all included runs already have the required v1 outputs on disk."""
    req = [
        "analysis/ml/v1/model_manifest.json",
        "analysis/ml/v1/ml_summary.json",
        "analysis/ml/v1/anomaly_scores_iforest.csv",
        "analysis/ml/v1/anomaly_scores_ocsvm.csv",
    ]
    for rid in included_run_ids:
        run_dir = root / rid
        if not run_dir.exists():
            return False
        for rel in req:
            if not (run_dir / rel).exists():
                return False
    return True


def _load_freeze_payload(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to read freeze manifest: {path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Freeze manifest is not an object: {path}")
    return payload


def _load_frozen_run_ids_from_payload(payload: dict[str, Any]) -> set[str] | None:
    ids = payload.get("included_run_ids")
    if not isinstance(ids, list):
        return None
    out: set[str] = set()
    for rid in ids:
        if isinstance(rid, str) and rid:
            out.add(rid)
    return out or None


def _parse_ended_at_epoch(value: object) -> float:
    if not isinstance(value, str) or not value.strip():
        return float("inf")
    s = value.strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except Exception:
        return float("inf")


def _interaction_tag_from_manifest(manifest: dict[str, Any]) -> str | None:
    op = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    msg = str(op.get("messaging_activity") or "").strip().lower()
    if msg:
        return msg
    inter = str(op.get("interaction_level") or "").strip().lower()
    return inter or None


def _canonical_interaction_tag(tag: str | None) -> str | None:
    if not tag:
        return None
    t = str(tag).strip().lower()
    if not t:
        return None
    if "video" in t:
        return "video"
    if "voice" in t or "audio" in t:
        return "voice"
    if "text" in t:
        return "text"
    if "mixed" in t:
        return "mixed"
    if "none" in t:
        return "none"
    return t


def _fallback_phase(run_profile: str | None) -> str:
    if not run_profile:
        return "interactive"
    p = run_profile.lower()
    if "baseline" in p or "idle" in p:
        return "idle"
    return "interactive"


def _model_csv_label(model_name: str) -> str:
    """Stable, paper-facing model label used in output filenames."""
    if model_name == config.MODEL_IFOREST:
        return "iforest"
    if model_name == config.MODEL_OCSVM:
        return "ocsvm"
    return model_name


def _ensure_score_csv_aliases(out_dir: Path) -> None:
    """Ensure canonical anomaly score CSV names exist (Paper #2) without recomputation.

    Earlier runs wrote:
      - anomaly_scores_isolation_forest.csv
      - anomaly_scores_one_class_svm.csv
    Paper-facing canonical names are:
      - anomaly_scores_iforest.csv
      - anomaly_scores_ocsvm.csv

    This function only copies when the old file exists and the new one does not.
    """
    mapping = {
        "anomaly_scores_isolation_forest.csv": "anomaly_scores_iforest.csv",
        "anomaly_scores_one_class_svm.csv": "anomaly_scores_ocsvm.csv",
    }
    for old, new in mapping.items():
        src = out_dir / old
        dst = out_dir / new
        if dst.exists():
            continue
        if not src.exists():
            continue
        try:
            shutil.copyfile(src, dst)
        except Exception:
            # Best-effort. If this fails, the runner may still write the canonical
            # files during a full ML run.
            pass


def _baseline_bytes_gate_ok(app_runs: list[RunInputs], *, baseline_rid: str) -> tuple[bool, int]:
    baseline = next((r for r in app_runs if r.run_id == baseline_rid), None)
    if not baseline:
        return False, int(config.MIN_PCAP_BYTES_FALLBACK)

    ds = baseline.manifest.get("dataset") if isinstance(baseline.manifest.get("dataset"), dict) else {}
    min_bytes = ds.get("min_pcap_bytes")
    try:
        min_bytes_i = int(min_bytes) if min_bytes is not None else int(config.MIN_PCAP_BYTES_FALLBACK)
    except Exception:
        min_bytes_i = int(config.MIN_PCAP_BYTES_FALLBACK)

    size_bytes = None
    if isinstance(baseline.pcap_report, dict):
        sb = baseline.pcap_report.get("pcap_size_bytes")
        try:
            if sb is not None:
                size_bytes = int(sb)
        except Exception:
            size_bytes = None
    if size_bytes is None and baseline.pcap_path and baseline.pcap_path.exists():
        try:
            size_bytes = int(baseline.pcap_path.stat().st_size)
        except Exception:
            size_bytes = None
    if size_bytes is None:
        return False, min_bytes_i
    return bool(size_bytes >= min_bytes_i), min_bytes_i


def _rows_to_matrix(rows: list[dict[str, Any]], *, window_spec: WindowSpec) -> tuple[np.ndarray, list[str]]:
    denom = float(window_spec.window_size_s) if window_spec.window_size_s > 0 else 1.0
    feature_names = ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"]
    data: list[list[float]] = []
    for row in rows:
        try:
            byte_count = float(row.get("byte_count") or 0.0)
            pkt_count = float(row.get("packet_count") or 0.0)
            avg_pkt = float(row.get("avg_packet_size_bytes") or 0.0)
            data.append([byte_count / denom, pkt_count / denom, avg_pkt])
        except Exception:
            continue
    if not data:
        return np.zeros((0, len(feature_names)), dtype=float), feature_names
    return np.asarray(data, dtype=float), feature_names


def _ml_output_dir(run_dir: Path, *, frozen: bool) -> Path:
    if frozen:
        return run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL
    return run_dir / "analysis" / "ml_provisional" / config.ML_SCHEMA_LABEL


def _compute_phase_rows(
    *,
    identity_key: str,
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
        threshold = float(per_model_thresholds.get(model_name) or 0.0)
        for r in app_runs:
            run_scores = scores_by_run.get(r.run_id) or []
            if not run_scores:
                continue
            arr = np.asarray(run_scores, dtype=float)
            phase = per_run_phase.get(r.run_id) or _fallback_phase(r.run_profile)
            tag = per_run_tag.get(r.run_id) or ""
            ds = r.manifest.get("dataset") if isinstance(r.manifest.get("dataset"), dict) else {}
            anomalous = int(sum(1 for s in run_scores if float(s) >= threshold))
            rows.append(
                {
                    "identity_key": identity_key,
                    "package_name": package_name,
                    "run_id": r.run_id,
                    "phase": phase,
                    "interaction_tag": tag,
                    "model": model_name,
                    "training_mode": training_mode,
                    "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
                    "windows_total": int(arr.shape[0]),
                    "median": float(statistics.median(run_scores)),
                    "p95": float(np.percentile(arr, 95.0)),
                    "max": float(np.max(arr)),
                    "anomalous_windows": anomalous,
                    "anomalous_pct": float(anomalous) / float(arr.shape[0]) if arr.shape[0] > 0 else 0.0,
                    "threshold_value": float(threshold),
                    "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )
    return rows


def _write_prevalence_csvs(rows: list[dict[str, Any]]) -> None:
    """Write dataset-level anomaly prevalence tables.

    Paper #2 (locked):
    - Main table is per-app and has only two phases: idle vs interactive (concatenated windows).
    - Detailed per-run/per-model distributions are written to a separate appendix file.
    """
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    main_path = out_dir / "anomaly_prevalence_per_app_phase.csv"
    appendix_path = out_dir / "anomaly_prevalence_per_run.csv"
    import csv

    # Appendx: per-run/per-model with distribution stats.
    appendix_fields = [
        "identity_key",
        "package_name",
        "run_id",
        "phase",
        "interaction_tag",
        "model",
        "training_mode",
        "low_signal",
        "windows_total",
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

    # Main: per-app, idle vs interactive_concat (concatenated windows, no per-run averaging).
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
                "training_mode": row.get("training_mode"),
                "ml_schema_version": row.get("ml_schema_version"),
            }
            agg[key] = cur
        try:
            cur["windows_total"] += int(row.get("windows_total") or 0)
            cur["windows_flagged"] += int(row.get("anomalous_windows") or 0)
        except Exception:
            continue

    main_fields = [
        "package_name",
        "phase",
        "model",
        "windows_total",
        "windows_flagged",
        "flagged_pct",
        "training_mode",
        "ml_schema_version",
    ]
    rows_out: list[dict[str, Any]] = []
    for (_, _, _), cur in sorted(agg.items(), key=lambda kv: (kv[1]["package_name"], kv[1]["phase"], kv[1]["model"])):
        total = int(cur.get("windows_total") or 0)
        flagged = int(cur.get("windows_flagged") or 0)
        pct = (float(flagged) / float(total)) if total > 0 else 0.0
        out = dict(cur)
        out["flagged_pct"] = pct
        rows_out.append(out)
    with main_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=main_fields)
        writer.writeheader()
        for row in rows_out:
            writer.writerow({k: row.get(k) for k in main_fields})


def _compute_model_overlap_rows(
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
        phase = per_run_phase.get(r.run_id) or _fallback_phase(r.run_profile)
        tag = per_run_tag.get(r.run_id) or ""
        rows.append(
            {
                "package_name": package_name,
                "run_id": r.run_id,
                "phase": phase,
                "interaction_tag": tag,
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
    return rows


def _write_model_overlap_csv(rows: list[dict[str, Any]]) -> None:
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "model_overlap_per_run.csv"
    fieldnames = [
        "package_name",
        "run_id",
        "phase",
        "interaction_tag",
        "training_mode",
        "windows_total",
        "iforest_flagged",
        "ocsvm_flagged",
        "both_flagged",
        "either_flagged",
        "jaccard",
        "ml_schema_version",
    ]
    import csv

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})


def _compute_transport_mix_rows(
    *,
    package_name: str,
    app_runs: list[RunInputs],
    per_run_phase: dict[str, str],
    per_run_tag: dict[str, str | None],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in app_runs:
        tls, quic, tcp, udp = _transport_ratios_from_inputs(r)
        phase = per_run_phase.get(r.run_id) or _fallback_phase(r.run_profile)
        tag = per_run_tag.get(r.run_id) or ""
        pcap_bytes = _pcap_size_bytes_from_inputs(r)
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


def _write_transport_mix_csvs(rows: list[dict[str, Any]]) -> None:
    """Write transport mix tables.

    Paper #2 main table: per-app, idle vs interactive (weighted by PCAP bytes when available).
    """
    out_dir = Path(app_config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    main_path = out_dir / "transport_mix_by_phase.csv"
    appendix_path = out_dir / "transport_mix_per_run.csv"
    import csv

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

    # Aggregate idle vs interactive (bytes-weighted when available).
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
        # fall back to unweighted mean of non-null
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
                "tls_ratio": wavg([( _safe_float(r.get("tls_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                "quic_ratio": wavg([( _safe_float(r.get("quic_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                "tcp_ratio": wavg([( _safe_float(r.get("tcp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
                "udp_ratio": wavg([( _safe_float(r.get("udp_ratio")), int(r.get("pcap_bytes") or 0)) for r in rs]),
            }
        )
    with main_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=main_fields)
        writer.writeheader()
        for row in out_rows:
            writer.writerow({k: row.get(k) for k in main_fields})


def _pcap_size_bytes_from_inputs(inputs: RunInputs) -> int | None:
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


def _maybe_write_paper_artifacts_json(*, candidate: _ExemplarCandidate | None, freeze_manifest_path: Path) -> None:
    """Write a stable, human-readable lock file for the paper's flagship timeline exemplar.

    This file is dataset-adjacent (stored next to the freeze manifest) and is never overwritten.
    """
    path = FREEZE_DIR / "paper_artifacts.json"
    if path.exists():
        return
    if not candidate:
        # No eligible exemplar (e.g., no video-tagged interactive runs). Leave absent rather than guessing.
        return
    payload: dict[str, Any] = {
        "freeze_anchor": str(freeze_manifest_path),
        "fig_B1_run_id": candidate.run_id,
        "package_name": candidate.package_name,
        "interaction_tag": candidate.interaction_tag,
        "ended_at": candidate.ended_at,
        "selection_metric": "sustained_bytes_per_sec_k6",
        "tie_breakers": ["iforest_prevalence", "ocsvm_prevalence", "ended_at"],
        "metrics": {
            "sustained_bytes_per_sec_k6": float(candidate.sustained_bytes_per_sec_k6),
            "iforest_flagged_pct": float(candidate.iforest_flagged_pct),
            "ocsvm_flagged_pct": float(candidate.ocsvm_flagged_pct),
        },
        "written_at": datetime.now(UTC).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _select_fig_b1_exemplar_candidate(
    *,
    current: _ExemplarCandidate | None,
    package_name: str,
    interactive_run_ids: list[str],
    per_run_rows: dict[str, tuple[list[dict[str, Any]], int]],
    per_run_tag: dict[str, str | None],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
    checksums: dict[str, Any],
    k_windows: int = 6,
) -> _ExemplarCandidate | None:
    """Select the canonical Fig B1 exemplar candidate deterministically.

    Reviewer protocol (Paper #2):
    - Consider only interactive runs with unambiguous video tag.
    - Primary metric: sustained bytes/sec over >=K consecutive windows (K=6 => 30s).
    - Tie breakers: higher IF prevalence, then higher OC-SVM prevalence, then later ended_at.
    """
    if config.MODEL_IFOREST not in per_model_scores_by_run or config.MODEL_OCSVM not in per_model_scores_by_run:
        return current

    if_thr = float(per_model_thresholds.get(config.MODEL_IFOREST) or 0.0)
    oc_thr = float(per_model_thresholds.get(config.MODEL_OCSVM) or 0.0)

    for rid in interactive_run_ids:
        tag_raw = per_run_tag.get(rid)
        tag = _canonical_interaction_tag(tag_raw)
        if tag != "video":
            continue
        run_rows = per_run_rows.get(rid, ([], 0))[0]
        if not run_rows:
            continue
        bps = []
        denom = float(config.WINDOW_SIZE_S) if float(config.WINDOW_SIZE_S) > 0 else 1.0
        for row in run_rows:
            try:
                bps.append(float(row.get("byte_count") or 0.0) / denom)
            except Exception:
                continue
        if len(bps) < int(k_windows):
            continue
        # Sustained metric: max rolling mean over K windows.
        best = 0.0
        s = sum(bps[:k_windows])
        best = max(best, float(s) / float(k_windows))
        for i in range(k_windows, len(bps)):
            s += bps[i] - bps[i - k_windows]
            best = max(best, float(s) / float(k_windows))

        if_scores = per_model_scores_by_run[config.MODEL_IFOREST].get(rid) or []
        oc_scores = per_model_scores_by_run[config.MODEL_OCSVM].get(rid) or []
        if not if_scores or not oc_scores:
            continue
        if_pct = float(sum(1 for x in if_scores if float(x) >= if_thr)) / float(len(if_scores)) if if_scores else 0.0
        oc_pct = float(sum(1 for x in oc_scores if float(x) >= oc_thr)) / float(len(oc_scores)) if oc_scores else 0.0

        ended_at = None
        blk = checksums.get(rid) if isinstance(checksums.get(rid), dict) else {}
        ended_at = blk.get("ended_at") if isinstance(blk, dict) else None

        cand = _ExemplarCandidate(
            run_id=rid,
            package_name=package_name,
            interaction_tag=tag,
            ended_at=str(ended_at) if ended_at is not None else None,
            sustained_bytes_per_sec_k6=float(best),
            iforest_flagged_pct=float(if_pct),
            ocsvm_flagged_pct=float(oc_pct),
        )
        if not current:
            current = cand
            continue

        # Primary
        if cand.sustained_bytes_per_sec_k6 > current.sustained_bytes_per_sec_k6 + 1e-12:
            current = cand
            continue
        if abs(cand.sustained_bytes_per_sec_k6 - current.sustained_bytes_per_sec_k6) <= 1e-12:
            # Tie 1: IF prevalence
            if cand.iforest_flagged_pct > current.iforest_flagged_pct + 1e-12:
                current = cand
                continue
            if abs(cand.iforest_flagged_pct - current.iforest_flagged_pct) <= 1e-12:
                # Tie 2: OC-SVM prevalence
                if cand.ocsvm_flagged_pct > current.ocsvm_flagged_pct + 1e-12:
                    current = cand
                    continue
                if abs(cand.ocsvm_flagged_pct - current.ocsvm_flagged_pct) <= 1e-12:
                    # Tie 3: later ended_at (fallback: lexical run_id)
                    a = _parse_ended_at_epoch(current.ended_at)
                    b = _parse_ended_at_epoch(cand.ended_at)
                    if b > a + 1e-9:
                        current = cand
                        continue
                    if abs(b - a) <= 1e-9 and cand.run_id > current.run_id:
                        current = cand
                        continue
    return current


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
    quic_ratio = float(quic_b) / float(udp_b) if udp_b > 0 else None
    tcp_ratio = float(tcp_b) / total if total > 0 else None
    udp_ratio = float(udp_b) / total if total > 0 else None
    return tls_ratio, quic_ratio, tcp_ratio, udp_ratio


def _safe_float(v: object) -> float | None:
    try:
        if v is None:
            return None
        f = float(v)
        if f < 0.0:
            return None
        return f
    except Exception:
        return None


def _write_model_manifest(
    path: Path,
    *,
    run_inputs: RunInputs,
    identity_key_used: str,
    seed: int,
    window_spec: WindowSpec,
    model_outputs: dict[str, dict[str, Any]],
    freeze_manifest_path: str | None,
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
        "frozen": bool(freeze_manifest_path),
        "freeze_manifest_path": freeze_manifest_path,
        "identity_key_used": identity_key_used,
        "seed": int(seed),
        **salt_metadata(),
        "windowing": {
            "window_size_s": float(window_spec.window_size_s),
            "stride_s": float(window_spec.stride_s),
            "drop_partial_windows": True,
            "timebase": "pcap_time_relative_seconds",
        },
        "score_semantics": "higher_is_more_anomalous",
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
    phase: str,
    interaction_tag: str | None,
    window_rows: list[dict[str, Any]],
    dropped_partial_windows: int,
    model_outputs: dict[str, dict[str, Any]],
    out_dir: Path,
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
        "skip": None,
    }
    for model_name, meta in model_outputs.items():
        csv_path = out_dir / f"anomaly_scores_{model_name}.csv"
        if not csv_path.exists():
            continue
        scores = _load_scores(csv_path)
        if not scores:
            continue
        threshold = float(meta.get("threshold_value") or 0.0)
        payload["models"][model_name] = {
            "median": float(statistics.median(scores)),
            "p95": float(np.percentile(np.asarray(scores, dtype=float), 95.0)),
            "max": float(max(scores)),
            "anomalous_windows": int(sum(1 for s in scores if float(s) >= threshold)),
            "threshold_value": float(threshold),
            "threshold_percentile": float(meta.get("threshold_percentile") or config.THRESHOLD_PERCENTILE),
            "training_mode": meta.get("training_mode"),
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


__all__ = ["MlRunStats", "run_ml_on_evidence_packs"]
