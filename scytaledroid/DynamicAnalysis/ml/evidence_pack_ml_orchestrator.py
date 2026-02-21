"""Batch ML runner over evidence packs (Paper #2, DB-free).

Phase E v1.2 (locked posture):
- Selector is the checksummed freeze manifest (included_run_ids).
- Evidence packs remain authoritative; ML never reads DB.
- Windowing is deterministic (10s/5s, drop partials).
- Per-app models: IsolationForest + OneClassSVM (fixed params).
- Training: baseline-only per app; fail-closed when baseline quality gates fail.
- Thresholding: 95th percentile of training distribution (per model x app).
- Output is immutable after freeze (no overwrite; versioned paths).
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q

from . import ml_parameters_paper2 as config
from .anomaly_model_training import anomaly_scores, fit_model, fixed_model_specs
from .evidence_pack_ml_preflight import (
    RunInputs,
    compute_ml_preflight,
    get_sampling_duration_seconds,
    is_valid_dataset_run,
    load_run_inputs,
    write_ml_preflight,
)
from .io import MLOutputPaths
from .numpy_percentile import percentile as np_percentile
from .pcap_window_features import (
    build_window_features,
    extract_packet_timeline,
    write_anomaly_scores_csv,
)
from .seed_identity import derive_seed, salt_metadata
from .telemetry_windowing import WindowSpec

FREEZE_DIR = Path(app_config.DATA_DIR) / "archive"
DATASET_FREEZE_CANONICAL = FREEZE_DIR / config.FREEZE_CANONICAL_FILENAME
PAPER_ARTIFACTS_PATH = FREEZE_DIR / "paper_artifacts.json"
PAPER_EXCLUSION_REASON_CODES = {
    "ML_SKIPPED_BASELINE_GATE_FAIL",
    "ML_SKIPPED_MISSING_FREEZE_MANIFEST",
    "ML_SKIPPED_BAD_FREEZE_CHECKSUM",
    "ML_SKIPPED_MISSING_STATIC_LINK",
    "ML_SKIPPED_MISSING_BASE_APK_SHA256",
    "ML_SKIPPED_MISSING_STATIC_FEATURES",
    "ML_SKIPPED_APK_CHANGED_DURING_RUN",
}


@dataclass(frozen=True)
class MlRunStats:
    apps_seen: int
    apps_trained: int
    runs_scored: int
    runs_skipped: int
    generated_at: str
    # Runs whose v1 outputs already existed and were reused (no overwrite).
    runs_reused: int = 0


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
        _write_global_cohort_status(
            root,
            reason="ML_SKIPPED_MISSING_FREEZE_MANIFEST",
            details={"freeze_manifest_path": str(freeze_path)},
        )
        raise RuntimeError(f"Freeze manifest missing (fail-closed): {freeze_path}")
    frozen = True

    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)

    apps_trained = 0
    runs_scored = 0  # "ready/complete" runs (includes reused outputs)
    runs_skipped = 0
    written_run_ids: set[str] = set()

    dataset_phase_rows: list[dict[str, Any]] = []
    model_overlap_rows: list[dict[str, Any]] = []
    transport_mix_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    exemplar_candidate: _ExemplarCandidate | None = None

    if frozen:
        assert freeze_path is not None
        freeze_sha = _sha256_file(freeze_path)
        try:
            freeze = _load_freeze_payload(freeze_path)
        except RuntimeError as exc:
            _write_global_cohort_status(
                root,
                reason="ML_SKIPPED_BAD_FREEZE_CHECKSUM",
                details={"freeze_manifest_path": str(freeze_path), "error": str(exc)},
            )
            raise
        included_run_ids = _load_frozen_run_ids_from_payload(freeze)
        freeze_apps = freeze.get("apps") if isinstance(freeze.get("apps"), dict) else None
        checksums = freeze.get("included_run_checksums") if isinstance(freeze.get("included_run_checksums"), dict) else None
        if included_run_ids is None or freeze_apps is None or checksums is None:
            _write_global_cohort_status(
                root,
                reason="ML_SKIPPED_BAD_FREEZE_CHECKSUM",
                details={"freeze_manifest_path": str(freeze_path), "error": "missing required fields"},
            )
            raise RuntimeError(f"Freeze manifest missing required fields: {freeze_path}")

        # Fast path: if all per-run v1 outputs already exist, do not re-run tshark/modeling.
        # Still ensure dataset-level derived tables and paper lockfiles exist (they are
        # regenerable but required for the paper bundle). If missing, rebuild from
        # existing v1 outputs without touching per-run artifacts.
        if reuse_existing_outputs and _all_frozen_v1_outputs_exist(root, included_run_ids):
            apps_seen = 0
            for _pkg, entry in sorted(freeze_apps.items()):
                if not isinstance(entry, dict):
                    continue
                base_ids = entry.get("baseline_run_ids") or []
                inter_ids = entry.get("interactive_run_ids") or []
                if isinstance(base_ids, list) and isinstance(inter_ids, list) and len(base_ids) >= 1 and len(inter_ids) >= 2:
                    apps_seen += 1

            # Ensure the canonical dataset-level CSVs exist. If they are missing, rebuild
            # them from per-run v1 outputs (DB-free) without recomputation.
            missing_tables = _missing_dataset_level_outputs()
            if missing_tables:
                _rebuild_dataset_outputs_from_v1(
                    evidence_root=root,
                    freeze_path=freeze_path,
                    freeze_payload=freeze,
                    freeze_apps=freeze_apps,
                    checksums=checksums,
                )

            # Ensure the exemplar lock exists. If absent, we allow a lightweight selection
            # pass (windowing) because this is a paper-facing artifact.
            if not PAPER_ARTIFACTS_PATH.exists():
                exemplar = _select_fig_b1_exemplar_from_existing_or_inputs(
                    evidence_root=root,
                    freeze_apps=freeze_apps,
                    checksums=checksums,
                )
                _maybe_write_paper_artifacts_json(candidate=exemplar, freeze_manifest_path=freeze_path)

            return MlRunStats(
                apps_seen=apps_seen,
                apps_trained=apps_seen,
                runs_scored=len(included_run_ids),
                runs_skipped=0,
                generated_at=datetime.now(UTC).isoformat(),
                runs_reused=len(included_run_ids),
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
            identity_key, identity_error, identity_details = _resolve_paper_identity_contract(app_runs)
            if not identity_key:
                _write_app_skip(
                    app_runs,
                    frozen=True,
                    reason=identity_error or "ML_SKIPPED_MISSING_STATIC_LINK",
                    details=identity_details,
                )
                runs_skipped += len(app_runs)
                continue
            seed = derive_seed(identity_key)
            specs = fixed_model_specs(seed)

            # Phase labels are freeze-derived and deterministic.
            per_run_phase = {
                baseline_id: "idle",
                interactive_ids[0]: "interactive_a",
                interactive_ids[1]: "interactive_b",
            }
            per_run_tag = {r.run_id: _interaction_tag_from_manifest(r.manifest) for r in app_runs}
            per_run_low_signal = {
                r.run_id: bool(
                    (r.manifest.get("dataset") if isinstance(r.manifest.get("dataset"), dict) else {}).get("low_signal") is True
                )
                for r in app_runs
            }

            # Extract windows for each run (always write ML preflight).
            per_run_rows: dict[str, tuple[list[dict[str, Any]], int]] = {}
            all_rows: list[dict[str, Any]] = []

            for r in sorted(app_runs, key=lambda rr: rr.run_id):
                out_dir_pf = _ml_output_dir(r.run_dir, frozen=True)
                out_dir_pf.mkdir(parents=True, exist_ok=True)
                pf_path = out_dir_pf / "ml_preflight.json"
                if not pf_path.exists():
                    write_ml_preflight(pf_path, compute_ml_preflight(r))

                duration = get_sampling_duration_seconds(r)
                if duration is None or duration <= 0:
                    _write_run_skip(r, frozen=True, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                    runs_skipped += 1
                    continue
                if not r.pcap_path or not r.pcap_path.exists():
                    _write_run_skip(r, frozen=True, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                    runs_skipped += 1
                    continue

                try:
                    packets = extract_packet_timeline(r.pcap_path)
                    rows, dropped = build_window_features(packets, duration_s=float(duration), spec=window_spec)
                except Exception as exc:  # noqa: BLE001
                    # Do not crash the batch run: emit an explicit SKIPPED artifact
                    # for this run. This keeps Phase E deterministic and audit-friendly.
                    out_dir = _ml_output_dir(r.run_dir, frozen=True)
                    out_dir.mkdir(parents=True, exist_ok=True)
                    err_path = out_dir / "tshark_error.txt"
                    if not err_path.exists():
                        try:
                            err_path.write_text(str(exc), encoding="utf-8")
                        except Exception:
                            pass
                    _write_run_skip(r, frozen=True, reason="ML_SKIPPED_TSHARK_ERROR")
                    runs_skipped += 1
                    continue
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

            # Training selection (paper contract):
            # baseline-only; fail-closed if baseline fails bytes/windows gates.
            baseline_rows = per_run_rows.get(baseline_id, ([], 0))[0]
            bytes_ok, min_bytes = _baseline_bytes_gate_ok(app_runs, baseline_rid=baseline_id)
            windows_ok = len(baseline_rows) >= int(config.MIN_WINDOWS_BASELINE)
            if not (bytes_ok and windows_ok and baseline_rows):
                _write_app_skip(
                    app_runs,
                    frozen=True,
                    reason="ML_SKIPPED_BASELINE_GATE_FAIL",
                    details={
                        "baseline_windows_total": int(len(baseline_rows)),
                        "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
                        "baseline_windows_ok": bool(windows_ok),
                        "baseline_pcap_bytes_ok": bool(bytes_ok),
                        "baseline_min_pcap_bytes": int(min_bytes),
                        "freeze_manifest_sha256": freeze_sha,
                    },
                )
                runs_skipped += len(app_runs)
                continue
            training_mode = "baseline_only"
            train_rows = baseline_rows

            X_train, feature_names = _rows_to_matrix(train_rows, window_spec=window_spec)
            X_all, _ = _rows_to_matrix(all_rows, window_spec=window_spec)
            if X_train.size == 0 or X_train.shape[0] < 3 or X_all.size == 0:
                _write_app_skip(app_runs, frozen=True, reason="ML_SKIPPED_EMPTY_FEATURE_VECTOR")
                runs_skipped += len(app_runs)
                continue

            baseline_feature_stats = _baseline_feature_stats(X_train, feature_names=feature_names)
            feature_scaling: dict[str, Any] | None = None
            if config.FEATURE_ROBUST_SCALE:
                X_train, X_all, feature_scaling = _apply_robust_scaling(X_train, X_all)

            apps_trained += 1

            per_model_scores_by_run: dict[str, dict[str, list[float]]] = {}
            per_model_thresholds: dict[str, float] = {}
            model_outputs: dict[str, dict[str, Any]] = {}
            per_model_audit_rows: list[dict[str, Any]] = []

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
                    "baseline_provenance": {
                        "baseline_run_id": baseline_id,
                        "baseline_pcap_bytes_ok": bool(bytes_ok),
                        "baseline_windows_ok": bool(windows_ok),
                        "fallback_reason": [],
                        "degraded_comparability": False,
                    },
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
                    written_run_ids.add(r.run_id)

                baseline_inputs = next((r for r in app_runs if r.run_id == baseline_id), None)
                baseline_pcap_bytes = _pcap_size_bytes_from_inputs(baseline_inputs) if baseline_inputs else None
                per_model_audit_rows.append(
                    {
                        "package_name": pkg,
                        "model": spec.name,
                        "training_mode": training_mode,
                        "training_samples": training_samples,
                        "training_samples_warning": training_samples_warning,
                        "threshold_value": threshold,
                        "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                        "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
                        "threshold_equals_max": threshold_equals_max,
                        "baseline_windows": int(len(baseline_rows)),
                        "baseline_pcap_bytes": baseline_pcap_bytes,
                        "baseline_min_pcap_bytes": int(min_bytes),
                        "baseline_pcap_bytes_ok": bool(bytes_ok),
                        "baseline_windows_ok": bool(windows_ok),
                        "windows_scored": int(len(all_rows)),
                        "windows_dropped_partial": int(sum(d for _, d in per_run_rows.values())),
                        "feature_transform": "log1p_bytes_packets" if config.FEATURE_LOG1P else "none",
                        "feature_scaling": feature_scaling.get("method") if feature_scaling else None,
                        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                    }
                )

            audit_rows.extend(per_model_audit_rows)

            # Write per-run manifests/summaries.
            for r in app_runs:
                out_dir = _ml_output_dir(r.run_dir, frozen=True)
                out_dir.mkdir(parents=True, exist_ok=True)
                manifest_path = out_dir / "model_manifest.json"
                summary_path = out_dir / "ml_summary.json"
                wrote_any = False
                if not manifest_path.exists():
                    _write_model_manifest(
                        manifest_path,
                        run_inputs=r,
                        identity_key_used=identity_key,
                        seed=seed,
                        window_spec=window_spec,
                        model_outputs=model_outputs,
                        freeze_manifest_path=str(freeze_path),
                    )
                    wrote_any = True
                if not summary_path.exists():
                    _write_ml_summary(
                        summary_path,
                        run_inputs=r,
                        phase=per_run_phase.get(r.run_id) or _fallback_phase(r.run_profile),
                        interaction_tag=per_run_tag.get(r.run_id),
                        window_rows=per_run_rows[r.run_id][0],
                        dropped_partial_windows=per_run_rows[r.run_id][1],
                        model_outputs=model_outputs,
                        out_dir=out_dir,
                        baseline_feature_stats=baseline_feature_stats,
                    )
                    wrote_any = True
                if wrote_any:
                    written_run_ids.add(r.run_id)
                _write_cohort_status(
                    r,
                    status="CANONICAL_PAPER_ELIGIBLE",
                    reason_code=None,
                    details={
                        "identity_key": identity_key,
                        "freeze_manifest_path": str(freeze_path),
                        "freeze_manifest_sha256": freeze_sha,
                    },
                )

            # Dataset-level derived outputs (not frozen inputs).
            per_run_empty_windows: dict[str, int] = {
                rid: int(sum(1 for row in rows if int(row.get("packet_count") or 0) <= 0))
                for rid, (rows, _dropped) in per_run_rows.items()
            }
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
                    per_run_empty_windows=per_run_empty_windows,
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
                per_run_low_signal=per_run_low_signal,
                per_model_scores_by_run=per_model_scores_by_run,
                per_model_thresholds=per_model_thresholds,
                checksums=checksums,
            )

        _write_prevalence_csvs(dataset_phase_rows)
        _write_model_overlap_csv(model_overlap_rows)
        _write_transport_mix_csvs(transport_mix_rows)
        _write_ml_audit_csv(audit_rows)
        _maybe_write_paper_artifacts_json(
            candidate=exemplar_candidate,
            freeze_manifest_path=freeze_path,
        )
        # Compute "scored" as "all included runs that have complete v1 outputs present",
        # regardless of whether this invocation had to write anything.
        runs_scored = sum(
            1 for rid in included_run_ids if _run_has_complete_v1_outputs(root / rid)
        )
        runs_reused = max(0, runs_scored - len(written_run_ids))
        return MlRunStats(
            apps_seen=apps_seen,
            apps_trained=apps_trained,
            runs_scored=runs_scored,
            runs_skipped=runs_skipped,
            generated_at=datetime.now(UTC).isoformat(),
            runs_reused=runs_reused,
        )


def _all_frozen_v1_outputs_exist(root: Path, included_run_ids: set[str]) -> bool:
    """Return True if all included runs already have the required v1 outputs on disk."""
    for rid in included_run_ids:
        run_dir = root / rid
        if not run_dir.exists():
            return False
        if not _run_has_complete_v1_outputs(run_dir):
            return False
    return True


def _run_has_complete_v1_outputs(run_dir: Path) -> bool:
    paths = MLOutputPaths(run_dir=run_dir, schema_label=config.ML_SCHEMA_LABEL)
    required = [
        paths.model_manifest_path,
        paths.summary_path,
        paths.iforest_scores_path,
        paths.ocsvm_scores_path,
    ]
    return all(path.exists() for path in required)


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
        if config.FEATURE_LOG1P:
            bytes_per_sec = float(np.log1p(bytes_per_sec))
            packets_per_sec = float(np.log1p(packets_per_sec))
        data.append([bytes_per_sec, packets_per_sec, avg_pkt])
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
    iqr = np.maximum(q3 - q1, 1e-9)
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


def _ml_output_dir(run_dir: Path, *, frozen: bool) -> Path:
    # Retain `frozen` for compatibility with existing call sites; output paths are canonical.
    _ = frozen
    return MLOutputPaths(run_dir=run_dir, schema_label=config.ML_SCHEMA_LABEL).output_dir


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
        "is_fallback_mode",
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


def _write_ml_audit_csv(rows: list[dict[str, Any]]) -> None:
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

    Controlled repinning (one-time) must be performed explicitly by an operator-facing action.
    """
    path = PAPER_ARTIFACTS_PATH
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


def _missing_dataset_level_outputs() -> list[str]:
    """Return a list of missing required dataset-level CSV paths (relative)."""
    required = [
        "anomaly_prevalence_per_app_phase.csv",
        "model_overlap_per_run.csv",
        "transport_mix_by_phase.csv",
        "ml_audit_per_app_model.csv",
    ]
    out_dir = Path(app_config.DATA_DIR)
    missing = []
    for name in required:
        if not (out_dir / name).exists():
            missing.append(str(out_dir / name))
    return missing


def _rebuild_dataset_outputs_from_v1(
    *,
    evidence_root: Path,
    freeze_path: Path,
    freeze_payload: dict[str, Any],
    freeze_apps: dict[str, Any],
    checksums: dict[str, Any],
) -> None:
    """Rebuild dataset-level CSVs from existing per-run v1 outputs.

    This is used only when:
    - per-run v1 outputs exist for all included runs, but
    - the dataset-level CSVs under data/ are missing (deleted/cleaned).

    It does not touch per-run artifacts and does not rerun modeling.
    """
    # Build per-run rows in the same shape expected by _write_* writers.
    phase_rows: list[dict[str, Any]] = []
    overlap_rows: list[dict[str, Any]] = []
    transport_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []

    included = _load_frozen_run_ids_from_payload(freeze_payload) or set()

    for pkg, entry in sorted(freeze_apps.items()):
        if not isinstance(entry, dict):
            continue
        base_ids = entry.get("baseline_run_ids") or []
        inter_ids = entry.get("interactive_run_ids") or []
        if not (isinstance(base_ids, list) and isinstance(inter_ids, list) and len(base_ids) >= 1 and len(inter_ids) >= 2):
            continue
        baseline_id = str(base_ids[0])
        interactive_ids = [str(x) for x in inter_ids[:2]]
        interactive_ids = sorted(
            interactive_ids,
            key=lambda rid: (_parse_ended_at_epoch((checksums.get(rid) or {}).get("ended_at")), rid),
        )
        run_ids = [baseline_id] + interactive_ids
        for rid in run_ids:
            if rid not in included:
                raise RuntimeError(f"Freeze manifest inconsistency (rebuild): {rid} not in included_run_ids")

        per_run_phase = {
            baseline_id: "idle",
            interactive_ids[0]: "interactive_a",
            interactive_ids[1]: "interactive_b",
        }

        # Load manifests just for tags/low_signal.
        inputs_by_rid: dict[str, RunInputs] = {}
        for rid in run_ids:
            run_dir = evidence_root / rid
            inputs = load_run_inputs(run_dir)
            if not inputs:
                raise RuntimeError(f"Missing included run during rebuild: {rid}")
            inputs_by_rid[rid] = inputs

        identity_key = next((r.identity_key for r in inputs_by_rid.values() if r.identity_key), None) or pkg
        tag_by_rid = {rid: _interaction_tag_from_manifest(inputs_by_rid[rid].manifest) for rid in run_ids}

        # Read per-model per-run scores/flags.
        per_model_scores_by_run: dict[str, dict[str, list[float]]] = {
            config.MODEL_IFOREST: {},
            config.MODEL_OCSVM: {},
        }
        per_model_thresholds: dict[str, float] = {}
        training_mode = None
        model_meta_by_name: dict[str, dict[str, Any]] = {}

        for model_name in (config.MODEL_IFOREST, config.MODEL_OCSVM):
            for rid in run_ids:
                out_dir = _ml_output_dir(evidence_root / rid, frozen=True)
                csv_path = out_dir / f"anomaly_scores_{_model_csv_label(model_name)}.csv"
                scores, threshold = _read_scores_and_threshold(csv_path)
                per_model_scores_by_run[model_name][rid] = scores
                if threshold is not None:
                    per_model_thresholds[model_name] = float(threshold)
            # training_mode + thresholds are recorded in model_manifest (same for all 3 runs in app)
            mf = _ml_output_dir(evidence_root / baseline_id, frozen=True) / "model_manifest.json"
            try:
                m = json.loads(mf.read_text(encoding="utf-8"))
                models = m.get("models") if isinstance(m.get("models"), dict) else {}
                mo = models.get(model_name) if isinstance(models.get(model_name), dict) else {}
                if training_mode is None:
                    training_mode = str(mo.get("training_mode") or "") or None
                if model_name not in per_model_thresholds and mo.get("threshold_value") is not None:
                    per_model_thresholds[model_name] = float(mo.get("threshold_value"))
                if not model_meta_by_name and isinstance(models, dict):
                    for name, meta in models.items():
                        if isinstance(meta, dict):
                            model_meta_by_name[str(name)] = dict(meta)
            except Exception:
                pass

        training_mode = training_mode or "baseline_only"

        bytes_ok, min_bytes = _baseline_bytes_gate_ok([inputs_by_rid[r] for r in run_ids], baseline_rid=baseline_id)
        baseline_windows = len(per_model_scores_by_run[config.MODEL_IFOREST].get(baseline_id) or [])
        windows_ok = baseline_windows >= int(config.MIN_WINDOWS_BASELINE)
        baseline_pcap_bytes = _pcap_size_bytes_from_inputs(inputs_by_rid[baseline_id])
        windows_scored = int(
            sum(len(per_model_scores_by_run[config.MODEL_IFOREST].get(rid) or []) for rid in run_ids)
        )
        windows_dropped_partial = 0
        for rid in run_ids:
            summary_path = _ml_output_dir(evidence_root / rid, frozen=True) / "ml_summary.json"
            if summary_path.exists():
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    windows_dropped_partial += int(summary.get("dropped_partial_windows") or 0)
                except Exception:
                    pass

        for model_name in (config.MODEL_IFOREST, config.MODEL_OCSVM):
            meta = model_meta_by_name.get(model_name, {})
            training_samples = int(meta.get("training_samples") or 0)
            training_samples_warning = bool(
                meta.get("training_samples_warning")
                if "training_samples_warning" in meta
                else training_samples < int(config.MIN_TRAINING_SAMPLES_WARNING)
            )
            audit_rows.append(
                {
                    "package_name": pkg,
                    "model": model_name,
                    "training_mode": training_mode,
                    "training_samples": training_samples,
                    "training_samples_warning": training_samples_warning,
                    "threshold_value": float(per_model_thresholds.get(model_name) or 0.0),
                    "threshold_percentile": float(config.THRESHOLD_PERCENTILE),
                    "threshold_equals_max": bool(meta.get("threshold_equals_max")),
                    "baseline_windows": int(baseline_windows),
                    "baseline_pcap_bytes": baseline_pcap_bytes,
                    "baseline_min_pcap_bytes": int(min_bytes),
                    "baseline_pcap_bytes_ok": bool(bytes_ok),
                    "baseline_windows_ok": bool(windows_ok),
                    "windows_scored": int(windows_scored),
                    "windows_dropped_partial": int(windows_dropped_partial),
                    "feature_transform": meta.get("feature_transform"),
                    "feature_scaling": (meta.get("feature_scaling") or {}).get("method")
                    if isinstance(meta.get("feature_scaling"), dict)
                    else meta.get("feature_scaling"),
                    "ml_schema_version": int(config.ML_SCHEMA_VERSION),
                }
            )

        # Phase rows: per-run, per-model (distribution computed from CSV scores).
        for model_name, scores_by_run in per_model_scores_by_run.items():
            threshold = float(per_model_thresholds.get(model_name) or 0.0)
            for rid in run_ids:
                run_scores = scores_by_run.get(rid) or []
                if not run_scores:
                    continue
                arr = np.asarray(run_scores, dtype=float)
                anomalous = int(sum(1 for s in run_scores if float(s) >= threshold))
                ds = inputs_by_rid[rid].manifest.get("dataset") if isinstance(inputs_by_rid[rid].manifest.get("dataset"), dict) else {}
                phase_rows.append(
                    {
                        "identity_key": identity_key,
                        "package_name": pkg,
                        "run_id": rid,
                        "phase": per_run_phase.get(rid) or "interactive",
                        "interaction_tag": tag_by_rid.get(rid) or "",
                        "model": model_name,
                        "training_mode": training_mode,
                        "low_signal": bool(ds.get("low_signal")) if ds.get("low_signal") is not None else None,
                        "windows_total": int(arr.shape[0]),
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

        # Model overlap: computed from CSV flags via thresholds.
        overlap_rows.extend(
            _compute_model_overlap_rows(
                package_name=pkg,
                app_runs=[inputs_by_rid[r] for r in run_ids],
                per_model_scores_by_run=per_model_scores_by_run,
                per_model_thresholds=per_model_thresholds,
                per_run_phase=per_run_phase,
                per_run_tag=tag_by_rid,
                training_mode=training_mode,
            )
        )

        # Transport mix: derived from existing pcap_features/pcap_report.
        transport_rows.extend(
            _compute_transport_mix_rows(
                package_name=pkg,
                app_runs=[inputs_by_rid[r] for r in run_ids],
                per_run_phase=per_run_phase,
                per_run_tag=tag_by_rid,
            )
        )

    _write_ml_audit_csv(audit_rows)
    _write_prevalence_csvs(phase_rows)
    _write_model_overlap_csv(overlap_rows)
    _write_transport_mix_csvs(transport_rows)


def _read_scores_and_threshold(path: Path) -> tuple[list[float], float | None]:
    """Read anomaly score CSV and return (scores, threshold) where threshold may be None."""
    import csv

    if not path.exists():
        return [], None
    scores: list[float] = []
    threshold: float | None = None
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                s = float(row.get("score") or 0.0)
            except Exception:
                continue
            scores.append(float(s))
            if threshold is None:
                try:
                    threshold = float(row.get("threshold") or row.get("threshold_value") or 0.0)
                except Exception:
                    threshold = None
    return scores, threshold


def _select_fig_b1_exemplar_from_existing_or_inputs(
    *,
    evidence_root: Path,
    freeze_apps: dict[str, Any],
    checksums: dict[str, Any],
) -> _ExemplarCandidate | None:
    """Select exemplar candidate in a reuse-only scenario.

    If paper_artifacts.json is missing, we may need to compute the sustained bytes/sec metric.
    This function performs a minimal windowing pass only for eligible messaging call runs
    (voice/video tags) that are not low_signal (PM locked).
    """
    candidate: _ExemplarCandidate | None = None
    for pkg, entry in sorted(freeze_apps.items()):
        if not isinstance(entry, dict):
            continue
        if pkg not in config.MESSAGING_PACKAGES:
            continue
        base_ids = entry.get("baseline_run_ids") or []
        inter_ids = entry.get("interactive_run_ids") or []
        if not (isinstance(base_ids, list) and isinstance(inter_ids, list) and len(base_ids) >= 1 and len(inter_ids) >= 2):
            continue
        interactive_ids = [str(x) for x in inter_ids[:2]]
        interactive_ids = sorted(
            interactive_ids,
            key=lambda rid: (_parse_ended_at_epoch((checksums.get(rid) or {}).get("ended_at")), rid),
        )
        # Load minimal per-run tag + anomaly prevalence (from CSVs). Sustained bytes requires windowing.
        per_run_tag: dict[str, str | None] = {}
        per_run_low_signal: dict[str, bool] = {}
        per_run_rows: dict[str, tuple[list[dict[str, Any]], int]] = {}
        per_model_scores_by_run: dict[str, dict[str, list[float]]] = {config.MODEL_IFOREST: {}, config.MODEL_OCSVM: {}}
        per_model_thresholds: dict[str, float] = {}

        for rid in interactive_ids:
            inputs = load_run_inputs(evidence_root / rid)
            if not inputs:
                continue
            per_run_tag[rid] = _interaction_tag_from_manifest(inputs.manifest)
            ds = inputs.manifest.get("dataset") if isinstance(inputs.manifest.get("dataset"), dict) else {}
            per_run_low_signal[rid] = bool(ds.get("low_signal") is True)
            # Load anomaly scores/thresholds.
            for model_name in (config.MODEL_IFOREST, config.MODEL_OCSVM):
                out_dir = _ml_output_dir(evidence_root / rid, frozen=True)
                csv_path = out_dir / f"anomaly_scores_{_model_csv_label(model_name)}.csv"
                scores, threshold = _read_scores_and_threshold(csv_path)
                per_model_scores_by_run[model_name][rid] = scores
                if threshold is not None:
                    per_model_thresholds[model_name] = float(threshold)
            # Window rows for sustained bytes/sec.
            dur = get_sampling_duration_seconds(inputs)
            if not inputs.pcap_path or not inputs.pcap_path.exists() or not dur:
                continue
            packets = extract_packet_timeline(inputs.pcap_path)
            rows, dropped = build_window_features(packets, duration_s=float(dur), spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S))
            per_run_rows[rid] = (rows, dropped)

        candidate = _select_fig_b1_exemplar_candidate(
            current=candidate,
            package_name=pkg,
            interactive_run_ids=interactive_ids,
            per_run_rows=per_run_rows,
            per_run_tag=per_run_tag,
            per_run_low_signal=per_run_low_signal,
            per_model_scores_by_run=per_model_scores_by_run,
            per_model_thresholds=per_model_thresholds,
            checksums=checksums,
        )
    return candidate


def _select_fig_b1_exemplar_candidate(
    *,
    current: _ExemplarCandidate | None,
    package_name: str,
    interactive_run_ids: list[str],
    per_run_rows: dict[str, tuple[list[dict[str, Any]], int]],
    per_run_tag: dict[str, str | None],
    per_run_low_signal: dict[str, bool],
    per_model_scores_by_run: dict[str, dict[str, list[float]]],
    per_model_thresholds: dict[str, float],
    checksums: dict[str, Any],
    k_windows: int = 6,
) -> _ExemplarCandidate | None:
    """Select the canonical Fig B1 exemplar candidate deterministically.

    PM protocol (Paper #2):
    - Consider only messaging apps (locked cohort).
    - Consider only interactive runs with call tags (voice or video).
    - Exclude low_signal runs.
    - Primary metric: sustained bytes/sec over >=K consecutive windows (K=6 => 30s).
    - Tie breakers: higher IF prevalence, then higher OC-SVM prevalence, then later ended_at.
    """
    if config.MODEL_IFOREST not in per_model_scores_by_run or config.MODEL_OCSVM not in per_model_scores_by_run:
        return current
    if package_name not in config.MESSAGING_PACKAGES:
        return current

    if_thr = float(per_model_thresholds.get(config.MODEL_IFOREST) or 0.0)
    oc_thr = float(per_model_thresholds.get(config.MODEL_OCSVM) or 0.0)

    for rid in interactive_run_ids:
        tag_raw = per_run_tag.get(rid)
        tag = _canonical_interaction_tag(tag_raw)
        if tag not in config.EXEMPLAR_ALLOWED_INTERACTION_TAGS:
            continue
        if per_run_low_signal.get(rid) is True:
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
    # Protocol hierarchy can contain duplicate/overlapping rows. Normalize defensively:
    # - use a denominator that cannot yield >1.0
    # - clamp ratios into [0,1]
    quic_denom = float(max(udp_b, quic_b))
    quic_ratio = (float(quic_b) / quic_denom) if quic_denom > 0 else None
    tcp_ratio = float(tcp_b) / total if total > 0 else None
    udp_ratio = float(udp_b) / total if total > 0 else None
    tls_ratio = _clamp01(tls_ratio)
    quic_ratio = _clamp01(quic_ratio)
    tcp_ratio = _clamp01(tcp_ratio)
    udp_ratio = _clamp01(udp_ratio)
    return tls_ratio, quic_ratio, tcp_ratio, udp_ratio


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
        if v is None:
            return None
        f = float(v)
        if f < 0.0:
            return None
        return f
    except Exception:
        return None


def _capture_semantics_from_run_inputs(run_inputs: RunInputs) -> dict[str, Any]:
    manifest = run_inputs.manifest if isinstance(run_inputs.manifest, dict) else {}
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    meta_rel = None
    for art in artifacts:
        if isinstance(art, dict) and str(art.get("type") or "") == "pcapdroid_capture_meta":
            rp = art.get("relative_path")
            if isinstance(rp, str) and rp:
                meta_rel = rp
                break
    pcapdroid_version = "unknown"
    capture_mode = "unknown"
    filter_type = "PCAPdroid app_filter (package)"
    if meta_rel:
        try:
            meta_path = run_inputs.run_dir / meta_rel
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                capture_mode = str(payload.get("capture_mode") or "unknown")
                pkg = payload.get("pcapdroid_package")
                if isinstance(pkg, str) and pkg.strip():
                    pcapdroid_version = str(payload.get("pcapdroid_version") or "unknown")
        except Exception:
            pass
    report = run_inputs.pcap_report if isinstance(run_inputs.pcap_report, dict) else {}
    capinfos = report.get("capinfos") if isinstance(report.get("capinfos"), dict) else {}
    parsed = capinfos.get("parsed") if isinstance(capinfos.get("parsed"), dict) else {}
    linktype = (
        parsed.get("file_type")
        or parsed.get("encapsulation")
        or report.get("linktype")
        or "unknown"
    )
    return {
        "capture_tool": "PCAPdroid",
        "filter_type": filter_type,
        "capture_mode": str(capture_mode),
        "pcapdroid_version": str(pcapdroid_version),
        "pcap_linktype": str(linktype),
    }


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
    env_dict = env if isinstance(env, dict) else {}
    host_tools = env.get("host_tools") if isinstance(env, dict) else None
    try:
        import numpy
        import sklearn

        deps = {"numpy": numpy.__version__, "sklearn": sklearn.__version__}
    except Exception:
        deps = {}
    freeze_sha256 = None
    if freeze_manifest_path:
        try:
            freeze_sha256 = _sha256_file(Path(freeze_manifest_path))
        except Exception:
            freeze_sha256 = None
    payload: dict[str, Any] = {
        "ml_schema_version": config.ML_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "frozen": bool(freeze_manifest_path),
        "freeze_manifest_path": freeze_manifest_path,
        "freeze_manifest_sha256": freeze_sha256,
        "identity_key_used": identity_key_used,
        "seed": int(seed),
        **salt_metadata(),
        "tool_semver": env_dict.get("tool_semver"),
        "tool_git_commit": env_dict.get("tool_git_commit"),
        "schema_version": env_dict.get("schema_version"),
        "feature_schema_version": (
            run_inputs.pcap_features.get("feature_schema_version")
            if isinstance(run_inputs.pcap_features, dict)
            else None
        ),
        "windowing": {
            "window_size_s": float(window_spec.window_size_s),
            "stride_s": float(window_spec.stride_s),
            "drop_partial_windows": True,
            "timebase": "pcap_time_relative_seconds",
        },
        "paper_constants": {
            "window_size_s": float(config.WINDOW_SIZE_S),
            "window_stride_s": float(config.WINDOW_STRIDE_S),
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes_fallback": int(config.MIN_PCAP_BYTES_FALLBACK),
            "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
        },
        "capture_semantics": {
            "capture_scope": "PCAPdroid-filtered capture restricted to the target package.",
            "byte_semantics": "aggregate frame length (frame.len) as reported by tshark.",
            "directionality": "no direction split is performed.",
            **_capture_semantics_from_run_inputs(run_inputs),
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
        "model_reporting_roles": {
            config.MODEL_IFOREST: "primary",
            config.MODEL_OCSVM: "secondary_model_robustness_check",
        },
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
    run_matrix, _ = _rows_to_matrix(
        window_rows,
        window_spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S),
    )
    for model_name, meta in model_outputs.items():
        model_label = _model_csv_label(model_name)
        csv_path = out_dir / f"anomaly_scores_{_model_csv_label(model_name)}.csv"
        if not csv_path.exists():
            continue
        scores = _load_scores(csv_path)
        if not scores:
            continue
        threshold = float(meta.get("threshold_value") or 0.0)
        threshold_payload["models"][model_name] = {
            "threshold_value": float(threshold),
            "threshold_percentile": float(meta.get("threshold_percentile") or config.THRESHOLD_PERCENTILE),
        }
        streak_count, longest_streak = _anomaly_streak_metrics(scores, threshold)
        dars_row = _compute_dars_v1(scores=scores, threshold=threshold)
        dars_row["threshold_value"] = float(round(threshold, 6))
        dars_row["model"] = str(model_name)
        dars_row["k_policy"] = "top_10_percent"
        topk_rows, zscore_rows = _build_topk_and_zscores(
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
            _write_csv_dicts(topk_path, topk_rows)
        if not zscore_path.exists():
            _write_csv_dicts(zscore_path, zscore_rows)
        if model_name == config.MODEL_IFOREST:
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
                _write_csv_dicts(canonical_scores_path, canonical_rows)
            if not canonical_topk_path.exists():
                _write_csv_dicts(canonical_topk_path, topk_rows)
            if not canonical_attr_path.exists():
                _write_csv_dicts(canonical_attr_path, zscore_rows)
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
        threshold_path.write_text(json.dumps(threshold_payload, indent=2, sort_keys=True), encoding="utf-8")
    dars_path = out_dir / "dars_v1.json"
    dars_hash_path = out_dir / "dars_v1.sha256"
    if dars_payload.get("scores"):
        if not dars_path.exists():
            dars_body = json.dumps(dars_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            dars_hash = hashlib.sha256(dars_body).hexdigest()
            dars_emit = dict(dars_payload)
            dars_emit["hash_of_dars_artifact"] = dars_hash
            dars_path.write_text(json.dumps(dars_emit, indent=2, sort_keys=True), encoding="utf-8")
        if not dars_hash_path.exists():
            dars_hash_path.write_text(_sha256_file(dars_path) + "\n", encoding="utf-8")
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


def _write_csv_dicts(path: Path, rows: list[dict[str, Any]]) -> None:
    import csv

    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not fieldnames:
            handle.write("")
            return
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _baseline_feature_stats(X_train: np.ndarray, *, feature_names: list[str]) -> dict[str, Any]:
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


def _compute_dars_v1(*, scores: list[float], threshold: float) -> dict[str, Any]:
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


def _build_topk_and_zscores(
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


def _anomaly_streak_metrics(scores: list[float], threshold: float) -> tuple[int, int]:
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


def _write_run_skip(run: RunInputs, *, frozen: bool, reason: str, details: dict[str, Any] | None = None) -> None:
    paths = MLOutputPaths(run_dir=run.run_dir, schema_label=config.ML_SCHEMA_LABEL)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    if not (frozen and paths.summary_path.exists()):
        payload = {
            "ml_schema_version": config.ML_SCHEMA_VERSION,
            "run_id": run.run_id,
            "package_name": run.package_name,
            "run_profile": run.run_profile,
            "skip": {"reason": reason},
        }
        if details:
            payload["skip"]["details"] = details
        paths.summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _write_cohort_status(run, status="EXCLUDED", reason_code=reason, details=details)


def _write_app_skip(
    app_runs: list[RunInputs],
    *,
    frozen: bool,
    reason: str,
    details: dict[str, Any] | None = None,
) -> None:
    for r in app_runs:
        _write_run_skip(r, frozen=frozen, reason=reason, details=details)


def _resolve_paper_identity_contract(app_runs: list[RunInputs]) -> tuple[str | None, str | None, dict[str, Any] | None]:
    base_sha_values: set[str] = set()
    static_handoff_values: set[str] = set()
    missing_base_sha_run_ids: list[str] = []
    missing_static_link_run_ids: list[str] = []
    missing_static_features: dict[str, list[str]] = {}
    apk_change_mismatches: dict[str, dict[str, str]] = {}
    for r in app_runs:
        ident = r.plan.get("run_identity") if isinstance(r.plan, dict) and isinstance(r.plan.get("run_identity"), dict) else {}
        base_sha = str(ident.get("base_apk_sha256") or "").strip().lower() if isinstance(ident, dict) else ""
        static_handoff_hash = str(ident.get("static_handoff_hash") or "").strip().lower() if isinstance(ident, dict) else ""
        if not base_sha:
            missing_base_sha_run_ids.append(str(r.run_id))
        else:
            base_sha_values.add(base_sha)
        if not static_handoff_hash:
            missing_static_link_run_ids.append(str(r.run_id))
        else:
            static_handoff_values.add(static_handoff_hash)
        static_features = (
            r.plan.get("static_features")
            if isinstance(r.plan, dict) and isinstance(r.plan.get("static_features"), dict)
            else {}
        )
        required_static_features = (
            "exported_components_total",
            "dangerous_permission_count",
            "uses_cleartext_traffic",
            "sdk_indicator_score",
        )
        missing = [key for key in required_static_features if key not in static_features]
        if missing:
            missing_static_features[str(r.run_id)] = missing
        package = str(ident.get("package_name_lc") or r.plan.get("package_name") or "").strip().lower() if isinstance(r.plan, dict) else ""
        version_code = str(ident.get("version_code") or r.plan.get("version_code") or "").strip() if isinstance(r.plan, dict) else ""
        signer_digest = str(ident.get("signer_digest") or "").strip() if isinstance(ident, dict) else ""
        if not package or not version_code:
            missing_static_link_run_ids.append(str(r.run_id))
        if not signer_digest or signer_digest.upper() == "UNKNOWN":
            missing_static_link_run_ids.append(str(r.run_id))
        target = r.manifest.get("target") if isinstance(r.manifest.get("target"), dict) else {}
        target_package = str(target.get("package_name") or "").strip().lower()
        target_version = str(target.get("version_code") or "").strip()
        if package and target_package and package != target_package:
            apk_change_mismatches[str(r.run_id)] = {
                "expected_package_name_lc": package,
                "observed_package_name_lc": target_package,
            }
        if version_code and target_version and version_code != target_version:
            apk_change_mismatches[str(r.run_id)] = {
                "expected_version_code": version_code,
                "observed_version_code": target_version,
            }

    if missing_base_sha_run_ids:
        return None, "ML_SKIPPED_MISSING_BASE_APK_SHA256", {"run_ids": sorted(missing_base_sha_run_ids)}
    if missing_static_link_run_ids:
        return None, "ML_SKIPPED_MISSING_STATIC_LINK", {"run_ids": sorted(set(missing_static_link_run_ids))}
    if missing_static_features:
        return None, "ML_SKIPPED_MISSING_STATIC_FEATURES", {"runs": missing_static_features}
    if apk_change_mismatches:
        return None, "ML_SKIPPED_APK_CHANGED_DURING_RUN", {"runs": apk_change_mismatches}
    if len(base_sha_values) != 1:
        return None, "ML_SKIPPED_MISSING_STATIC_LINK", {"conflicting_base_apk_sha256": sorted(base_sha_values)}
    if len(static_handoff_values) != 1:
        return None, "ML_SKIPPED_MISSING_STATIC_LINK", {"conflicting_static_handoff_hash": sorted(static_handoff_values)}
    return f"base_apk_sha256:{next(iter(base_sha_values))}", None, None


def _write_cohort_status(
    run: RunInputs,
    *,
    status: str,
    reason_code: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    paths = MLOutputPaths(run_dir=run.run_dir, schema_label=config.ML_SCHEMA_LABEL)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "run_id": run.run_id,
        "package_name": run.package_name,
        "status": status,
        "reason_code": reason_code,
        "gates": {
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(config.MIN_PCAP_BYTES),
        },
    }
    _validate_paper_reason_code(reason_code)
    if details:
        payload["details"] = details
    paths.cohort_status_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _persist_paper_cohort_status_db(
        run_id=str(run.run_id),
        package_name=str(run.package_name or ""),
        status=str(status),
        reason_code=reason_code,
        details=payload.get("details"),
        plan_identity=run.plan.get("run_identity") if isinstance(run.plan, dict) else None,
    )


def _write_global_cohort_status(root: Path, *, reason: str, details: dict[str, Any] | None = None) -> None:
    out = root / "analysis" / "ml" / "paper" / "cohort_status.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "status": "EXCLUDED",
        "reason_code": reason,
        "gates": {
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(config.MIN_PCAP_BYTES),
        },
    }
    _validate_paper_reason_code(reason)
    if details:
        payload["details"] = details
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _validate_paper_reason_code(reason_code: str | None) -> None:
    if reason_code is None:
        return
    if reason_code not in PAPER_EXCLUSION_REASON_CODES:
        raise RuntimeError(f"Unknown paper exclusion reason code: {reason_code}")


def _persist_paper_cohort_status_db(
    *,
    run_id: str,
    package_name: str,
    status: str,
    reason_code: str | None,
    details: dict[str, Any] | None,
    plan_identity: dict[str, Any] | None,
) -> None:
    ident = plan_identity if isinstance(plan_identity, dict) else {}
    base_sha = str(ident.get("base_apk_sha256") or "").strip().lower() or None
    static_handoff_hash = str(ident.get("static_handoff_hash") or "").strip().lower() or None
    freeze_manifest_sha256 = None
    if isinstance(details, dict):
        freeze_manifest_sha256 = str(details.get("freeze_manifest_sha256") or "").strip().lower() or None
    try:
        core_q.run_sql_write(
            """
            INSERT INTO analysis_dynamic_cohort_status
              (dynamic_run_id, package_name, base_apk_sha256, static_handoff_hash, freeze_manifest_sha256, status, reason_code, details_json, created_at_utc, updated_at_utc)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP())
            ON DUPLICATE KEY UPDATE
              package_name=VALUES(package_name),
              base_apk_sha256=VALUES(base_apk_sha256),
              static_handoff_hash=VALUES(static_handoff_hash),
              freeze_manifest_sha256=VALUES(freeze_manifest_sha256),
              status=VALUES(status),
              reason_code=VALUES(reason_code),
              details_json=VALUES(details_json),
              updated_at_utc=UTC_TIMESTAMP()
            """,
            (
                run_id,
                package_name or None,
                base_sha,
                static_handoff_hash,
                freeze_manifest_sha256,
                status,
                reason_code,
                json.dumps(details, sort_keys=True) if isinstance(details, dict) else None,
            ),
            query_name="dynamic.paper_cohort_status.upsert",
        )
    except Exception:
        # DB persistence is best-effort here; gate command enforces paper eligibility later.
        pass


__all__ = ["MlRunStats", "run_ml_on_evidence_packs"]
