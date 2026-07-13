"""Batch ML runner over evidence packs (DB-free).

Freeze/profile v1.2 (locked posture):
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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    legacy_archive_dir,
    resolve_dataset_freeze_read_path,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from . import ml_parameters_profile as config
from .anomaly_model_training import anomaly_scores, fit_model, fixed_model_specs
from .config_fingerprint import compute_ml_config_fingerprint, profile_v2_fingerprint_payload
from .deliverable_bundle_paths import dataset_level_table_names
from .evidence_pack_ml_preflight import (
    RunInputs,
    compute_ml_preflight,
    get_sampling_duration_seconds,
    is_valid_dataset_run,
    load_run_inputs,
    write_ml_preflight,
)
from .feature_matrix import rows_to_basic_matrix
from .freeze_profile.dataset_tables import (
    clamp01 as _clamp01,
    compute_baseline_stability_rows as _compute_baseline_stability_rows,
    compute_dars_component_rows as _compute_dars_component_rows,
    compute_model_overlap_rows as _compute_model_overlap_rows,
    compute_phase_rows as _compute_phase_rows,
    compute_static_dynamic_stratification_row as _compute_static_dynamic_stratification_row,
    compute_transport_mix_rows as _compute_transport_mix_rows,
    extract_static_snapshot as _extract_static_snapshot,
    pcap_size_bytes_from_inputs as _pcap_size_bytes_from_inputs,
    safe_float as _safe_float,
    transport_ratios_from_inputs as _transport_ratios_from_inputs,
    write_baseline_stability_csv as _write_baseline_stability_csv,
    write_dars_components_csv as _write_dars_components_csv,
    write_ml_audit_csv as _write_ml_audit_csv,
    write_model_overlap_csv as _write_model_overlap_csv,
    write_prevalence_csvs as _write_prevalence_csvs,
    write_static_dynamic_stratification_csv as _write_static_dynamic_stratification_csv,
    write_transport_mix_csvs as _write_transport_mix_csvs,
)
from .freeze_profile.run_artifacts import (
    read_ml_config_fingerprint as _read_ml_config_fingerprint,
    write_app_skip as _write_app_skip,
    write_cohort_status as _write_cohort_status,
    write_global_cohort_status as _write_global_cohort_status,
    write_model_manifest as _write_model_manifest,
    write_run_skip as _write_run_skip,
)
from .freeze_profile.identity_contract import (
    resolve_paper_identity_contract as _resolve_paper_identity_contract,
)
from .freeze_profile.run_summary import (
    anomaly_streak_metrics as _anomaly_streak_metrics,
    baseline_feature_stats as _baseline_feature_stats,
    build_topk_and_zscores as _build_topk_and_zscores,
    compute_dars_v1 as _compute_dars_v1,
    load_scores as _load_scores,
    model_csv_label as _model_csv_label,
    write_csv_dicts as _write_csv_dicts,
    write_ml_summary as _write_ml_summary,
)
from .io import MLOutputPaths
from .numpy_percentile import percentile as np_percentile
from .pcap_window_features import (
    build_window_features,
    extract_packet_timeline,
    write_anomaly_scores_csv,
)
from .seed_identity import derive_seed
from .telemetry_windowing import WindowSpec

FREEZE_DIR = legacy_archive_dir()
# Legacy import-compatibility constants. Runtime code should call
# default_freeze_manifest_path() / paper_artifacts_path() so active cohort
# archive paths are honored.
DATASET_FREEZE_CANONICAL = FREEZE_DIR / config.FREEZE_CANONICAL_FILENAME
PAPER_ARTIFACTS_PATH = FREEZE_DIR / "paper_artifacts.json"


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


def default_freeze_manifest_path() -> Path:
    """Return the active cohort freeze if present, falling back to the legacy anchor."""
    return resolve_dataset_freeze_read_path()


def paper_artifacts_path(freeze_manifest_path: Path | None = None) -> Path:
    """Dataset-adjacent lockfile for the paper-facing exemplar selection.

    Older runs used `data/archive/paper_artifacts.json`. For cohort-aware freezes,
    keeping the lockfile next to the freeze prevents multiple cohort freezes from
    accidentally sharing one exemplar pin.
    """
    anchor = freeze_manifest_path or default_freeze_manifest_path()
    return anchor.parent / "paper_artifacts.json"


def run_ml_on_evidence_packs(
    *,
    output_root: Path | None = None,
    freeze_manifest_path: Path | None = None,
    reuse_existing_outputs: bool = True,
) -> MlRunStats:
    """Run freeze/profile ML over evidence packs.

    Selector (PM/reviewer locked):
    - Use the canonical freeze anchor unless an explicit freeze_manifest_path is provided.
    - Fail closed if the freeze manifest is missing required checksum fields.

    Hard rules:
    - No DB reads for selection/training/scoring.
    - No exploratory-mode fallback.
    """

    root = output_root or dynamic_evidence_root()
    if not root.exists():
        return MlRunStats(0, 0, 0, 0, datetime.now(UTC).isoformat())

    freeze_path = freeze_manifest_path or default_freeze_manifest_path()
    if not freeze_path.exists():
        _write_global_cohort_status(
            root,
            reason="ML_SKIPPED_MISSING_FREEZE_MANIFEST",
            details={"freeze_manifest_path": str(freeze_path)},
        )
        raise RuntimeError(f"Freeze manifest missing (fail-closed): {freeze_path}")
    frozen = True

    window_spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)
    ml_fp_payload = profile_v2_fingerprint_payload(ml_config=config)
    ml_fp = compute_ml_config_fingerprint(payload=ml_fp_payload)

    apps_trained = 0
    runs_scored = 0  # "ready/complete" runs (includes reused outputs)
    runs_skipped = 0
    written_run_ids: set[str] = set()

    dataset_phase_rows: list[dict[str, Any]] = []
    model_overlap_rows: list[dict[str, Any]] = []
    transport_mix_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    dars_component_rows: list[dict[str, Any]] = []
    baseline_stability_rows: list[dict[str, Any]] = []
    static_dynamic_rows: list[dict[str, Any]] = []
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
        freeze_dataset_hash = str(freeze.get("freeze_dataset_hash") or "").strip()

        # Fast path: if all per-run v1 outputs already exist, do not re-run tshark/modeling.
        # Still ensure dataset-level derived tables and paper lockfiles exist (they are
        # regenerable but required for the paper bundle). If missing, rebuild from
        # existing v1 outputs without touching per-run artifacts.
        if reuse_existing_outputs and _all_frozen_v1_outputs_exist(root, included_run_ids):
            # Reuse safety: require semantic config fingerprint match across ALL included runs.
            mismatched: list[dict[str, str]] = []
            missing_fp: list[str] = []
            stale_freeze: list[str] = []
            for rid in sorted(included_run_ids):
                run_dir = root / str(rid)
                out_dir = _ml_output_dir(run_dir, frozen=True)
                found_freeze_hash = _read_model_manifest_freeze_hash(out_dir)
                if freeze_dataset_hash and found_freeze_hash != freeze_dataset_hash:
                    stale_freeze.append(str(rid))
                    continue
                found = _read_ml_config_fingerprint(out_dir)
                if not found:
                    missing_fp.append(str(rid))
                    continue
                if found != ml_fp:
                    mismatched.append({"run_id": str(rid), "reason": "fingerprint_mismatch"})
            if missing_fp:
                # Freeze/profile mode contract: never "patch in" fingerprints for reuse.
                # Missing fingerprints means the existing outputs may be stale and cannot be
                # safely reused without recomputation.
                raise RuntimeError(
                    "Refusing reuse_existing_outputs: ml_config_fingerprint missing for existing outputs "
                    f"(runs={sorted(missing_fp)}). Outputs may be stale. Re-run with reuse disabled."
                )
            if mismatched:
                raise RuntimeError(
                    "Refusing reuse_existing_outputs: ml_config_fingerprint mismatch (freeze/profile mode). "
                    f"Example mismatch: {mismatched[0]}. Re-run with reuse disabled."
                )
            if reuse_existing_outputs and not stale_freeze:
                # Safe to reuse; proceed to dataset-level regeneration if needed.
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
                if not paper_artifacts_path(freeze_path).exists():
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

            baseline_ids = _ordered_freeze_run_ids(base_ids, checksums=checksums)
            interactive_ids = _ordered_freeze_run_ids(inter_ids, checksums=checksums)
            run_ids = baseline_ids + interactive_ids

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
            specs = fixed_model_specs(seed, ml_config=config)

            # Phase labels are freeze-derived and deterministic. Multiple eligible
            # runs are preserved at per-run grain and aggregate into the paper-facing
            # idle/interactive phases.
            per_run_phase = {rid: "idle" for rid in baseline_ids}
            per_run_phase.update({rid: "interactive" for rid in interactive_ids})
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
                if freeze_dataset_hash and _read_model_manifest_freeze_hash(out_dir_pf) != freeze_dataset_hash:
                    _clear_stale_ml_output_dir(out_dir_pf)
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

            # Require the minimum freeze contract to window successfully.
            baseline_rows_by_run = {
                rid: per_run_rows.get(rid, ([], 0))[0]
                for rid in baseline_ids
                if per_run_rows.get(rid, ([], 0))[0]
            }
            interactive_rows_by_run = {
                rid: per_run_rows.get(rid, ([], 0))[0]
                for rid in interactive_ids
                if per_run_rows.get(rid, ([], 0))[0]
            }
            if len(baseline_rows_by_run) < 1 or len(interactive_rows_by_run) < 2:
                _write_app_skip(app_runs, frozen=True, reason="ML_SKIPPED_INSUFFICIENT_RUNS")
                runs_skipped += len(app_runs)
                continue

            # Training selection (paper contract):
            # baseline-only; use all eligible baseline runs in the locked window.
            baseline_rows = [row for rid in baseline_ids for row in per_run_rows.get(rid, ([], 0))[0]]
            bytes_ok, min_bytes = _baseline_bytes_gate_ok(app_runs, baseline_rids=baseline_ids)
            windows_ok = len(baseline_rows) >= int(config.MIN_WINDOWS_BASELINE)
            if not (bytes_ok and windows_ok and baseline_rows):
                _write_app_skip(
                    app_runs,
                    frozen=True,
                    reason="ML_SKIPPED_BASELINE_GATE_FAIL",
                    details={
                        "baseline_windows_total": int(len(baseline_rows)),
                        "baseline_run_count": int(len(baseline_ids)),
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
                        "baseline_run_ids": list(baseline_ids),
                        "baseline_run_count": int(len(baseline_ids)),
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

                baseline_pcap_bytes = sum(
                    int(_pcap_size_bytes_from_inputs(r) or 0)
                    for r in app_runs
                    if r.run_id in set(baseline_ids)
                )
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
                        "baseline_run_count": int(len(baseline_ids)),
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
                        ml_config_fingerprint=ml_fp,
                        ml_config_fingerprint_payload=ml_fp_payload,
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
            app_dars_rows = _compute_dars_component_rows(
                package_name=pkg,
                app_runs=app_runs,
                per_model_scores_by_run=per_model_scores_by_run,
                per_model_thresholds=per_model_thresholds,
                per_run_phase=per_run_phase,
                per_run_tag=per_run_tag,
                training_mode=training_mode,
            )
            dars_component_rows.extend(app_dars_rows)
            baseline_stability_rows.extend(
                _compute_baseline_stability_rows(
                    package_name=pkg,
                    baseline_run_ids=baseline_ids,
                    per_model_scores_by_run=per_model_scores_by_run,
                    per_model_thresholds=per_model_thresholds,
                    training_mode=training_mode,
                )
            )
            static_dynamic_rows.append(
                _compute_static_dynamic_stratification_row(
                    package_name=pkg,
                    static_snapshot=_extract_static_snapshot(app_runs),
                    dars_rows=app_dars_rows,
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
        _write_dars_components_csv(dars_component_rows)
        _write_baseline_stability_csv(baseline_stability_rows)
        _write_static_dynamic_stratification_csv(static_dynamic_rows)
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


def _read_model_manifest_freeze_hash(out_dir: Path) -> str | None:
    manifest = out_dir / "model_manifest.json"
    if not manifest.exists():
        return None
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    value = str(payload.get("freeze_dataset_hash") or "").strip()
    return value or None


def _clear_stale_ml_output_dir(out_dir: Path) -> None:
    """Remove derived per-run ML files before rebuilding for a new freeze."""
    if not out_dir.exists():
        return
    for path in out_dir.iterdir():
        if not path.is_file():
            continue
        try:
            path.unlink()
        except FileNotFoundError:
            continue


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


def _ordered_freeze_run_ids(values: object, *, checksums: dict[str, Any]) -> list[str]:
    if not isinstance(values, list):
        return []
    ids = [str(x).strip() for x in values if str(x).strip()]
    return sorted(dict.fromkeys(ids), key=lambda rid: (_parse_ended_at_epoch((checksums.get(rid) or {}).get("ended_at")), rid))


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


def _baseline_bytes_gate_ok(app_runs: list[RunInputs], *, baseline_rids: list[str]) -> tuple[bool, int]:
    wanted = {str(rid) for rid in baseline_rids if str(rid).strip()}
    baselines = [r for r in app_runs if r.run_id in wanted]
    if not baselines:
        return False, int(config.MIN_PCAP_BYTES_FALLBACK)

    fallback_min_bytes = int(config.MIN_PCAP_BYTES_FALLBACK)
    thresholds: list[int] = []
    for baseline in baselines:
        ds = baseline.manifest.get("dataset") if isinstance(baseline.manifest.get("dataset"), dict) else {}
        min_bytes = ds.get("min_pcap_bytes")
        try:
            threshold = int(min_bytes) if min_bytes is not None else fallback_min_bytes
        except Exception:
            threshold = fallback_min_bytes
        thresholds.append(max(0, int(threshold)))

    for baseline, min_bytes_i in zip(baselines, thresholds):
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
        if size_bytes is None or size_bytes < min_bytes_i:
            return False, min_bytes_i
    return True, max(thresholds) if thresholds else fallback_min_bytes


def _rows_to_matrix(rows: list[dict[str, Any]], *, window_spec: WindowSpec) -> tuple[np.ndarray, list[str]]:
    return rows_to_basic_matrix(rows, window_spec=window_spec, feature_log1p=bool(config.FEATURE_LOG1P))


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


def _maybe_write_paper_artifacts_json(*, candidate: _ExemplarCandidate | None, freeze_manifest_path: Path) -> None:
    """Write a stable, human-readable lock file for the paper's flagship timeline exemplar.

    This file is dataset-adjacent (stored next to the freeze manifest). It is
    reused only while it matches the current freeze dataset hash; rebuilding the
    anchor intentionally repins the exemplar against the new locked dataset.
    """
    path = paper_artifacts_path(freeze_manifest_path)
    freeze_dataset_hash = _freeze_dataset_hash_from_path(freeze_manifest_path)
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if isinstance(existing, dict) and str(existing.get("freeze_dataset_hash") or "").strip() == freeze_dataset_hash:
            return
    if not candidate:
        # No eligible exemplar (e.g., no video-tagged interactive runs). Leave absent rather than guessing.
        return
    payload: dict[str, Any] = {
        "freeze_anchor": str(freeze_manifest_path),
        "freeze_dataset_hash": freeze_dataset_hash,
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


def _freeze_dataset_hash_from_path(path: Path) -> str:
    try:
        payload = _load_freeze_payload(path)
    except Exception:
        return ""
    return str(payload.get("freeze_dataset_hash") or "").strip()


def _missing_dataset_level_outputs() -> list[str]:
    """Return a list of missing required dataset-level CSV paths (relative)."""
    out_dir = Path(app_config.DATA_DIR)
    missing = []
    for name in dataset_level_table_names():
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
    dars_rows: list[dict[str, Any]] = []
    baseline_stability_rows: list[dict[str, Any]] = []
    static_dynamic_rows: list[dict[str, Any]] = []

    included = _load_frozen_run_ids_from_payload(freeze_payload) or set()

    for pkg, entry in sorted(freeze_apps.items()):
        if not isinstance(entry, dict):
            continue
        base_ids = entry.get("baseline_run_ids") or []
        inter_ids = entry.get("interactive_run_ids") or []
        if not (isinstance(base_ids, list) and isinstance(inter_ids, list) and len(base_ids) >= 1 and len(inter_ids) >= 2):
            continue
        baseline_ids = _ordered_freeze_run_ids(base_ids, checksums=checksums)
        interactive_ids = _ordered_freeze_run_ids(inter_ids, checksums=checksums)
        run_ids = baseline_ids + interactive_ids
        for rid in run_ids:
            if rid not in included:
                raise RuntimeError(f"Freeze manifest inconsistency (rebuild): {rid} not in included_run_ids")

        per_run_phase = {rid: "idle" for rid in baseline_ids}
        per_run_phase.update({rid: "interactive" for rid in interactive_ids})

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
            baseline_model_rid = baseline_ids[0]
            mf = _ml_output_dir(evidence_root / baseline_model_rid, frozen=True) / "model_manifest.json"
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

        bytes_ok, min_bytes = _baseline_bytes_gate_ok([inputs_by_rid[r] for r in run_ids], baseline_rids=baseline_ids)
        baseline_windows = sum(len(per_model_scores_by_run[config.MODEL_IFOREST].get(rid) or []) for rid in baseline_ids)
        windows_ok = baseline_windows >= int(config.MIN_WINDOWS_BASELINE)
        baseline_pcap_bytes = sum(int(_pcap_size_bytes_from_inputs(inputs_by_rid[rid]) or 0) for rid in baseline_ids)
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

        phase_rows.extend(
            _compute_phase_rows(
                identity_key=identity_key,
                package_name=pkg,
                app_runs=[inputs_by_rid[r] for r in run_ids],
                per_model_scores_by_run=per_model_scores_by_run,
                per_model_thresholds=per_model_thresholds,
                per_run_phase=per_run_phase,
                per_run_tag=tag_by_rid,
                training_mode=training_mode,
                per_run_empty_windows={rid: 0 for rid in run_ids},
            )
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
        app_dars_rows = _compute_dars_component_rows(
            package_name=pkg,
            app_runs=[inputs_by_rid[r] for r in run_ids],
            per_model_scores_by_run=per_model_scores_by_run,
            per_model_thresholds=per_model_thresholds,
            per_run_phase=per_run_phase,
            per_run_tag=tag_by_rid,
            training_mode=training_mode,
        )
        dars_rows.extend(app_dars_rows)
        baseline_stability_rows.extend(
                _compute_baseline_stability_rows(
                    package_name=pkg,
                    baseline_run_ids=baseline_ids,
                    per_model_scores_by_run=per_model_scores_by_run,
                    per_model_thresholds=per_model_thresholds,
                    training_mode=training_mode,
            )
        )
        static_dynamic_rows.append(
            _compute_static_dynamic_stratification_row(
                package_name=pkg,
                static_snapshot=_extract_static_snapshot([inputs_by_rid[r] for r in run_ids]),
                dars_rows=app_dars_rows,
            )
        )

    _write_ml_audit_csv(audit_rows)
    _write_prevalence_csvs(phase_rows)
    _write_model_overlap_csv(overlap_rows)
    _write_transport_mix_csvs(transport_rows)
    _write_dars_components_csv(dars_rows)
    _write_baseline_stability_csv(baseline_stability_rows)
    _write_static_dynamic_stratification_csv(static_dynamic_rows)


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
            try:
                packets = extract_packet_timeline(inputs.pcap_path)
                rows, dropped = build_window_features(
                    packets,
                    duration_s=float(dur),
                    spec=WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S),
                )
            except Exception:
                continue
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

    Exemplar selection protocol:
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _to_mysql_dt(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1]
    if "T" in raw:
        raw = raw.replace("T", " ")
    if len(raw) >= 19:
        return raw[:19]
    return None


__all__ = ["MlRunStats", "run_ml_on_evidence_packs"]
