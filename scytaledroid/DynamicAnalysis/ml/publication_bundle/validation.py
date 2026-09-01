"""Validation and reproducibility reports for runtime ML publication bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.utils.path_utils import (
    dynamic_evidence_root,
    normalize_run_id,
    resolve_dynamic_run_dir,
    resolve_run_dir_under,
)
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from .. import ml_parameters_profile as config
from ..deliverable_bundle_paths import (
    freeze_anchor_path,
    output_locked_runtime_bundle_tables_dir,
)
from ..evidence_pack_ml_preflight import get_sampling_duration_seconds, load_run_inputs
from ..pcap_window_features import build_window_features, extract_packet_timeline
from ..telemetry_windowing import WindowSpec
from .manifest_utils import sha256_stream

PROHIBITED_PHRASES = (
    "outbound traffic",
    "payload bytes",
    "application-only traffic",
    "network requests",
    "strict app isolation",
)


def _included_run_ids(freeze_payload: object) -> list[str]:
    if not isinstance(freeze_payload, dict):
        raise ValueError("Freeze manifest must be an object")
    values = freeze_payload.get("included_run_ids")
    if not isinstance(values, list):
        raise ValueError("Freeze manifest included_run_ids must be a list")
    run_ids: list[str] = []
    for value in values:
        run_id = normalize_run_id(value)
        if run_id is None:
            raise ValueError(f"Unsafe freeze run_id: {value!r}")
        run_ids.append(run_id)
    return run_ids


def write_required_fields_validation_report(*, manifest_dir: Path) -> Path:
    """Required-field validation for publication-grade model manifests."""
    freeze_payload = json.loads(freeze_anchor_path().read_text(encoding="utf-8"))
    included_run_ids = _included_run_ids(freeze_payload)
    required_paths = {
        "seed": ("seed",),
        "window_size_s": ("windowing", "window_size_s"),
        "window_stride_s": ("windowing", "stride_s"),
        "threshold_percentile": ("models", config.MODEL_IFOREST, "threshold_percentile"),
        "np_percentile_method": ("models", config.MODEL_IFOREST, "np_percentile_method"),
        "feature_names": ("models", config.MODEL_IFOREST, "feature_names"),
        "model_params": ("models", config.MODEL_IFOREST, "params"),
        "training_mode": ("models", config.MODEL_IFOREST, "training_mode"),
        "numpy_version": ("environment", "deps", "numpy"),
        "sklearn_version": ("environment", "deps", "sklearn"),
        "tshark_version": ("environment", "host_tools", "tshark", "version"),
    }

    missing_by_run: dict[str, list[str]] = {}
    for rid in included_run_ids:
        path = _dynamic_run_dir(rid) / "analysis" / "ml" / config.ML_SCHEMA_LABEL / "model_manifest.json"
        if not path.exists():
            missing_by_run[rid] = sorted(required_paths.keys())
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            missing_by_run[rid] = sorted(required_paths.keys())
            continue
        missing: list[str] = []
        for field_name, token_path in required_paths.items():
            cur: Any = payload
            for token in token_path:
                if isinstance(cur, dict) and token in cur:
                    cur = cur[token]
                else:
                    cur = None
                    break
            if cur in (None, "", []):
                missing.append(field_name)
        if missing:
            missing_by_run[rid] = sorted(missing)

    checked_runs = len(included_run_ids)
    failed_runs = len(missing_by_run)
    payload = {
        "checked_runs": checked_runs,
        "failed_runs": failed_runs,
        "passed_runs": checked_runs - failed_runs,
        "paper_grade_ready": failed_runs == 0,
        "status": "PAPER_GRADE" if failed_runs == 0 else "EXPERIMENTAL",
        "missing_by_run": missing_by_run,
    }
    out_path = manifest_dir / "required_fields_validation.json"
    atomic_write_text(out_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return out_path


def write_phrase_lint_report(*, target_paths: tuple[Path, ...], out_path: Path) -> Path:
    violations: list[dict[str, str]] = []
    for path in target_paths:
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        lower = text.lower()
        for phrase in PROHIBITED_PHRASES:
            if phrase in lower:
                violations.append({"path": str(path), "phrase": phrase})
    payload = {
        "checked_files": [str(p) for p in target_paths if p.exists()],
        "prohibited_phrases": list(PROHIBITED_PHRASES),
        "ok": len(violations) == 0,
        "violations": violations,
    }
    atomic_write_text(out_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return out_path


def write_determinism_checksums(*, manifest_dir: Path) -> Path:
    """Write deterministic hash anchors for publication-facing reproducibility checks."""
    freeze_payload = json.loads(freeze_anchor_path().read_text(encoding="utf-8"))
    included_run_ids = _included_run_ids(freeze_payload)
    per_run: dict[str, Any] = {}
    spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)
    for rid in included_run_ids:
        run_dir = _dynamic_run_dir(rid)
        model_manifest = run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL / "model_manifest.json"
        if_scores = run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL / "anomaly_scores_iforest.csv"
        oc_scores = run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL / "anomaly_scores_ocsvm.csv"
        record: dict[str, Any] = {
            "model_manifest_sha256": sha256_stream(model_manifest) if model_manifest.exists() else None,
            "iforest_scores_sha256": sha256_stream(if_scores) if if_scores.exists() else None,
            "ocsvm_scores_sha256": sha256_stream(oc_scores) if oc_scores.exists() else None,
            "feature_matrix_sha256": None,
        }
        try:
            inputs = load_run_inputs(run_dir)
            if inputs and inputs.pcap_path and inputs.pcap_path.exists():
                duration_s = get_sampling_duration_seconds(inputs)
                if duration_s and duration_s > 0:
                    rows, _ = build_window_features(
                        extract_packet_timeline(inputs.pcap_path),
                        duration_s=float(duration_s),
                        spec=spec,
                    )
                    digest = hashlib.sha256()
                    for row in rows:
                        line = (
                            f"{float(row.get('window_start_s') or 0.0):.6f},"
                            f"{float(row.get('window_end_s') or 0.0):.6f},"
                            f"{int(row.get('packet_count') or 0)},"
                            f"{int(row.get('byte_count') or 0)},"
                            f"{float(row.get('avg_packet_size_bytes') or 0.0):.6f}\n"
                        )
                        digest.update(line.encode("utf-8"))
                    record["feature_matrix_sha256"] = digest.hexdigest()
        except Exception as exc:  # noqa: BLE001
            record["feature_matrix_error"] = str(exc)
        per_run[rid] = record

    table_1 = output_locked_runtime_bundle_tables_dir() / "table_1_rdi_prevalence.csv"
    table_8 = output_locked_runtime_bundle_tables_dir() / "table_8_model_comparison_metrics.csv"
    payload = {
        "freeze_anchor": str(freeze_anchor_path()),
        "freeze_sha256": sha256_stream(freeze_anchor_path()),
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "report_schema_version": int(config.REPORT_SCHEMA_VERSION),
        "window_spec": {"window_size_s": float(config.WINDOW_SIZE_S), "window_stride_s": float(config.WINDOW_STRIDE_S)},
        "table_hashes": {
            "table_1_rdi_prevalence_csv": sha256_stream(table_1) if table_1.exists() else None,
            "table_8_model_comparison_metrics_csv": sha256_stream(table_8) if table_8.exists() else None,
        },
        "per_run": per_run,
    }
    out_path = manifest_dir / "determinism_checksums.json"
    atomic_write_text(out_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return out_path


def _dynamic_run_dir(run_id: str | int | None) -> Path:
    rid = run_id if isinstance(run_id, str) else str(run_id or "")
    run_dir = resolve_dynamic_run_dir(rid)
    if run_dir is None:
        run_dir = resolve_run_dir_under(dynamic_evidence_root(), rid)
    if run_dir is None:
        raise ValueError(f"Unsafe dynamic run_id: {run_id!r}")
    return run_dir


__all__ = [
    "PROHIBITED_PHRASES",
    "write_determinism_checksums",
    "write_phrase_lint_report",
    "write_required_fields_validation_report",
]
