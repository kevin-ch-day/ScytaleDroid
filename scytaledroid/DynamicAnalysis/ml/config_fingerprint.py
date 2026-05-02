"""Deterministic ML configuration fingerprinting (Profile v2 / legacy keys).

Existence checks are not sufficient for reuse safety. This module computes a stable
fingerprint over the semantic configuration that affects model outputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_ml_config_fingerprint(*, payload: dict[str, Any]) -> str:
    """Return sha256 over a canonical JSON blob."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def profile_v2_fingerprint_payload(*, ml_config: Any) -> dict[str, Any]:
    """Build the semantic fingerprint payload for Profile v2 (legacy paper2 keys).

    Include only items that can change outputs. Exclude timestamps, hostnames, paths.
    """
    # Keep this explicit (avoid accidental drift from introspection).
    return {
        "paper": "paper2",
        "ml_schema_version": int(ml_config.ML_SCHEMA_VERSION),
        "paper_contract_version": int(ml_config.PAPER_CONTRACT_VERSION),
        "windowing": {
            "window_size_s": float(ml_config.WINDOW_SIZE_S),
            "window_stride_s": float(ml_config.WINDOW_STRIDE_S),
            "drop_partial_windows": True,
        },
        "features": {
            "names": ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"],
            "log1p": bool(ml_config.FEATURE_LOG1P),
            "robust_scale": bool(ml_config.FEATURE_ROBUST_SCALE),
        },
        "thresholding": {
            "percentile": float(ml_config.THRESHOLD_PERCENTILE),
            "np_percentile_method": str(ml_config.NP_PERCENTILE_METHOD),
            # Score semantics: >= tau
            "comparison": "ge",
        },
        "quality_gates": {
            "min_windows_baseline": int(ml_config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(ml_config.MIN_PCAP_BYTES_FALLBACK),
        },
        "seed": {
            "salt_label": str(ml_config.SEED_SALT_LABEL),
            "salt": str(ml_config.SEED_SALT),
        },
        "models": {
            "iforest": {
                "n_estimators": int(ml_config.IFOREST_N_ESTIMATORS),
                "max_samples": ml_config.IFOREST_MAX_SAMPLES,
                "bootstrap": bool(ml_config.IFOREST_BOOTSTRAP),
            },
            "ocsvm": {
                "kernel": str(ml_config.OCSVM_KERNEL),
                "nu": float(ml_config.OCSVM_NU),
                "gamma": str(ml_config.OCSVM_GAMMA),
                "shrinking": bool(ml_config.OCSVM_SHRINKING),
                "tol": float(ml_config.OCSVM_TOL),
            },
        },
    }
__all__ = ["compute_ml_config_fingerprint", "profile_v2_fingerprint_payload"]
