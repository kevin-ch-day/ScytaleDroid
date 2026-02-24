"""Deterministic ML configuration fingerprinting (Paper #2).

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


def paper2_fingerprint_payload(*, ml_config: Any) -> dict[str, Any]:
    """Build the semantic fingerprint payload for Paper #2.

    Include only items that can change outputs. Exclude timestamps, hostnames, paths.
    """
    # Keep this explicit (avoid accidental drift from introspection).
    return {
        "paper": "paper2",
        "ml_schema_version": int(getattr(ml_config, "ML_SCHEMA_VERSION")),
        "paper_contract_version": int(getattr(ml_config, "PAPER_CONTRACT_VERSION")),
        "windowing": {
            "window_size_s": float(getattr(ml_config, "WINDOW_SIZE_S")),
            "window_stride_s": float(getattr(ml_config, "WINDOW_STRIDE_S")),
            "drop_partial_windows": True,
        },
        "features": {
            "names": ["bytes_per_sec", "packets_per_sec", "avg_packet_size_bytes"],
            "log1p": bool(getattr(ml_config, "FEATURE_LOG1P")),
            "robust_scale": bool(getattr(ml_config, "FEATURE_ROBUST_SCALE")),
        },
        "thresholding": {
            "percentile": float(getattr(ml_config, "THRESHOLD_PERCENTILE")),
            "np_percentile_method": str(getattr(ml_config, "NP_PERCENTILE_METHOD")),
            # Score semantics: >= tau
            "comparison": "ge",
        },
        "quality_gates": {
            "min_windows_baseline": int(getattr(ml_config, "MIN_WINDOWS_BASELINE")),
            "min_pcap_bytes": int(getattr(ml_config, "MIN_PCAP_BYTES_FALLBACK")),
        },
        "seed": {
            "salt_label": str(getattr(ml_config, "SEED_SALT_LABEL")),
            "salt": str(getattr(ml_config, "SEED_SALT")),
        },
        "models": {
            "iforest": {
                "n_estimators": int(getattr(ml_config, "IFOREST_N_ESTIMATORS")),
                "max_samples": getattr(ml_config, "IFOREST_MAX_SAMPLES"),
                "bootstrap": bool(getattr(ml_config, "IFOREST_BOOTSTRAP")),
            },
            "ocsvm": {
                "kernel": str(getattr(ml_config, "OCSVM_KERNEL")),
                "nu": float(getattr(ml_config, "OCSVM_NU")),
                "gamma": str(getattr(ml_config, "OCSVM_GAMMA")),
                "shrinking": bool(getattr(ml_config, "OCSVM_SHRINKING")),
                "tol": float(getattr(ml_config, "OCSVM_TOL")),
            },
        },
    }


__all__ = ["compute_ml_config_fingerprint", "paper2_fingerprint_payload"]

