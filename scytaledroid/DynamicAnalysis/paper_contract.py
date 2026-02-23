"""Paper mode contract snapshot + hash (first-class reproducibility anchor)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN
from scytaledroid.DynamicAnalysis.templates.category_map import mapping_sha256, mapping_snapshot, mapping_version

PAPER_CONTRACT_VERSION = "v1"


def build_paper_contract_snapshot() -> dict[str, Any]:
    return {
        "paper_contract_version": PAPER_CONTRACT_VERSION,
        "capture_policy_version": int(getattr(paper2_config, "PAPER_CONTRACT_VERSION", 1)),
        "reason_taxonomy_version": int(getattr(paper2_config, "REASON_TAXONOMY_VERSION", 1)),
        "sampling": {
            "window_size_s": float(getattr(paper2_config, "WINDOW_SIZE_S", 10.0)),
            "window_stride_s": float(getattr(paper2_config, "WINDOW_STRIDE_S", 5.0)),
            "min_sampling_seconds": float(getattr(paper2_config, "MIN_SAMPLING_SECONDS", 180.0)),
            "recommended_sampling_seconds": float(getattr(paper2_config, "RECOMMENDED_SAMPLING_SECONDS", 240.0)),
            "min_windows_per_run": int(MIN_WINDOWS_PER_RUN),
        },
        "qa": {
            "min_pcap_bytes": int(getattr(paper2_config, "MIN_PCAP_BYTES", 50000)),
            "baseline_required": int(getattr(app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1)),
            "interactive_required": int(getattr(app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2)),
        },
        "templates": {
            "category_map_version": mapping_version(),
            "category_map_sha256": mapping_sha256(),
            "category_map": mapping_snapshot(),
            "canonical_template_ids": {
                "social_feed": "social_feed_basic_v2",
                "messaging": "messaging_basic_v1",
            },
            "canonical_baseline_protocols": {
                "default": {"id": "baseline_idle_v1", "version": 1},
                "messaging": {"id": "baseline_connected_v2", "version": 2},
            },
        },
    }


def paper_contract_hash(snapshot: dict[str, Any] | None = None) -> str:
    payload = snapshot if isinstance(snapshot, dict) else build_paper_contract_snapshot()
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


__all__ = [
    "PAPER_CONTRACT_VERSION",
    "build_paper_contract_snapshot",
    "paper_contract_hash",
]
