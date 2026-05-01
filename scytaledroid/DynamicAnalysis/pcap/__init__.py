"""PCAP utilities for dynamic analysis.

Keep imports lazy; PCAP utilities are used by many tools that should not have to
import the full dynamic orchestrator stack during module import.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "export_pcap_features_csv",
    "export_dynamic_run_summary_csv",
    "OverlapConfig",
    "write_static_dynamic_overlap",
    "DatasetTrackerConfig",
    "load_dataset_tracker",
    "recompute_dataset_tracker",
    "update_dataset_tracker",
    "PcapFeatureConfig",
    "write_pcap_features",
    "PcapIndexConfig",
    "index_pcap_by_app",
    "PcapReportConfig",
    "write_pcap_report",
]


def __getattr__(name: str) -> Any:  # pragma: no cover - import-time shim
    if name in {"export_dynamic_run_summary_csv", "export_pcap_features_csv"}:
        from .aggregate import export_dynamic_run_summary_csv, export_pcap_features_csv

        return {"export_dynamic_run_summary_csv": export_dynamic_run_summary_csv, "export_pcap_features_csv": export_pcap_features_csv}[name]
    if name in {"OverlapConfig", "write_static_dynamic_overlap"}:
        from .correlate import OverlapConfig, write_static_dynamic_overlap

        return {"OverlapConfig": OverlapConfig, "write_static_dynamic_overlap": write_static_dynamic_overlap}[name]
    if name in {"DatasetTrackerConfig", "load_dataset_tracker", "recompute_dataset_tracker", "update_dataset_tracker"}:
        from .dataset_tracker import DatasetTrackerConfig, load_dataset_tracker, recompute_dataset_tracker, update_dataset_tracker

        return {
            "DatasetTrackerConfig": DatasetTrackerConfig,
            "load_dataset_tracker": load_dataset_tracker,
            "recompute_dataset_tracker": recompute_dataset_tracker,
            "update_dataset_tracker": update_dataset_tracker,
        }[name]
    if name in {"PcapFeatureConfig", "write_pcap_features"}:
        from .features import PcapFeatureConfig, write_pcap_features

        return {"PcapFeatureConfig": PcapFeatureConfig, "write_pcap_features": write_pcap_features}[name]
    if name in {"PcapIndexConfig", "index_pcap_by_app"}:
        from .indexer import PcapIndexConfig, index_pcap_by_app

        return {"PcapIndexConfig": PcapIndexConfig, "index_pcap_by_app": index_pcap_by_app}[name]
    if name in {"PcapReportConfig", "write_pcap_report"}:
        from .report import PcapReportConfig, write_pcap_report

        return {"PcapReportConfig": PcapReportConfig, "write_pcap_report": write_pcap_report}[name]
    raise AttributeError(name)

