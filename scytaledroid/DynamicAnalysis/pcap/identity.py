"""Capture identity helpers for PCAP-derived artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .naming import package_slug


def build_capture_identity(
    *,
    dynamic_run_id: str | None,
    package_name: str | None,
    app_label: str | None = None,
    pcap_capture_name: str | None = None,
) -> dict[str, str | None]:
    return {
        "dynamic_run_id": str(dynamic_run_id or "").strip() or None,
        "package_name": str(package_name or "").strip() or None,
        "package_slug": package_slug(package_name),
        "app_label": str(app_label or "").strip() or None,
        "pcap_capture_name": str(pcap_capture_name or "").strip() or None,
        "naming_scheme": "scytaledroid_{package_slug}_{dynamic_run_id}.pcap",
    }


def infer_pcap_capture_name(report: dict[str, Any] | None = None) -> str | None:
    if not isinstance(report, dict):
        return None
    name = str(report.get("pcap_capture_name") or "").strip()
    if name:
        return name
    path_text = str(report.get("pcap_path") or "").strip()
    return Path(path_text).name if path_text else None


def ensure_report_capture_identity(
    report: dict[str, Any],
    *,
    dynamic_run_id: str | None,
    package_name: str | None,
    app_label: str | None = None,
) -> bool:
    changed = False
    resolved_label = str(app_label or report.get("app_label") or "").strip() or None
    pcap_capture_name = infer_pcap_capture_name(report)
    if report.get("pcap_capture_name") != pcap_capture_name:
        report["pcap_capture_name"] = pcap_capture_name
        changed = True
    desired = build_capture_identity(
        dynamic_run_id=dynamic_run_id,
        package_name=package_name,
        app_label=resolved_label,
        pcap_capture_name=pcap_capture_name,
    )
    current = report.get("capture_identity") if isinstance(report.get("capture_identity"), dict) else {}
    merged = dict(current)
    for key, value in desired.items():
        if merged.get(key) != value:
            merged[key] = value
            changed = True
    report["capture_identity"] = merged
    return changed


def ensure_features_capture_identity(
    features: dict[str, Any],
    *,
    dynamic_run_id: str | None,
    package_name: str | None,
    app_label: str | None = None,
    report: dict[str, Any] | None = None,
) -> bool:
    quality = features.get("quality")
    if not isinstance(quality, dict):
        quality = {}
        features["quality"] = quality
    resolved_label = str(app_label or (report or {}).get("app_label") or "").strip() or None
    desired = build_capture_identity(
        dynamic_run_id=dynamic_run_id,
        package_name=package_name,
        app_label=resolved_label,
        pcap_capture_name=infer_pcap_capture_name(report),
    )
    current = quality.get("capture_identity") if isinstance(quality.get("capture_identity"), dict) else {}
    merged = dict(current)
    changed = False
    for key, value in desired.items():
        if merged.get(key) != value:
            merged[key] = value
            changed = True
    quality["capture_identity"] = merged
    return changed


__all__ = [
    "build_capture_identity",
    "ensure_features_capture_identity",
    "ensure_report_capture_identity",
    "infer_pcap_capture_name",
]
