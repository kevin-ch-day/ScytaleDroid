"""Baseline-idle app-activity tagging (inverse of low_signal).

The tag captures app-generated foreground traffic during a no-touch baseline.
It is an analysis signal, not proof of operator interaction and not by itself a
quota exclusion.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package


@dataclass(frozen=True)
class BaselineActivityConfig:
    min_capture_duration_s: float = 90.0
    max_idle_bytes_total: int = 8_000_000
    max_idle_bytes_per_sec_avg: float = 35_000.0
    max_quic_ratio_with_bytes: float = 0.60
    quic_ratio_min_bytes: int = 5_000_000
    max_bytes_per_second_p95: float = 300_000.0
    social_feed_max_idle_bytes_total: int = 6_000_000
    social_feed_max_idle_bytes_per_sec_avg: float = 28_000.0


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _effective_config(
    cfg: BaselineActivityConfig,
    *,
    package_name: str | None,
) -> BaselineActivityConfig:
    category = str(category_for_package(str(package_name or "").strip().lower()) or "").strip().lower()
    if category != "social_feed":
        return cfg
    return BaselineActivityConfig(
        min_capture_duration_s=cfg.min_capture_duration_s,
        max_idle_bytes_total=cfg.social_feed_max_idle_bytes_total,
        max_idle_bytes_per_sec_avg=cfg.social_feed_max_idle_bytes_per_sec_avg,
        max_quic_ratio_with_bytes=cfg.max_quic_ratio_with_bytes,
        quic_ratio_min_bytes=cfg.quic_ratio_min_bytes,
        max_bytes_per_second_p95=cfg.max_bytes_per_second_p95,
        social_feed_max_idle_bytes_total=cfg.social_feed_max_idle_bytes_total,
        social_feed_max_idle_bytes_per_sec_avg=cfg.social_feed_max_idle_bytes_per_sec_avg,
    )


def compute_baseline_activity_from_evidence_pack(
    run_dir: Path,
    *,
    cfg: BaselineActivityConfig | None = None,
) -> dict[str, Any] | None:
    features_path = run_dir / "analysis" / "pcap_features.json"
    pf = _read_json(features_path)
    if not isinstance(pf, dict):
        return None

    config = cfg or BaselineActivityConfig()
    metrics = pf.get("metrics") if isinstance(pf.get("metrics"), dict) else {}
    proxies = pf.get("proxies") if isinstance(pf.get("proxies"), dict) else {}

    try:
        duration_s = float(metrics.get("capture_duration_s"))
    except Exception:
        duration_s = None
    try:
        data_bytes = int(metrics.get("data_size_bytes"))
    except Exception:
        data_bytes = None
    try:
        bytes_per_sec = float(metrics.get("bytes_per_sec"))
    except Exception:
        bytes_per_sec = None
    try:
        bytes_per_second_p95 = float(metrics.get("bytes_per_second_p95"))
    except Exception:
        bytes_per_second_p95 = None
    try:
        quic_ratio = float(proxies.get("quic_ratio"))
    except Exception:
        quic_ratio = None

    reasons: list[str] = []
    if duration_s is not None and duration_s >= float(config.min_capture_duration_s):
        if data_bytes is not None and data_bytes >= int(config.max_idle_bytes_total):
            reasons.append("BASELINE_BYTES_HIGH")
        if (
            bytes_per_sec is not None
            and bytes_per_sec >= float(config.max_idle_bytes_per_sec_avg)
        ):
            reasons.append("BASELINE_SUSTAINED_DOWNLINK")
        if (
            quic_ratio is not None
            and data_bytes is not None
            and quic_ratio >= float(config.max_quic_ratio_with_bytes)
            and data_bytes >= int(config.quic_ratio_min_bytes)
        ):
            reasons.append("BASELINE_QUIC_MEDIA_HEAVY")
        if (
            bytes_per_second_p95 is not None
            and bytes_per_second_p95 >= float(config.max_bytes_per_second_p95)
        ):
            reasons.append("BASELINE_TRAFFIC_BURST")

    return {
        "baseline_not_idle": bool(reasons),
        "baseline_not_idle_reasons": reasons,
        "exploratory_class": "BASELINE_NOT_IDLE" if reasons else None,
        "baseline_not_idle_thresholds": {
            "min_capture_duration_s": float(config.min_capture_duration_s),
            "max_idle_bytes_total": int(config.max_idle_bytes_total),
            "max_idle_bytes_per_sec_avg": float(config.max_idle_bytes_per_sec_avg),
            "max_quic_ratio_with_bytes": float(config.max_quic_ratio_with_bytes),
            "quic_ratio_min_bytes": int(config.quic_ratio_min_bytes),
            "max_bytes_per_second_p95": float(config.max_bytes_per_second_p95),
        },
    }


def compute_baseline_activity_for_run(
    run_dir: Path,
    *,
    package_name: str | None,
    run_profile: str | None,
    cfg: BaselineActivityConfig | None = None,
) -> dict[str, Any] | None:
    profile_lc = str(run_profile or "").strip().lower()
    if profile_lc != "baseline_idle":
        return None
    config = _effective_config(cfg or BaselineActivityConfig(), package_name=package_name)
    return compute_baseline_activity_from_evidence_pack(run_dir, cfg=config)


__all__ = [
    "BaselineActivityConfig",
    "compute_baseline_activity_for_run",
    "compute_baseline_activity_from_evidence_pack",
]
