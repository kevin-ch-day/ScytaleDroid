"""Effective PCAP minima helpers for dynamic run policy."""

from __future__ import annotations

import os

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package
from scytaledroid.DynamicAnalysis.utils.profile_v3_minima import (
    effective_min_pcap_bytes_idle,
    effective_min_pcap_bytes_scripted,
)


def _env_int(name: str) -> int | None:
    raw = str(os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        return None


def effective_min_pcap_bytes_for_run_profile(
    *,
    run_profile: str | None,
    scenario_id: str | None = None,
    package_name: str | None = None,
    messaging_activity: str | None = None,
) -> int:
    profile = str(run_profile or "").strip().lower()
    scenario = str(scenario_id or "").strip().lower()
    package = str(package_name or "").strip().lower()
    activity = str(messaging_activity or "").strip().lower()

    if scenario == "paper3_profile_v3":
        if profile == "baseline_idle":
            return int(effective_min_pcap_bytes_idle())
        if profile == "interaction_scripted":
            return int(effective_min_pcap_bytes_scripted())

    if profile == "baseline_connected" or _is_connected_messaging_text_run(
        package_name=package,
        run_profile=profile,
        messaging_activity=activity,
    ):
        override = _env_int("SCYTALEDROID_MIN_PCAP_BYTES_BASELINE_CONNECTED")
        if override is not None:
            return int(override)
        return int(
            getattr(
                profile_config,
                "MIN_PCAP_BYTES_BASELINE_CONNECTED",
                getattr(profile_config, "MIN_PCAP_BYTES", 50_000),
            )
        )

    return int(getattr(profile_config, "MIN_PCAP_BYTES", 50_000))


def _is_connected_messaging_text_run(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str,
) -> bool:
    if run_profile != "interaction_manual":
        return False
    if category_for_package(package_name) != "messaging":
        return False
    return messaging_activity in {
        "connected_idle",
        "manual_freeform",
        "text_only",
    }


__all__ = ["effective_min_pcap_bytes_for_run_profile"]
