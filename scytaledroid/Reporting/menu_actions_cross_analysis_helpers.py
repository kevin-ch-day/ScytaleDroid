"""Formatting helpers for cross-analysis reporting menu output."""

from __future__ import annotations


def compact_gap(value: object) -> str:
    text = str(value or "—")
    mapping = {
        "latest_run_has_features": "latest-ok",
        "latest_run_missing_features_older_features_exist": "older-features",
        "no_feature_rows_for_package": "no-features-ever",
        "—": "—",
    }
    return mapping.get(text, text)


def compact_regime(value: object) -> str:
    text = str(value or "—")
    if text == "—":
        return text
    replacements = {
        "Low Exposure": "LE",
        "Medium Exposure": "ME",
        "High Exposure": "HE",
        "Low Deviation": "LD",
        "Medium Deviation": "MD",
        "High Deviation": "HD",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text.replace(" + ", "+")


def compact_runtime_state(technical_state: object, quota_state: object) -> str:
    tech = {
        "TECH_VALID": "valid",
        "TECH_INVALID": "invalid",
        "TECH_LEGACY_UNKNOWN": "legacy",
        "": "—",
    }.get(str(technical_state or "").strip().upper(), str(technical_state or "—") or "—")
    quota = {
        "QUOTA_VALID": "quota",
        "SUPPLEMENTAL_VALID": "supp",
        "QUOTA_INELIGIBLE": "inelig",
        "VALID_COUNTING_UNKNOWN": "count-?",
        "QUOTA_LEGACY_UNKNOWN": "legacy",
        "": "—",
    }.get(str(quota_state or "").strip().upper(), str(quota_state or "—") or "—")
    if tech == "—" and quota == "—":
        return "—"
    if quota == "—":
        return tech
    return f"{tech}/{quota}"
