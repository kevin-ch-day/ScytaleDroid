"""Derived duration tiers for dynamic evidence runs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DurationTier:
    key: str
    label: str
    description: str


MINIMUM_VALID_S = 3 * 60
TARGET_S = 4 * 60
EXTENDED_S = 8 * 60
LONG_OBSERVATION_S = 15 * 60
SOAK_S = 30 * 60


def classify_duration_tier(duration_s: float | int | None) -> DurationTier:
    """Return an analysis tier for a run duration.

    These tiers are descriptive only. Validity and quota eligibility stay owned
    by the dynamic tracker and evidence QA logic.
    """

    try:
        seconds = float(duration_s) if duration_s is not None else None
    except Exception:
        seconds = None
    if seconds is None or seconds < 0:
        return DurationTier("unknown", "Unknown", "duration unavailable")
    if seconds < MINIMUM_VALID_S:
        return DurationTier("short", "Short", "below 3 minute minimum")
    if seconds < TARGET_S:
        return DurationTier("minimum", "Minimum", "3 to under 4 minutes")
    if seconds < EXTENDED_S:
        return DurationTier("standard", "Standard", "4 to under 8 minutes")
    if seconds < LONG_OBSERVATION_S:
        return DurationTier("extended", "Extended", "8 to under 15 minutes")
    if seconds < SOAK_S:
        return DurationTier("long_observation", "Long observation", "15 to under 30 minutes")
    return DurationTier("soak", "Soak", "30 minutes or longer")


__all__ = [
    "EXTENDED_S",
    "LONG_OBSERVATION_S",
    "MINIMUM_VALID_S",
    "SOAK_S",
    "TARGET_S",
    "DurationTier",
    "classify_duration_tier",
]
