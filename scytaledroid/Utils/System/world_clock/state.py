"""world_clock_state.py - Helpers for persisting world clock settings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import zoneinfo

from scytaledroid.Config import app_config


class WorldClockError(RuntimeError):
    """Base class for world clock configuration issues."""


class ClockLimitError(WorldClockError):
    """Raised when attempting to add more clocks than the limit allows."""


class MinimumClockError(WorldClockError):
    """Raised when an operation would leave the dashboard without clocks."""


class TimezoneValidationError(WorldClockError):
    """Raised when a supplied timezone identifier cannot be resolved."""


@dataclass
class WorldClockState:
    """Snapshot of the persisted world clock configuration."""

    clocks: Dict[str, str]
    defaults: Dict[str, str]
    max_clocks: int
    primary: Optional[str]
    primary_timezone: Optional[str]


def _normalise_max(value: object) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = 3
    return max(1, min(parsed, 3))


def _validate_timezone(tz_name: str) -> None:
    try:
        zoneinfo.ZoneInfo(tz_name)
    except Exception as exc:  # pragma: no cover - defensive path
        raise TimezoneValidationError(
            f"Invalid timezone identifier '{tz_name}'."
        ) from exc


def load_state() -> WorldClockState:
    """Return a ``WorldClockState`` representing the stored preferences."""

    defaults = dict(getattr(app_config, "DEFAULT_UI_TIMEZONES", {}))
    configured = dict(getattr(app_config, "UI_TIMEZONES", {}))
    max_clocks = _normalise_max(getattr(app_config, "UI_MAX_CLOCKS", 3))

    trimmed = dict(list(configured.items())[:max_clocks])
    if len(trimmed) != len(configured):
        app_config.UI_TIMEZONES = dict(trimmed)
    clocks = trimmed or dict(list(defaults.items())[:max_clocks])
    if not clocks:
        clocks = {"Local": "Etc/UTC"}
    app_config.UI_TIMEZONES = dict(clocks)

    primary = getattr(app_config, "UI_PRIMARY_CLOCK", None)
    if primary not in clocks:
        primary = next(iter(clocks), None)
        app_config.UI_PRIMARY_CLOCK = primary

    primary_timezone = clocks.get(primary)
    if not primary_timezone:
        primary_timezone = next(iter(clocks.values()), "Etc/UTC")

    # Keep legacy attributes aligned with the primary selection for compatibility
    app_config.UI_LOCAL_TIME_LABEL = primary
    app_config.UI_LOCAL_TIMEZONE = primary_timezone

    return WorldClockState(
        clocks=clocks,
        defaults=defaults,
        max_clocks=max_clocks,
        primary=primary,
        primary_timezone=primary_timezone,
    )


def upsert_clock(label: str, tz_name: str, *, max_clocks: int) -> bool:
    """Insert or update a clock entry, enforcing the configured limit."""

    cleaned_label = label.strip()
    if not cleaned_label:
        raise ValueError("Clock label must not be empty.")

    tz_name = tz_name.strip()
    _validate_timezone(tz_name)

    clocks = dict(getattr(app_config, "UI_TIMEZONES", {}))
    exists = cleaned_label in clocks
    if not exists and len(clocks) >= max_clocks:
        raise ClockLimitError(
            f"Limit of {max_clocks} clocks reached. Remove one before adding new entries."
        )

    clocks[cleaned_label] = tz_name
    app_config.UI_TIMEZONES = dict(clocks)

    if not getattr(app_config, "UI_PRIMARY_CLOCK", None):
        app_config.UI_PRIMARY_CLOCK = cleaned_label
        app_config.UI_LOCAL_TIME_LABEL = cleaned_label
        app_config.UI_LOCAL_TIMEZONE = tz_name

    return exists


def remove_clock(label: str, *, min_clocks: int = 1) -> bool:
    """Remove *label* from the configuration if possible."""

    clocks = dict(getattr(app_config, "UI_TIMEZONES", {}))
    if label not in clocks:
        return False
    if len(clocks) <= min_clocks:
        raise MinimumClockError(
            "At least one clock must remain configured for the dashboard."
        )

    del clocks[label]
    app_config.UI_TIMEZONES = dict(clocks)

    if getattr(app_config, "UI_PRIMARY_CLOCK", None) == label:
        app_config.UI_PRIMARY_CLOCK = next(iter(clocks), None)

    primary_label = getattr(app_config, "UI_PRIMARY_CLOCK", None)
    if primary_label not in clocks:
        primary_label = next(iter(clocks), None)
        app_config.UI_PRIMARY_CLOCK = primary_label
    fallback_timezone = clocks.get(primary_label) or next(
        iter(clocks.values()), "Etc/UTC"
    )
    app_config.UI_LOCAL_TIME_LABEL = primary_label
    app_config.UI_LOCAL_TIMEZONE = fallback_timezone

    return True


def reset_to_defaults(max_clocks: int) -> None:
    """Restore the configured clocks to the application defaults."""

    defaults = dict(getattr(app_config, "DEFAULT_UI_TIMEZONES", {}))
    restored = dict(list(defaults.items())[:max_clocks])
    if not restored:
        restored = {"Minneapolis, USA": "America/Chicago"}

    app_config.UI_TIMEZONES = dict(restored)
    app_config.UI_PRIMARY_CLOCK = next(iter(restored), None)

    primary_label = app_config.UI_PRIMARY_CLOCK
    app_config.UI_LOCAL_TIME_LABEL = primary_label
    app_config.UI_LOCAL_TIMEZONE = restored.get(primary_label, "Etc/UTC")


def set_primary_clock(label: str) -> None:
    """Designate *label* as the primary display clock."""

    clocks = getattr(app_config, "UI_TIMEZONES", {})
    if label not in clocks:
        raise KeyError(label)
    app_config.UI_PRIMARY_CLOCK = label

    app_config.UI_LOCAL_TIME_LABEL = label
    app_config.UI_LOCAL_TIMEZONE = clocks.get(label, "Etc/UTC")


__all__ = [
    "ClockLimitError",
    "MinimumClockError",
    "TimezoneValidationError",
    "WorldClockError",
    "WorldClockState",
    "load_state",
    "remove_clock",
    "reset_to_defaults",
    "set_primary_clock",
    "upsert_clock",
]
