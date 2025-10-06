"""profiles.py - Metadata helpers for world clock city profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable


@dataclass(frozen=True)
class ClockProfile:
    """Describe a city/timezone pairing for the world clock dashboard."""

    city: str
    country: str
    region: str
    locale_summary: str


_PROFILE_BY_KEY: Dict[str, ClockProfile] = {
    "minneapolis, usa": ClockProfile(
        city="Minneapolis",
        country="United States",
        region="North America",
        locale_summary="Upper Midwest innovation corridor on the Mississippi River.",
    ),
    "las vegas, usa": ClockProfile(
        city="Las Vegas",
        country="United States",
        region="North America",
        locale_summary="Mojave Desert events hub and frequent host for security expos.",
    ),
    "dubai, uae": ClockProfile(
        city="Dubai",
        country="United Arab Emirates",
        region="Middle East",
        locale_summary="Persian Gulf technology, aviation, and finance centre.",
    ),
    "paris, france": ClockProfile(
        city="Paris",
        country="France",
        region="Europe",
        locale_summary="European capital city with major aerospace and defence showcases.",
    ),
    "london (utc)": ClockProfile(
        city="London",
        country="United Kingdom",
        region="Europe",
        locale_summary="Greenwich Mean Time reference location for UTC planning.",
    ),
    "london, united kingdom": ClockProfile(
        city="London",
        country="United Kingdom",
        region="Europe",
        locale_summary="Global financial hub anchored on the River Thames.",
    ),
    "etc/utc": ClockProfile(
        city="UTC",
        country="Coordinated Universal Time",
        region="Global",
        locale_summary="Zero-offset baseline used for worldwide coordination.",
    ),
}


_PREFIX_REGION: Dict[str, str] = {
    "africa": "Africa",
    "america": "North / South America",
    "antarctica": "Antarctica",
    "asia": "Asia",
    "atlantic": "Atlantic Ocean",
    "australia": "Oceania",
    "europe": "Europe",
    "indian": "Indian Ocean",
    "pacific": "Pacific Ocean",
    "etc": "Global",
}


def _normalise_key(value: str | None) -> str:
    return (value or "").strip().lower()


def _fallback_profile(label: str, timezone: str) -> ClockProfile:
    city, country = (label.split(",", 1) + [""])[:2]
    city = city.strip() or label.strip() or timezone
    country = country.strip() or ""

    prefix = timezone.split("/", 1)[0].lower() if timezone else ""
    region = _PREFIX_REGION.get(prefix, "Global")
    summary_country = f" {country}" if country else ""
    locale_summary = f"Key location in {region}{summary_country}."

    return ClockProfile(
        city=city,
        country=country or region,
        region=region,
        locale_summary=locale_summary,
    )


def get_profile(label: str, timezone: str) -> ClockProfile:
    """Return descriptive metadata for *label* and *timezone*."""

    keys_to_try: Iterable[str] = (
        _normalise_key(label),
        _normalise_key(timezone),
        _normalise_key(label.replace("-", " ")),
    )

    for key in keys_to_try:
        if key in _PROFILE_BY_KEY:
            return _PROFILE_BY_KEY[key]

    return _fallback_profile(label, timezone)


def featured_timezones() -> Iterable[tuple[str, str]]:
    """Return curated reference cities to highlight alongside the dashboard."""

    return (
        ("London, United Kingdom", "Etc/UTC"),
        ("Paris, France", "Europe/Paris"),
    )


__all__ = ["ClockProfile", "featured_timezones", "get_profile"]
