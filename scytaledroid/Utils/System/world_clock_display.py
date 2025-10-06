"""world_clock_display.py - Rendering helpers for the world clock dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

import zoneinfo

from scytaledroid.Utils.DisplayUtils import status_messages, table_utils

from .world_clock_profiles import ClockProfile, featured_timezones, get_profile


@dataclass
class ClockSnapshot:
    """Calculated view of a configured clock entry."""

    label: str
    timezone: str
    profile: ClockProfile
    is_primary: bool
    local_time: datetime
    utc_offset_long: str
    utc_offset_compact: str
    category: str


def _format_offset(dt: datetime) -> tuple[str, str]:
    offset = dt.utcoffset()
    if offset is None:
        return "UTC", "+0"
    total_minutes = int(offset.total_seconds() // 60)
    hours, minutes = divmod(abs(total_minutes), 60)
    sign = "+" if total_minutes >= 0 else "-"
    long_form = f"UTC{sign}{hours:02d}:{minutes:02d}"
    if total_minutes == 0:
        compact = "+0"
    elif minutes == 0:
        compact = f"{sign}{hours}"
    else:
        compact = f"{sign}{hours}:{minutes:02d}"
    return long_form, compact


def _snapshot_clocks(
    clocks: Dict[str, str],
    *,
    primary: Optional[str],
    category: str,
) -> List[ClockSnapshot]:
    now_utc = datetime.now(zoneinfo.ZoneInfo("UTC"))
    snapshots: List[ClockSnapshot] = []

    for label, timezone_name in sorted(
        clocks.items(),
        key=lambda item: (item[0] != primary, item[0].lower()),
    ):
        try:
            tz = zoneinfo.ZoneInfo(timezone_name)
            local_time = now_utc.astimezone(tz)
        except Exception:
            tz = None
            local_time = now_utc
            timezone_name = timezone_name or "Etc/UTC"

        profile = get_profile(label, timezone_name)
        utc_offset_long, utc_offset_compact = _format_offset(local_time if tz else now_utc)

        snapshots.append(
            ClockSnapshot(
                label=label,
                timezone=timezone_name,
                profile=profile,
                is_primary=label == primary,
                local_time=local_time,
                utc_offset_long=utc_offset_long,
                utc_offset_compact=utc_offset_compact,
                category=category,
            )
        )

    return snapshots


def _featured_snapshots() -> List[ClockSnapshot]:
    featured = {label: tz for label, tz in featured_timezones()}
    return _snapshot_clocks(
        featured,
        primary=None,
        category="reference",
    )


_FRIENDLY_TIMEZONE_NAMES = {
    "America/Chicago": "Central Time",
    "America/Los_Angeles": "Pacific Time",
    "Asia/Dubai": "Gulf Standard Time",
    "Europe/Paris": "Central European Time",
    "Etc/UTC": "Coordinated Universal Time",
}


def _describe_timezone(timezone_name: str, local_time: datetime) -> str:
    abbreviation = local_time.tzname() or "UTC"
    friendly = _FRIENDLY_TIMEZONE_NAMES.get(timezone_name)
    if friendly:
        return f"{friendly} ({abbreviation})"

    if "/" in timezone_name:
        region, city = timezone_name.split("/", 1)
        city = city.replace("_", " ")
        region = region.replace("_", " ").title()
        return f"{abbreviation} · {city}, {region}"

    return f"{abbreviation} · {timezone_name}"


def _format_display_time(dt: datetime) -> str:
    time_part = dt.strftime("%I:%M %p").lstrip("0")
    date_part = f"{dt.month}-{dt.day}-{dt.year}"
    return f"{date_part} {time_part}"


def render_clock_overview(
    clocks: Dict[str, str],
    *,
    primary: Optional[str],
    primary_timezone: Optional[str],
    max_clocks: int,
) -> None:
    """Render the configured clocks in a professional table with context."""

    if not clocks:
        print(status_messages.status("No world clocks configured.", level="warn"))
        return

    snapshots = _snapshot_clocks(
        clocks,
        primary=primary,
        category="configured",
    )
    featured = _featured_snapshots()

    headers = [
        "Display",
        "City",
        "Country",
        "Region",
        "Primary",
        "Time Zone",
        "UTC±",
        "Local Time",
    ]

    rows = []
    configured_labels = set()
    primary_snapshot: Optional[ClockSnapshot] = None
    for snapshot in snapshots:
        configured_labels.add(snapshot.label)
        marker = "*"
        primary_text = "Yes" if snapshot.is_primary else ""
        tz_display = _describe_timezone(snapshot.timezone, snapshot.local_time)
        if snapshot.is_primary:
            primary_snapshot = snapshot
        rows.append(
            [
                marker,
                snapshot.profile.city,
                snapshot.profile.country,
                snapshot.profile.region,
                primary_text,
                tz_display,
                snapshot.utc_offset_compact,
                _format_display_time(snapshot.local_time),
            ]
        )

    if featured:
        for snapshot in featured:
            if snapshot.label in configured_labels:
                continue
            tz_display = _describe_timezone(snapshot.timezone, snapshot.local_time)
            rows.append(
                [
                    "",
                    snapshot.profile.city,
                    snapshot.profile.country,
                    snapshot.profile.region,
                    "",
                    tz_display,
                    snapshot.utc_offset_compact,
                    _format_display_time(snapshot.local_time),
                ]
            )

    table_utils.render_table(headers, rows, accent_first_column=False)
    print()

    print(
        status_messages.status(
            f"Configured {len(clocks)}/{max_clocks} clocks — maintain between 1 and {max_clocks}.",
            level="info",
        )
    )

    print()
    _print_primary_details(primary or None, primary_timezone, primary_snapshot)


def _print_primary_details(
    primary_label: Optional[str],
    primary_timezone: Optional[str],
    snapshot: Optional[ClockSnapshot],
) -> None:
    if not primary_label or not primary_timezone:
        return

    try:
        tz = zoneinfo.ZoneInfo(primary_timezone)
        now_local = datetime.now(tz)
    except Exception:
        tz = zoneinfo.ZoneInfo("UTC")
        now_local = datetime.now(tz)

    offset_long, _ = _format_offset(now_local)
    formatted = _format_display_time(now_local)
    tz_description = _describe_timezone(primary_timezone, now_local)

    if snapshot is not None:
        tz_description = _describe_timezone(snapshot.timezone, snapshot.local_time)
        offset_long = snapshot.utc_offset_long
        formatted = _format_display_time(snapshot.local_time)

    print(
        status_messages.status(
            f"Primary clock — {primary_label} ({tz_description}, {offset_long}) · {formatted}",
            level="info",
        )
    )

__all__ = ["render_clock_overview"]
