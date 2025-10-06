"""Rendering helpers for the world clock dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

import zoneinfo

from scytaledroid.Utils.DisplayUtils import colors, status_messages, table_utils

from .world_clock_profiles import ClockProfile, featured_timezones, get_profile


@dataclass
class ClockSnapshot:
    """Calculated view of a configured clock entry."""

    label: str
    timezone: str
    profile: ClockProfile
    is_primary: bool
    is_local_reference: bool
    local_time: datetime
    utc_offset: str
    category: str


def _format_offset(dt: datetime) -> str:
    offset = dt.utcoffset()
    if offset is None:
        return "UTC"
    total_minutes = int(offset.total_seconds() // 60)
    hours, minutes = divmod(abs(total_minutes), 60)
    sign = "+" if total_minutes >= 0 else "-"
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def _snapshot_clocks(
    clocks: Dict[str, str],
    *,
    primary: Optional[str],
    local_label: Optional[str],
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
        utc_offset = _format_offset(local_time if tz else now_utc)

        snapshots.append(
            ClockSnapshot(
                label=label,
                timezone=timezone_name,
                profile=profile,
                is_primary=label == primary,
                is_local_reference=label == local_label,
                local_time=local_time,
                utc_offset=utc_offset,
                category=category,
            )
        )

    return snapshots


def _featured_snapshots() -> List[ClockSnapshot]:
    featured = {label: tz for label, tz in featured_timezones()}
    return _snapshot_clocks(
        featured,
        primary=None,
        local_label=None,
        category="reference",
    )


def _format_display_time(dt: datetime) -> str:
    time_part = dt.strftime("%I:%M %p")
    if time_part.startswith("0"):
        time_part = time_part[1:]
    return f"{time_part} {dt.month}-{dt.day}-{dt.year}"


def render_clock_overview(
    clocks: Dict[str, str],
    *,
    primary: Optional[str],
    local_label: Optional[str],
    local_timezone: Optional[str],
    max_clocks: int,
) -> None:
    """Render the configured clocks in a professional table with context."""

    if not clocks:
        print(status_messages.status("No world clocks configured.", level="warn"))
        return

    snapshots = _snapshot_clocks(
        clocks,
        primary=primary,
        local_label=local_label,
        category="configured",
    )
    featured = _featured_snapshots()

    headers = [
        "Display",
        "City",
        "Country",
        "Region",
        "Primary",
        "Local Ref",
        "Timezone",
        "UTC Offset",
        "Local Time",
    ]

    rows = []
    for snapshot in snapshots:
        marker = "★" if snapshot.is_primary else "•"
        primary_text = "Yes" if snapshot.is_primary else ""
        local_text = "Yes" if snapshot.is_local_reference else ""
        rows.append(
            [
                marker,
                snapshot.profile.city,
                snapshot.profile.country,
                snapshot.profile.region,
                primary_text,
                local_text,
                snapshot.timezone,
                snapshot.utc_offset,
                _format_display_time(snapshot.local_time),
            ]
        )

    if featured:
        for snapshot in featured:
            rows.append(
                [
                    "○",
                    snapshot.profile.city,
                    snapshot.profile.country,
                    snapshot.profile.region,
                    "",
                    "",
                    snapshot.timezone,
                    snapshot.utc_offset,
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
    _print_local_reference_details(local_label, local_timezone)


def _print_local_reference_details(
    local_label: Optional[str], local_timezone: Optional[str]
) -> None:
    if not local_timezone:
        return

    try:
        tz = zoneinfo.ZoneInfo(local_timezone)
        now_local = datetime.now(tz)
        offset = _format_offset(now_local)
        formatted = _format_display_time(now_local)
    except Exception:
        formatted = "Unavailable"
        offset = "UTC"

    label_display = local_label or "Local Reference"
    print(
        status_messages.status(
            f"Local reference — {label_display} ({local_timezone}) [{offset}] {formatted}",
            level="info",
        )
    )


def print_featured_snapshots() -> None:
    """Display curated world times for Paris and London."""

    palette = colors.get_palette()
    heading = colors.apply("Paris & London reference clocks", palette.header, bold=True)
    print(heading)

    headers = ["City", "Country", "Region", "Timezone", "UTC Offset", "Local Time"]
    rows = [
        [
            snapshot.profile.city,
            snapshot.profile.country,
            snapshot.profile.region,
            snapshot.timezone,
            snapshot.utc_offset,
            _format_display_time(snapshot.local_time),
        ]
        for snapshot in _featured_snapshots()
    ]

    table_utils.render_table(headers, rows, accent_first_column=False)
    print()


__all__ = ["print_featured_snapshots", "render_clock_overview"]
