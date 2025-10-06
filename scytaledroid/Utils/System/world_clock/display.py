"""world_clock_display.py - Rendering helpers for the world clock dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import zoneinfo

from scytaledroid.Utils.DisplayUtils import colors, status_messages, table_utils

from .profiles import ClockProfile, featured_timezones, get_profile
from .state import ClockReference


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
    utc_offset_minutes: int
    category: str
    dst_status: str
    dst_next_change: Optional[datetime]
    dst_offset_change: Optional[int]


def format_offset(dt: datetime) -> tuple[str, str, int]:
    offset = dt.utcoffset()
    if offset is None:
        return "UTC", "+0", 0
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
    return long_form, compact, total_minutes


def compute_dst_details(
    tz: Optional[zoneinfo.ZoneInfo],
    reference_utc: datetime,
) -> tuple[str, Optional[datetime], Optional[int]]:
    if tz is None:
        return "unknown", None, None

    local_reference = reference_utc.astimezone(tz)
    try:
        dst_delta = tz.dst(local_reference)
    except Exception:  # pragma: no cover - defensive fallback
        return "unknown", None, None

    if dst_delta is None:
        return "unknown", None, None

    offset_now = tz.utcoffset(local_reference) or timedelta(0)
    active = bool(dst_delta and dst_delta.total_seconds())
    status = "daylight" if active else "standard"

    next_change: Optional[datetime] = None
    offset_change: Optional[int] = None
    for hours in range(1, 24 * 366 + 1):
        candidate_utc = reference_utc + timedelta(hours=hours)
        candidate_local = candidate_utc.astimezone(tz)
        candidate_offset = tz.utcoffset(candidate_local) or timedelta(0)
        if candidate_offset != offset_now:
            next_change = candidate_local
            offset_change = int((candidate_offset - offset_now).total_seconds() // 60)
            break

    if next_change is None and not active:
        status = "none"

    return status, next_change, offset_change


def snapshot_clocks(
    clocks: Dict[str, str],
    *,
    primary: Optional[str],
    category: str,
    reference: ClockReference,
) -> List[ClockSnapshot]:
    anchor_utc = reference.utc
    snapshots: List[ClockSnapshot] = []

    for label, timezone_name in sorted(
        clocks.items(),
        key=lambda item: (item[0] != primary, item[0].lower()),
    ):
        try:
            tz = zoneinfo.ZoneInfo(timezone_name)
            local_time = anchor_utc.astimezone(tz)
        except Exception:
            tz = None
            local_time = anchor_utc
            timezone_name = timezone_name or "Etc/UTC"

        profile = get_profile(label, timezone_name)
        (
            utc_offset_long,
            utc_offset_compact,
            utc_offset_minutes,
        ) = format_offset(local_time if tz else anchor_utc)
        dst_status, next_change, offset_change = compute_dst_details(tz, anchor_utc)

        snapshots.append(
            ClockSnapshot(
                label=label,
                timezone=timezone_name,
                profile=profile,
                is_primary=label == primary,
                local_time=local_time,
                utc_offset_long=utc_offset_long,
                utc_offset_compact=utc_offset_compact,
                utc_offset_minutes=utc_offset_minutes,
                category=category,
                dst_status=dst_status,
                dst_next_change=next_change,
                dst_offset_change=offset_change,
            )
        )

    return snapshots


def featured_snapshots(reference: ClockReference) -> List[ClockSnapshot]:
    featured = {label: tz for label, tz in featured_timezones()}
    return snapshot_clocks(
        featured,
        primary=None,
        category="reference",
        reference=reference,
    )


_FRIENDLY_TIMEZONE_NAMES = {
    "America/Chicago": "Central Time",
    "America/Los_Angeles": "Pacific Time",
    "Asia/Dubai": "Gulf Standard Time",
    "Europe/Paris": "Central European Time",
    "Etc/UTC": "Coordinated Universal Time",
}


def describe_timezone(timezone_name: str, local_time: datetime) -> str:
    abbreviation = local_time.tzname() or "UTC"
    friendly = _FRIENDLY_TIMEZONE_NAMES.get(timezone_name)
    if friendly:
        return f"{friendly} — {abbreviation}"

    if "/" in timezone_name:
        region, city = timezone_name.split("/", 1)
        city = city.replace("_", " ")
        region = region.replace("_", " ").title()
        return f"{abbreviation} — {city}, {region}"

    return f"{abbreviation} — {timezone_name}"


def format_dst_status_text(
    status: str,
    next_change: Optional[datetime],
    offset_change: Optional[int],
    *,
    use_color: bool = False,
) -> str:
    status_map = {
        "daylight": "DST active",
        "standard": "Standard",
        "none": "No DST",
        "unknown": "Unknown",
    }
    text = status_map.get(status, status)

    if next_change is not None:
        change_str = next_change.strftime("%b %d %Y %H:%M")
        delta = offset_change or 0
        if delta:
            hours, minutes = divmod(abs(delta), 60)
            change_delta = f"{'+' if delta > 0 else '-'}{hours}h"
            if minutes:
                change_delta += f"{minutes:02d}m"
            text += f" → {change_str} ({change_delta})"
        else:
            text += f" → {change_str}"

    if not use_color:
        return text

    if status == "daylight":
        style = colors.style("badge")
    elif status == "standard":
        style = colors.style("accent")
    elif status == "none":
        style = colors.style("muted")
    else:
        style = colors.style("warning")
    return colors.apply(text, style)


def format_display_time(dt: datetime) -> str:
    time_part = dt.strftime("%I:%M %p").lstrip("0")
    date_part = f"{dt.month}-{dt.day}-{dt.year}"
    return f"{date_part} {time_part}"


def render_clock_overview(
    clocks: Dict[str, str],
    *,
    primary: Optional[str],
    primary_timezone: Optional[str],
    reference: ClockReference,
) -> None:
    """Render the configured clocks in a professional table with context."""

    if not clocks:
        print(status_messages.status("No world clocks configured.", level="warn"))
        return

    snapshots = snapshot_clocks(
        clocks,
        primary=primary,
        category="configured",
        reference=reference,
    )
    featured = featured_snapshots(reference)

    configured_labels = {snapshot.label for snapshot in snapshots}
    combined: List[ClockSnapshot] = list(snapshots)
    combined.extend(snapshot for snapshot in featured if snapshot.label not in configured_labels)

    combined.sort(
        key=lambda snap: (
            snap.utc_offset_minutes,
            0 if snap.category == "configured" and snap.is_primary else 1 if snap.category == "configured" else 2,
            snap.profile.city.lower(),
        )
    )

    headers = [
        "Role",
        "City",
        "Country",
        "Region",
        "Time Zone",
        "UTC±",
        "Local Time",
        "DST",
    ]

    use_color = colors.colors_enabled()

    def _role_cell(snapshot: ClockSnapshot) -> str:
        if snapshot.category == "reference":
            text = "○ Reference"
            style = colors.style("muted") if use_color else ()
        elif snapshot.is_primary:
            text = "★ Primary"
            style = colors.style("badge") if use_color else ()
        else:
            text = "• Configured"
            style = colors.style("accent") if use_color else ()
        return colors.apply(text, style) if use_color else text

    rows: List[List[str]] = []
    primary_snapshot: Optional[ClockSnapshot] = None
    for snapshot in combined:
        if snapshot.is_primary and snapshot.category == "configured":
            primary_snapshot = snapshot
        tz_display = describe_timezone(snapshot.timezone, snapshot.local_time)
        local_time_display = format_display_time(snapshot.local_time)
        if use_color and snapshot.is_primary and snapshot.category == "configured":
            local_time_display = colors.apply(local_time_display, colors.style("badge"))
        rows.append(
            [
                _role_cell(snapshot),
                snapshot.profile.city,
                snapshot.profile.country,
                snapshot.profile.region,
                tz_display,
                snapshot.utc_offset_compact,
                local_time_display,
                format_dst_status_text(
                    snapshot.dst_status,
                    snapshot.dst_next_change,
                    snapshot.dst_offset_change,
                    use_color=use_color,
                ),
            ]
        )

    table_utils.render_table(headers, rows, accent_first_column=False, use_color=use_color)
    print()

    _print_reference_details(reference)
    _print_primary_details(primary or None, primary_timezone, primary_snapshot)
    _print_dst_transitions(snapshots)


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

    offset_long, _, _ = format_offset(now_local)
    formatted = format_display_time(now_local)
    tz_description = describe_timezone(primary_timezone, now_local)

    dst_note = ""
    if snapshot is not None:
        tz_description = describe_timezone(snapshot.timezone, snapshot.local_time)
        offset_long = snapshot.utc_offset_long
        formatted = format_display_time(snapshot.local_time)
        if snapshot.dst_status == "daylight":
            dst_note = " — DST active"
        elif snapshot.dst_status == "standard":
            dst_note = " — Standard time"
        elif snapshot.dst_status == "none":
            dst_note = " — No DST"
        elif snapshot.dst_status == "unknown":
            dst_note = " — DST data unavailable"

    message = (
        f"Primary clock — {primary_label} ({tz_description}, {offset_long}) · {formatted}{dst_note}"
    )
    print(status_messages.status(message, level="info"))


def _print_reference_details(reference: ClockReference) -> None:
    tz_name = reference.timezone or "UTC"
    try:
        tz = zoneinfo.ZoneInfo(tz_name)
    except Exception:  # pragma: no cover - fallback when tz missing
        tz = zoneinfo.ZoneInfo("UTC")
        tz_name = "UTC"

    localized = reference.utc.astimezone(tz)
    offset_long, _, _ = format_offset(localized)
    formatted = format_display_time(localized)
    label = reference.label or "Live (current time)"
    prefix = "Custom reference" if reference.mode == "custom" else "Live reference"

    print(
        status_messages.status(
            f"{prefix} — {label} ({tz_name}, {offset_long}) · {formatted}",
            level="info",
        )
    )


def _print_dst_transitions(snapshots: List[ClockSnapshot]) -> None:
    upcoming = [
        snap
        for snap in snapshots
        if snap.category == "configured" and snap.dst_next_change is not None
    ]

    if upcoming:
        upcoming.sort(key=lambda snap: snap.dst_next_change)
        print(status_messages.status("Upcoming DST transitions:", level="info"))
        for snap in upcoming[:3]:
            change_local = snap.dst_next_change
            change_str = change_local.strftime("%b %d %Y %H:%M")
            delta = snap.dst_offset_change or 0
            if delta:
                hours, minutes = divmod(abs(delta), 60)
                delta_str = f"{'+' if delta > 0 else '-'}{hours}h"
                if minutes:
                    delta_str += f"{minutes:02d}m"
            else:
                delta_str = "0h"
            detail = (
                f"  • {snap.profile.city}, {snap.profile.country}: {change_str} ({delta_str})"
            )
            print(detail)

        remaining = len(upcoming) - 3
        if remaining > 0:
            print(f"  • ... and {remaining} additional transitions")
        return

    no_dst = [
        snap.profile.city
        for snap in snapshots
        if snap.category == "configured" and snap.dst_status in {"none", "unknown"}
    ]
    if no_dst:
        cities = ", ".join(no_dst)
        print(
            status_messages.status(
                f"DST transitions not expected for: {cities}",
                level="info",
            )
        )

__all__ = [
    "ClockSnapshot",
    "compute_dst_details",
    "describe_timezone",
    "featured_snapshots",
    "format_display_time",
    "format_dst_status_text",
    "format_offset",
    "render_clock_overview",
    "snapshot_clocks",
]
