"""log_alignment.py - Tools for aligning logs with configured world clocks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List

import zoneinfo

from scytaledroid.Utils.DisplayUtils import (
    colors,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)

from .display import (
    ClockSnapshot,
    compute_dst_details,
    describe_timezone,
    featured_snapshots,
    format_display_time,
    format_dst_status_text,
    format_offset,
    snapshot_clocks,
)
from .profiles import get_profile
from .state import ClockReference, WorldClockState, set_reference_custom


@dataclass(frozen=True)
class LogEvent:
    """Container describing a simulated log timestamp."""

    label: str
    timezone_name: str
    local_time: datetime
    utc_time: datetime


_TIMESTAMP_FORMATS: Iterable[str] = (
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %I:%M %p",
    "%Y-%m-%d %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%Y %I:%M:%S %p",
)


def _parse_timestamp(raw: str) -> datetime:
    text = raw.strip()
    if not text:
        raise ValueError("Timestamp cannot be empty.")

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None

    if parsed is None:
        for fmt in _TIMESTAMP_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue

    if parsed is None:
        raise ValueError(f"Unable to parse '{raw}'.")

    return parsed


def _resolve_event_timezone(
    parsed: datetime,
    tz_name: str,
) -> tuple[datetime, datetime]:
    try:
        tz = zoneinfo.ZoneInfo(tz_name)
    except Exception as exc:  # pragma: no cover - defensive path
        raise ValueError(f"Invalid timezone identifier '{tz_name}'.") from exc

    if parsed.tzinfo is None:
        localized = parsed.replace(tzinfo=tz)
    else:
        localized = parsed.astimezone(tz)

    # Handle ambiguous fall-back hours by prompting the user when offsets differ.
    try:
        offset_first = tz.utcoffset(localized)
        offset_second = tz.utcoffset(localized.replace(fold=1))
    except Exception:  # pragma: no cover - fallback when tz library misbehaves
        offset_first = tz.utcoffset(localized)
        offset_second = offset_first

    if offset_first is not None and offset_second is not None and offset_first != offset_second:
        print(
            status_messages.status(
                "The provided time is ambiguous due to a daylight-savings switch.",
                level="warn",
            )
        )
        print("Choose whether the log entry occurred before or after the transition:")
        options = [
            menu_utils.MenuOption("1", "First occurrence", "Earlier (fold=0)"),
            menu_utils.MenuOption("2", "Second occurrence", "Later (fold=1)"),
        ]
        menu_utils.print_menu(options, boxed=False)
        choice = prompt_utils.get_choice(["1", "2"], default="1")
        if choice == "2":
            localized = localized.replace(fold=1)

    utc_time = localized.astimezone(zoneinfo.ZoneInfo("UTC"))
    return localized, utc_time


def _format_delta_minutes(minutes: int) -> str:
    if minutes == 0:
        return "0"
    sign = "+" if minutes > 0 else "-"
    minutes = abs(minutes)
    hours, remainder = divmod(minutes, 60)
    parts: List[str] = []
    if hours:
        parts.append(f"{hours}h")
    if remainder:
        parts.append(f"{remainder}m")
    return f"{sign}{''.join(parts)}"


def _render_alignment_table(
    event: LogEvent,
    state: WorldClockState,
) -> None:
    reference = ClockReference(
        mode="custom",
        label=event.label,
        timezone=event.timezone_name,
        utc=event.utc_time,
    )

    configured = snapshot_clocks(
        state.clocks,
        primary=state.primary,
        category="configured",
        reference=reference,
    )
    featured = featured_snapshots(reference)

    snapshots: List[ClockSnapshot] = list(configured)
    configured_labels = {snap.label for snap in configured}
    snapshots.extend(snap for snap in featured if snap.label not in configured_labels)

    log_profile = get_profile(event.label, event.timezone_name)
    (_, log_offset_compact, log_offset_minutes) = format_offset(event.local_time)
    dst_status, dst_next, dst_delta = compute_dst_details(
        zoneinfo.ZoneInfo(event.timezone_name),
        event.utc_time,
    )

    use_color = colors.colors_enabled()
    headers = [
        "Role",
        "City",
        "Local Time",
        "UTC±",
        "Δ vs log",
        "DST",
    ]

    rows: List[List[str]] = []

    log_row = [
        colors.apply("Log source", colors.style("accent")) if use_color else "Log source",
        log_profile.city,
        f"{format_display_time(event.local_time)} ({describe_timezone(event.timezone_name, event.local_time)})",
        log_offset_compact,
        "0",
        format_dst_status_text(dst_status, dst_next, dst_delta, use_color=use_color),
    ]
    rows.append(log_row)

    for snapshot in snapshots:
        delta = _format_delta_minutes(snapshot.utc_offset_minutes - log_offset_minutes)
        city_time = format_display_time(snapshot.local_time)
        tz_desc = describe_timezone(snapshot.timezone, snapshot.local_time)
        if use_color and snapshot.is_primary and snapshot.category == "configured":
            city_label = colors.apply("Primary", colors.style("badge"))
        elif snapshot.category == "reference":
            city_label = colors.apply("Reference", colors.style("muted")) if use_color else "Reference"
        else:
            city_label = "Configured"

        rows.append(
            [
                city_label,
                snapshot.profile.city,
                f"{city_time} ({tz_desc})",
                snapshot.utc_offset_compact,
                delta,
                format_dst_status_text(
                    snapshot.dst_status,
                    snapshot.dst_next_change,
                    snapshot.dst_offset_change,
                    use_color=use_color,
                ),
            ]
        )

    table_utils.render_table(headers, rows, accent_first_column=False, use_color=use_color)


def derive_reference_from_log(state: WorldClockState) -> None:
    """Simulate a log timestamp and optionally adopt it as the reference snapshot."""

    menu_utils.print_hint(
        "Align the dashboard with a captured log entry or scheduled test event.",
    )

    default_label = state.reference.label if state.reference.mode == "custom" else "Log snapshot"
    label = (
        prompt_utils.prompt_text(
            "Event label",
            default=default_label,
            hint="Short description for this snapshot",
        ).strip()
        or "Log snapshot"
    )

    timestamp_text = prompt_utils.prompt_text(
        "Event timestamp",
        required=True,
        hint="Examples: 2025-10-06 15:30, 10/06/2025 3:30 PM, 2025-10-06T15:30:00",
    )

    try:
        parsed = _parse_timestamp(timestamp_text)
    except ValueError as exc:
        print(status_messages.status(str(exc), level="error"))
        return

    default_timezone = (
        state.reference.timezone
        or state.primary_timezone
        or next(iter(state.clocks.values()), "Etc/UTC")
    )
    tz_name = prompt_utils.prompt_text(
        "Event timezone",
        default=default_timezone,
        required=True,
        hint="Use an IANA identifier such as America/Chicago",
    )

    try:
        localized, utc_time = _resolve_event_timezone(parsed, tz_name)
    except ValueError as exc:
        print(status_messages.status(str(exc), level="error"))
        return

    event = LogEvent(label=label, timezone_name=tz_name, local_time=localized, utc_time=utc_time)
    _render_alignment_table(event, state)

    print()
    print(
        status_messages.status(
            f"Log snapshot anchored to {format_display_time(localized)} ({tz_name}).",
            level="info",
        )
    )

    if prompt_utils.prompt_yes_no("Set this snapshot as the active reference?", default=False):
        set_reference_custom(label, tz_name, localized)
        print(status_messages.status("Reference updated to log snapshot.", level="success"))
    else:
        print(status_messages.status("Reference left unchanged.", level="info"))


__all__ = ["derive_reference_from_log"]
