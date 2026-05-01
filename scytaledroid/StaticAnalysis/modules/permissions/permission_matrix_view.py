"""Focused renderer for the cross-app permission matrix."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime

from scytaledroid.Utils.DisplayUtils import colors, text_blocks
from scytaledroid.Utils.DisplayUtils.terminal import get_terminal_width

_MATRIX_ROWS = [
    ("Location", ["ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]),
    ("Camera & Microphone", ["CAMERA", "RECORD_AUDIO"]),
    ("Overlay & Notifications", ["SYSTEM_ALERT_WINDOW", "POST_NOTIFICATIONS"]),
    ("Contacts & Accounts", ["READ_CONTACTS", "GET_ACCOUNTS"]),
    ("Phone & SMS", ["READ_CALL_LOG", "READ_PHONE_STATE", "SEND_SMS"]),
    ("Storage & Media", ["READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "ACCESS_MEDIA_LOCATION"]),
    ("Bluetooth & Nearby", ["BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT"]),
    ("Ads / Attribution", ["ACCESS_ADSERVICES_AD_ID", "com.google.android.gms.permission.AD_ID"]),
]


def _label_for_profile(profile: Mapping[str, object]) -> str:
    for key in ("display_name", "label", "package"):
        value = str(profile.get(key) or "").strip()
        if value:
            return value
    return "APP"


def _full_view_sort_key(profile: Mapping[str, object]) -> tuple[str, str]:
    return (_label_for_profile(profile).lower(), str(profile.get("package") or "").lower())


def _truncated_view_sort_key(profile: Mapping[str, object]) -> tuple[float, str, str]:
    try:
        risk = float(profile.get("risk", 0.0) or 0.0)
    except (TypeError, ValueError):
        risk = 0.0
    return (-risk, _label_for_profile(profile).lower(), str(profile.get("package") or "").lower())


def _select_profiles(profiles: Sequence[Mapping[str, object]], show: int) -> list[Mapping[str, object]]:
    if len(profiles) <= show:
        return sorted(profiles, key=_full_view_sort_key)
    return sorted(profiles, key=_truncated_view_sort_key)[:show]


def _alias_seed(label: str) -> str:
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", label) if part]
    if len(parts) >= 2:
        token = "".join(part[0] for part in parts[:4]).upper()
        return token[:4] or "APP"

    capitals = "".join(ch for ch in label if ch.isupper())
    if len(capitals) >= 2:
        return capitals[:4]

    compact = "".join(ch for ch in label.upper() if ch.isalnum())
    if len(compact) <= 4:
        return compact or "APP"

    consonants = compact[:1] + "".join(ch for ch in compact[1:] if ch not in "AEIOU")
    return (consonants or compact)[:4]


def _unique_aliases(labels: Sequence[str]) -> list[str]:
    used: dict[str, int] = {}
    aliases: list[str] = []
    for label in labels:
        base = _alias_seed(label)
        count = used.get(base, 0)
        alias = base
        if count:
            suffix = str(count + 1)
            alias = (base[: max(1, 4 - len(suffix))] + suffix)[:4]
            while alias in used:
                count += 1
                suffix = str(count + 1)
                alias = (base[: max(1, 4 - len(suffix))] + suffix)[:4]
        used[base] = count + 1
        used[alias] = 1
        aliases.append(alias)
    return aliases


def _format_snapshot(snapshot_at: datetime | str | None) -> str:
    if isinstance(snapshot_at, datetime):
        try:
            local = snapshot_at.astimezone()
        except Exception:
            local = snapshot_at
        try:
            return local.strftime("%Y-%m-%d %-I:%M %p")
        except Exception:
            return local.strftime("%Y-%m-%d %I:%M %p")
    if isinstance(snapshot_at, str) and snapshot_at.strip():
        return snapshot_at.strip()
    return "Unavailable"


def _pad_center(value: str, width: int) -> str:
    visible = text_blocks.visible_width(value)
    if visible >= width:
        return value
    total = width - visible
    left = total // 2
    right = total - left
    return (" " * left) + value + (" " * right)


def _needs_compact_headers(first_col: int, labels: Sequence[str], *, padding: int = 2) -> bool:
    if len(labels) > 8:
        return True
    app_col = max(5, *(text_blocks.visible_width(label) for label in labels))
    total = first_col + (len(labels) * app_col) + (padding * len(labels))
    return total > get_terminal_width()


def render_permission_matrix(
    profiles: Sequence[Mapping[str, object]],
    *,
    scope_label: str,
    show: int = 4,
    snapshot_at: datetime | str | None = None,
) -> None:
    if not profiles:
        return

    top = _select_profiles(profiles, max(1, show))
    full_labels = [_label_for_profile(profile) for profile in top]
    header_labels = full_labels[:]

    row_titles = [group for group, _ in _MATRIX_ROWS]
    row_permissions = [f"  {perm}" for _, perms in _MATRIX_ROWS for perm in perms]
    first_col = max(
        text_blocks.visible_width("Permission"),
        *(text_blocks.visible_width(title) for title in row_titles),
        *(text_blocks.visible_width(title) for title in row_permissions),
    )

    use_compact = _needs_compact_headers(first_col, full_labels)
    if use_compact:
        header_labels = _unique_aliases(full_labels)

    print("\nApplication Permission Matrix")
    print("High-signal matrix (governance-mapped)")
    print(f"Scope: {scope_label}")
    print(f"Snapshot: {_format_snapshot(snapshot_at)}")
    if len(profiles) <= show:
        print(f"View: Apps 1–{len(top)}/{len(profiles)}")
    else:
        print(f"View: Top 1–{len(top)}/{len(profiles)} by permission risk")
    print()

    headers = ["Permission"] + header_labels
    app_col = max(5, *(text_blocks.visible_width(label) for label in header_labels))
    widths = [first_col] + [app_col for _ in header_labels]
    pad = "  "

    header_cells = [header.ljust(widths[idx]) for idx, header in enumerate(headers)]
    print(pad.join(header_cells))
    print(pad.join("-" * width for width in widths))

    palette = colors.get_palette() if colors.colors_enabled() else None

    for group_title, perms in _MATRIX_ROWS:
        print(group_title.ljust(widths[0]))
        for perm in perms:
            row = [f"  {perm}"]
            for item in top:
                fw_ds = {key.upper() for key in item.get("fw_ds", set())}
                vendor = set(item.get("vendor_names", set()))
                if perm.startswith("com."):
                    mark = "*" if perm in vendor else "-"
                else:
                    mark = "X" if perm.upper() in fw_ds else "-"
                if palette:
                    if mark == "X":
                        cell = colors.apply(mark, palette.accent, bold=True)
                    elif mark == "*":
                        cell = colors.apply(mark, palette.warning, bold=True)
                    else:
                        cell = colors.apply(mark, palette.muted)
                else:
                    cell = mark
                row.append(cell)
            cells = []
            for idx, cell in enumerate(row):
                text = str(cell)
                if idx == 0:
                    cells.append(text.ljust(widths[idx]))
                else:
                    cells.append(_pad_center(text, widths[idx]))
            print(pad.join(cells))

    if use_compact:
        print("\nApp key:")
        per_line = 4
        for start in range(0, len(header_labels), per_line):
            chunk = [
                f"{header_labels[idx]}={full_labels[idx]}"
                for idx in range(start, min(start + per_line, len(header_labels)))
            ]
            print("  " + "  ".join(chunk))

    print("\nLegend:")
    print("X = framework (dangerous/signature)")
    print("* = oem/custom/ads")
    print("- = not requested")


__all__ = ["render_permission_matrix"]
