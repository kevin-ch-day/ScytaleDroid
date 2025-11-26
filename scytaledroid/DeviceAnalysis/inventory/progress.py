"""CLI progress and preamble rendering for inventory sync."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Dict

from scytaledroid.Utils.DisplayUtils import status_messages, terminal
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import INVENTORY_STALE_SECONDS
from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds


def _format_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0:
        return "--:--"

    total_seconds = int(round(seconds))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _format_progress_line(
    *,
    processed: int,
    total: int,
    elapsed_seconds: float,
    eta_seconds: Optional[float],
    split_processed: int,
) -> str:
    percentage = (processed / total) * 100 if total else 0.0
    eta_text = _format_duration(eta_seconds)
    elapsed_text = _format_duration(elapsed_seconds)
    bar_width = 20
    filled = int((percentage / 100.0) * bar_width)
    filled = max(0, min(bar_width, filled))
    empty = bar_width - filled
    fill_char = "█" if not terminal.use_ascii_ui() else "#"
    empty_char = "░" if not terminal.use_ascii_ui() else "."
    bar = f"{fill_char * filled}{empty_char * empty}"
    message = (
        f"[{bar}] {processed} / {total} ({percentage:.1f}%) "
        f"• Elapsed {elapsed_text}"
    )
    if eta_text:
        message += f" • ETA {eta_text}"
    message += f" • Split APKs: {split_processed}"
    return message


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_length(text: str) -> int:
    return len(_ANSI_ESCAPE_RE.sub("", text))


def make_cli_progress_printer(ui_prefs=None):
    """Return a progress callback that renders a single updating line."""

    last_length = 0

    def _printer(event: Dict[str, object]) -> bool | None:
        nonlocal last_length
        phase = event.get("phase")
        if phase == "progress":
            line = _format_progress_line(
                processed=int(event.get("processed", 0) or 0),
                total=int(event.get("total", 0) or 0),
                elapsed_seconds=float(event.get("elapsed_seconds", 0.0) or 0.0),
                eta_seconds=event.get("eta_seconds"),
                split_processed=int(event.get("split_processed", 0) or 0),
            )
            visible = _visible_length(line)
            padding = " " * max(0, last_length - visible)
            print(f"\r{line}{padding}", end="", flush=True)
            last_length = visible
        elif phase == "complete":
            if last_length:
                print()
        return True

    return _printer


def render_snapshot_block(previous_meta, ui_prefs=None) -> None:
    """Render a stable snapshot info block before sync starts."""
    status_line = "Status   : UNKNOWN"
    age_line = "Age      : unknown"
    pkg_line = "Packages : —"
    threshold_label = f"{INVENTORY_STALE_SECONDS // 3600}h" if INVENTORY_STALE_SECONDS >= 3600 else f"{INVENTORY_STALE_SECONDS // 60}m"
    threshold_line = f"Staleness threshold: {threshold_label}"

    if previous_meta and getattr(previous_meta, "captured_at", None):
        age_seconds = max(
            (datetime.now(timezone.utc) - previous_meta.captured_at).total_seconds(), 0.0
        )
        is_stale = age_seconds >= INVENTORY_STALE_SECONDS
        bullet = "● " if not terminal.use_ascii_ui() else ""
        status_text = "STALE" if is_stale else "FRESH"
        status_line = f"Status   : {bullet}{status_text}"
        age_line = f"Age      : {humanize_seconds(age_seconds)}"
        pkg_line = f"Packages : {getattr(previous_meta, 'package_count', '—')}"

    print("Snapshot before sync")
    print(f"  {status_line}")
    print(f"  {age_line}")
    print(f"  {pkg_line}")
    print(f"  {threshold_line}")


__all__ = ["make_cli_progress_printer", "render_snapshot_block"]
