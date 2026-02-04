"""CLI progress and preamble rendering for inventory sync."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Dict

from scytaledroid.Utils.DisplayUtils import colors, status_messages, terminal, text_blocks

# Avoid pulling in the entire device_menu stack when running headless (e.g., measure_inventory_latency).
try:
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import INVENTORY_STALE_SECONDS
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.utils import humanize_seconds
except Exception:  # pragma: no cover - headless fall-back
    INVENTORY_STALE_SECONDS = 24 * 60 * 60

    def humanize_seconds(seconds: float | int | None) -> str:
        if seconds is None:
            return "unknown"
        total = int(seconds)
        mins, secs = divmod(total, 60)
        hours, mins = divmod(mins, 60)
        days, hours = divmod(hours, 24)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours or parts:
            parts.append(f"{hours}h")
        if mins or parts:
            parts.append(f"{mins:02d}m")
        parts.append(f"{secs:02d}s")
        return " ".join(parts)


def _format_duration(seconds: Optional[float]) -> str:
    """Return a human-friendly duration like 8 mins 49 sec."""
    if seconds is None:
        return ""
    if seconds < 0:
        return "--"
    return humanize_seconds(seconds)


def _format_progress_lines(
    *,
    processed: int,
    total: int,
    elapsed_seconds: float,
    eta_seconds: Optional[float],
    split_processed: int,
    phase_label: Optional[str] = None,
) -> tuple[str, str]:
    percentage = (processed / total) * 100 if total else 0.0
    eta_text = _format_duration(eta_seconds)

    # Scale the bar to the terminal to avoid line wrapping on narrow consoles.
    term_width = terminal.get_terminal_width(default=100)
    bar_width = 24 if term_width >= 120 else 18 if term_width <= 80 else 20

    filled = int((percentage / 100.0) * bar_width)
    filled = max(0, min(bar_width, filled))
    empty = bar_width - filled
    fill_char = "█" if not terminal.use_ascii_ui() else "#"
    empty_char = "░" if not terminal.use_ascii_ui() else "."
    filled_bar = f"{fill_char * filled}"
    empty_bar = f"{empty_char * empty}"
    if colors.colors_enabled():
        palette = colors.get_palette()
        filled_bar = colors.apply(filled_bar, palette.accent)
        empty_bar = colors.apply(empty_bar, palette.muted)
    bar = f"{filled_bar}{empty_bar}"
    line1 = f"[{bar}] {processed}/{total} ({percentage:.1f}%)"
    if phase_label:
        label = phase_label
        if colors.colors_enabled():
            palette = colors.get_palette()
            label = colors.apply(phase_label, palette.header, bold=True)
        line1 = f"{label}  {line1}"

    line2 = ""
    if processed >= total and total > 0:
        line2 = "ETA --"
    elif eta_text:
        line2 = f"ETA: {eta_text}"
    if split_processed:
        line2 = f"{line2} | splits {split_processed}" if line2 else f"splits {split_processed}"

    return line1, line2


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_length(text: str) -> int:
    return len(_ANSI_ESCAPE_RE.sub("", text))


def make_cli_progress_printer(ui_prefs=None):
    """Return a progress callback that renders a two-line, updating progress block."""

    last_line1 = 0
    last_line2 = 0
    current_phase_label: Optional[str] = None
    last_elapsed: float = 0.0

    def _printer(event: Dict[str, object]) -> bool | None:
        nonlocal last_line1, last_line2, current_phase_label, last_elapsed
        phase = event.get("phase")
        if phase == "start":
            current_phase_label = event.get("phase_label") or "Collecting packages"
            print()  # visual separation after snapshot block
            print()  # reserve second line for live updates
            print("\033[F", end="")  # move cursor back to first reserved line
            return True
        if phase == "progress":
            last_elapsed = float(event.get("elapsed_seconds", 0.0) or 0.0)
            line1, line2 = _format_progress_lines(
                processed=int(event.get("processed", 0) or 0),
                total=int(event.get("total", 0) or 0),
                elapsed_seconds=last_elapsed,
                eta_seconds=event.get("eta_seconds"),
                split_processed=int(event.get("split_processed", 0) or 0),
                phase_label=current_phase_label,
            )
            vis1 = _visible_length(line1)
            vis2 = _visible_length(line2)
            pad1 = " " * max(0, last_line1 - vis1)
            pad2 = " " * max(0, last_line2 - vis2)
            print(f"\r{line1}{pad1}\n{line2}{pad2}\033[F", end="", flush=True)
            last_line1, last_line2 = vis1, vis2
        elif phase == "complete":
            # Ensure we end on a clean line below the progress block.
            print("\r", end="")
            print()  # move to line2
            print()  # blank line after progress
            label = event.get("phase_label") or current_phase_label or "Sync"
            done_line = f"{label} complete. Rendering summary…"
            print(status_messages.status(done_line, level="success"))
        return True

    return _printer


def render_snapshot_block(
    previous_meta,
    ui_prefs=None,
    mode: Optional[str] = None,
    *,
    serial: Optional[str] = None,
) -> None:
    """Render a stable snapshot info block before sync starts."""
    status_text = "UNKNOWN"
    age_text = "unknown"
    pkg_text = "—"

    if previous_meta and getattr(previous_meta, "captured_at", None):
        age_seconds = max(
            (datetime.now(timezone.utc) - previous_meta.captured_at).total_seconds(), 0.0
        )
        is_stale = age_seconds >= INVENTORY_STALE_SECONDS
        status_text = "STALE" if is_stale else "FRESH"
        age_text = humanize_seconds(age_seconds)
        snapshot_count = getattr(previous_meta, "package_count", None)
        device_count = None
        if serial:
            try:
                from scytaledroid.DeviceAnalysis import adb_packages

                device_count = len(adb_packages.list_packages(serial))
            except Exception:
                device_count = None
        if snapshot_count is not None and device_count and device_count != snapshot_count:
            status_text = "MISMATCH"
            pkg_text = f"{snapshot_count} (device {device_count})"
        else:
            pkg_text = str(snapshot_count if snapshot_count is not None else "—")

    mode_text = mode or "baseline"
    print(text_blocks.headline("Inventory Sync Status", width=70))
    print(f"Inventory: {status_text}")
    print(f"Last sync {age_text}")
    print(f"Packages: {pkg_text}")
    print(f"Mode: {mode_text}")


__all__ = ["make_cli_progress_printer", "render_snapshot_block"]
