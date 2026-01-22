"""CLI progress and preamble rendering for inventory sync."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Dict

from scytaledroid.Utils.DisplayUtils import status_messages, terminal

# Avoid pulling in the entire device_menu stack when running headless (e.g., measure_inventory).
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
        return "calculating…"
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
    bar = f"{fill_char * filled}{empty_char * empty}"
    line1 = f"[{bar}] {processed}/{total} ({percentage:.1f}%)"
    if phase_label:
        line1 = f"{phase_label} | {line1}"

    eta_display = "ETA --" if (processed >= total and total > 0) else f"ETA: {eta_text}"
    line2 = f"{eta_display}"
    if split_processed:
        line2 = f"{line2} | splits {split_processed}"

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
            done_line = f"Phase complete. Rendering summary…"
            print(done_line)
        return True

    return _printer


def render_snapshot_block(previous_meta, ui_prefs=None, mode: Optional[str] = None) -> None:
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
        status_text = "STALE" if is_stale else "FRESH"
        status_line = f"Status   : {status_text}"
        age_line = f"Age      : {humanize_seconds(age_seconds)}"
        pkg_line = f"Packages : {getattr(previous_meta, 'package_count', '—')}"

    mode_text = mode or "baseline"

    print("Snapshot before sync")
    print(f"  {status_line}")
    print(f"  {age_line}")
    print(f"  {pkg_line}")
    print(f"  {threshold_line}")
    print(f"  Mode     : {mode_text}")
    print()


__all__ = ["make_cli_progress_printer", "render_snapshot_block"]
