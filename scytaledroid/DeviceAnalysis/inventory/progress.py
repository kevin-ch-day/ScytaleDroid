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
    """Return a compact duration like 1h 12m, 3m 05s, 45s."""
    if seconds is None:
        return "calculating…"
    if seconds < 0:
        return "--"
    return humanize_seconds(seconds)


def _format_progress_line(
    *,
    processed: int,
    total: int,
    elapsed_seconds: float,
    eta_seconds: Optional[float],
    split_processed: int,
    phase_label: Optional[str] = None,
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
    message = f"[{bar}] {processed} / {total} ({percentage:.1f}%)"
    message += f" • Elapsed {elapsed_text}"
    if processed >= total and total > 0:
        message += " • ETA --:--"
    elif eta_text and eta_text not in ("--", "calculating…"):
        message += f" • ETA {eta_text}"
    elif eta_text == "calculating…":
        message += " • ETA calculating…"
    message += f" • Split APKs: {split_processed}"
    if phase_label:
        return f"{phase_label}: {message}"
    return message


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_length(text: str) -> int:
    return len(_ANSI_ESCAPE_RE.sub("", text))


def make_cli_progress_printer(ui_prefs=None):
    """Return a progress callback that renders a single updating line."""

    last_length = 0
    current_phase_label: Optional[str] = None
    last_elapsed: float = 0.0

    def _printer(event: Dict[str, object]) -> bool | None:
        nonlocal last_length, current_phase_label, last_elapsed
        phase = event.get("phase")
        if phase == "start":
            current_phase_label = event.get("phase_label") or "Collecting packages"
            print()  # visual separation after snapshot block
            return True
        if phase == "progress":
            last_elapsed = float(event.get("elapsed_seconds", 0.0) or 0.0)
            line = _format_progress_line(
                processed=int(event.get("processed", 0) or 0),
                total=int(event.get("total", 0) or 0),
                elapsed_seconds=last_elapsed,
                eta_seconds=event.get("eta_seconds"),
                split_processed=int(event.get("split_processed", 0) or 0),
                phase_label=current_phase_label,
            )
            visible = _visible_length(line)
            padding = " " * max(0, last_length - visible)
            print(f"\r{line}{padding}", end="", flush=True)
            last_length = visible
        elif phase == "complete":
            if last_length:
                print()
            label = event.get("phase_label") or current_phase_label or "Sync"
            done_line = f'Phase complete. Rendering summary…'
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
