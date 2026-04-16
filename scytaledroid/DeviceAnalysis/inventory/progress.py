"""CLI progress and preamble rendering for inventory sync."""

from __future__ import annotations

import sys
from datetime import UTC, datetime

from scytaledroid.Utils.DisplayUtils import colors, status_messages, terminal, text_blocks
from scytaledroid.Utils.DisplayUtils.colors import ansi

# Avoid pulling in the entire device_menu stack when running headless (e.g., measure_inventory_latency).
try:
    from scytaledroid.DeviceAnalysis.device_menu.inventory_guard.constants import (
        INVENTORY_STALE_SECONDS,
    )
except Exception:  # pragma: no cover - headless fall-back
    INVENTORY_STALE_SECONDS = 24 * 60 * 60


def _format_duration(seconds: float | None) -> str:
    """Return a compact duration like 8m49s for fast operator scanning."""
    if seconds is None:
        return ""
    if seconds < 0:
        return "--"
    total = int(seconds)
    mins, secs = divmod(total, 60)
    hours, mins = divmod(mins, 60)
    days, hours = divmod(hours, 24)
    if days > 0:
        return f"{days}d{hours:02d}h{mins:02d}m"
    if hours > 0:
        return f"{hours}h{mins:02d}m{secs:02d}s"
    if mins > 0:
        return f"{mins}m{secs:02d}s"
    return f"{secs}s"


def _format_progress_lines(
    *,
    processed: int,
    total: int,
    elapsed_seconds: float,
    eta_seconds: float | None,
    split_processed: int,
    rate_override: float | None = None,
    show_splits: bool = False,
    phase_label: str | None = None,
) -> tuple[str, str]:
    percentage = (processed / total) * 100 if total else 0.0
    # ETA tends to be noisy early. Suppress until we have enough signal.
    eta_text = ""
    if (
        eta_seconds is not None
        and elapsed_seconds >= 60.0
        and processed >= max(10, int(total * 0.15) if total else 10)
    ):
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
    # Rate helps operators see that the run is alive.
    rate = rate_override if rate_override is not None else ((processed / elapsed_seconds) if elapsed_seconds > 0 else 0.0)
    elapsed_text = _format_duration(elapsed_seconds)
    eta_field = eta_text or "--"

    label = (phase_label or "Collecting").strip()
    if colors.colors_enabled():
        palette = colors.get_palette()
        label = colors.apply(label, palette.header, bold=True)

    # Two-line layout: keep the progress bar readable and move timing/rate to line 2.
    line1 = f"{label}  [{bar}] {processed}/{total} ({percentage:.1f}%)"

    line2 = f"elapsed {elapsed_text}  eta {eta_field}  rate {rate:.2f} pkg/s"
    if split_processed and show_splits:
        line2 += f"  splits {split_processed}"
    return line1, line2


def make_cli_progress_printer(ui_prefs=None):
    """Return a progress callback that renders a two-line, updating progress block."""

    stream = getattr(sys, "stdout", None)
    live_redraw = bool(stream and hasattr(stream, "isatty") and stream.isatty())
    current_phase_label: str | None = None
    last_elapsed: float = 0.0
    last_processed: int = 0
    ema_rate: float = 0.0
    split_milestones_seen: set[int] = set()

    def _printer(event: dict[str, object]) -> bool | None:
        nonlocal current_phase_label, last_elapsed, last_processed, ema_rate, split_milestones_seen
        phase = event.get("phase")
        if phase == "start":
            current_phase_label = event.get("phase_label") or "Collecting packages"
            last_processed = 0
            last_elapsed = 0.0
            ema_rate = 0.0
            split_milestones_seen.clear()
            if live_redraw:
                print()  # visual separation after snapshot block
                print()  # reserve line2
                print(ansi.CURSOR_UP_ONE, end="")  # move cursor back to line1
            return True
        if phase == "progress":
            processed = int(event.get("processed", 0) or 0)
            total = int(event.get("total", 0) or 0)
            elapsed = float(event.get("elapsed_seconds", 0.0) or 0.0)
            split_processed = int(event.get("split_processed", 0) or 0)
            delta_elapsed = max(elapsed - last_elapsed, 0.0)
            delta_processed = max(processed - last_processed, 0)
            inst_rate = (delta_processed / delta_elapsed) if delta_elapsed > 0 else 0.0
            if ema_rate <= 0.0:
                ema_rate = inst_rate or ((processed / elapsed) if elapsed > 0 else 0.0)
            elif inst_rate > 0.0:
                # Favor stability over responsiveness so ETA does not jump excessively.
                ema_rate = (0.15 * inst_rate) + (0.85 * ema_rate)
            effective_rate = ema_rate if ema_rate > 0 else ((processed / elapsed) if elapsed > 0 else 0.0)
            eta_smoothed = ((total - processed) / effective_rate) if effective_rate > 0 and total > processed else None
            pct = int((processed / total) * 100) if total > 0 else 0
            show_splits = False
            for mark in (25, 50, 75, 100):
                if pct >= mark and mark not in split_milestones_seen:
                    split_milestones_seen.add(mark)
                    show_splits = True
            last_elapsed = elapsed
            last_processed = processed
            line1, line2 = _format_progress_lines(
                processed=processed,
                total=total,
                elapsed_seconds=elapsed,
                eta_seconds=eta_smoothed,
                split_processed=split_processed,
                rate_override=effective_rate,
                show_splits=show_splits,
                phase_label=current_phase_label,
            )
            if live_redraw:
                # Clear each line before redraw to avoid visual residue/trailing spaces.
                print(
                    f"{ansi.CR}{ansi.CLEAR_LINE}{line1}\n"
                    f"{ansi.CLEAR_LINE}{line2}{ansi.CURSOR_UP_ONE}",
                    end="",
                    flush=True,
                )
            else:
                print(line1)
                print(line2)
        elif phase == "complete":
            if live_redraw:
                # Ensure we end on a clean line below the progress block.
                print(ansi.CR, end="")
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
    mode: str | None = None,
    *,
    serial: str | None = None,
    allow_fallbacks: bool | None = None,
) -> None:
    """Render a stable snapshot info block before sync starts."""
    status_text = "UNKNOWN"
    age_text = "unknown"
    pkg_text = "—"

    if previous_meta and getattr(previous_meta, "captured_at", None):
        age_seconds = max(
            (datetime.now(UTC) - previous_meta.captured_at).total_seconds(), 0.0
        )
        is_stale = age_seconds >= INVENTORY_STALE_SECONDS
        status_text = "STALE" if is_stale else "FRESH"
        age_text = _format_duration(age_seconds)
        snapshot_count = getattr(previous_meta, "package_count", None)
        device_count = None
        if serial:
            try:
                from scytaledroid.DeviceAnalysis.adb import packages as adb_packages

                device_count = len(adb_packages.list_packages(serial))
            except Exception:
                device_count = None
        if snapshot_count is not None and device_count and device_count != snapshot_count:
            status_text = "MISMATCH"
            pkg_text = f"{snapshot_count} (device {device_count})"
        else:
            pkg_text = str(snapshot_count if snapshot_count is not None else "—")

    mode_text = (mode or "baseline").strip()
    device_text = (serial or "unknown").strip()
    prev_id = getattr(previous_meta, "snapshot_id", None) if previous_meta else None

    # Compact header with deterministic field ordering.
    print(text_blocks.headline("Refresh Inventory", width=70))
    title = f"Device: {device_text}  |  mode={mode_text}"
    if prev_id is not None:
        title += f"  |  prev_snapshot={prev_id}"
    if colors.colors_enabled():
        palette = colors.get_palette()
        title = colors.apply(title, palette.header, bold=True)
    print(title)

    meta_line = f"Status: {status_text}  |  last_sync={age_text}  |  packages={pkg_text}"
    print(meta_line)

    if allow_fallbacks is True:
        warn_key = f"{device_text}|{mode_text}"
        if warn_key in _FALLBACK_WARNED_KEYS:
            return
        _FALLBACK_WARNED_KEYS.add(warn_key)
        print(
            status_messages.status(
                "Non-root collection active: some system partition APK metadata and paths are unavailable; harvest scope will be policy-filtered to readable user paths.",
                level="warn",
            )
        )


__all__ = ["make_cli_progress_printer", "render_snapshot_block"]


_FALLBACK_WARNED_KEYS: set[str] = set()
