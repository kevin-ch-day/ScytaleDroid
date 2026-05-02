"""CLI progress and preamble rendering for inventory sync."""

from __future__ import annotations

import sys
from datetime import UTC, datetime

from scytaledroid.DeviceAnalysis.device_analysis_settings import INVENTORY_STALE_SECONDS
from scytaledroid.DeviceAnalysis.inventory.cli_labels import (
    NON_ROOT_POLICY_CARD_LINE,
    PROGRESS_FOOTER_TIP,
    SNAPSHOT_PANEL_HEADLINE,
)
from scytaledroid.Utils.DisplayUtils import colors, status_messages, terminal, text_blocks
from scytaledroid.Utils.DisplayUtils.colors import ansi

# Live redraw uses CR/carriage tricks; Ctrl+C leaves the cursor mid-line unless we tidy up.
_LIVE_INVENTORY_TTY_ACTIVE: bool = False
_LIVE_INVENTORY_ROWS: int = 3


def mark_live_inventory_progress_active(*, rows: int = 3) -> None:
    """Mark stdin/out as owning a CR-based progress block."""

    global _LIVE_INVENTORY_TTY_ACTIVE, _LIVE_INVENTORY_ROWS

    stream = getattr(sys, "stdout", None)
    if stream and getattr(stream, "isatty", lambda: False)():
        _LIVE_INVENTORY_TTY_ACTIVE = True
        _LIVE_INVENTORY_ROWS = max(rows, _LIVE_INVENTORY_ROWS)


def record_live_inventory_row_count(rows: int) -> None:
    """Track tallest progress rendering so Ctrl+C clears enough lines."""

    global _LIVE_INVENTORY_ROWS
    _LIVE_INVENTORY_ROWS = max(_LIVE_INVENTORY_ROWS, rows)


def mark_live_inventory_progress_done() -> None:
    """Call when the CLI progress finishes normally."""

    global _LIVE_INVENTORY_TTY_ACTIVE
    _LIVE_INVENTORY_TTY_ACTIVE = False


def finalize_inventory_live_tty() -> None:
    """Clear progress residue after KeyboardInterrupt (^C merges into CR-based lines otherwise)."""

    global _LIVE_INVENTORY_TTY_ACTIVE
    stream = getattr(sys, "stdout", None)
    if not _LIVE_INVENTORY_TTY_ACTIVE or not (
        stream and getattr(stream, "isatty", lambda: False)()
    ):
        _LIVE_INVENTORY_TTY_ACTIVE = False
        return

    rows = max(3, _LIVE_INVENTORY_ROWS)
    buf = ansi.RESET
    for _ in range(rows):
        buf += f"\r{ansi.CLEAR_LINE}\n"
    try:
        stream.write(buf + "\r")
        stream.flush()
    except Exception:
        pass
    _LIVE_INVENTORY_TTY_ACTIVE = False


def format_inventory_elapsed(seconds: float | None, *, absent: str = "") -> str:
    """Compact duration shared by live progress + summary (aligned rounding).

    Uses ``int(round(seconds))`` so the final summary matches the last progress tick.
    """
    if seconds is None or seconds < 0:
        return absent
    total = max(0, int(round(float(seconds))))
    mins, secs = divmod(total, 60)
    hours, mins = divmod(mins, 60)
    days, hours = divmod(hours, 24)
    if days > 0:
        return f"{days}d{hours:02d}h{mins:02d}m"
    if hours > 0:
        return f"{hours}h {mins:02d}m {secs:02d}s"
    if mins > 0:
        return f"{mins}m {secs:02d}s"
    return f"{secs}s"


def _format_rate(pkg_per_s: float) -> str:
    if pkg_per_s <= 0:
        return "— pkg/s"
    if pkg_per_s >= 100:
        return f"{pkg_per_s:.0f} pkg/s"
    if pkg_per_s >= 10:
        return f"{pkg_per_s:.1f} pkg/s"
    return f"{pkg_per_s:.2f} pkg/s"


def _compact_package_name(value: str | None, *, limit: int = 40) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if len(text) <= limit:
        return text
    head = max(12, limit - 13)
    return f"{text[:head]}...{text[-10:]}"


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
    current_package: str | None = None,
    current_stage: str | None = None,
    path_calls_completed: int | None = None,
    metadata_calls_completed: int | None = None,
    active: bool = False,
) -> tuple[str, str, str | None]:
    percentage = (processed / total) * 100 if total else 0.0
    # ETA tends to be noisy early. Suppress until we have enough signal.
    eta_text = ""
    if (
        eta_seconds is not None
        and elapsed_seconds >= 60.0
        and processed >= max(10, int(total * 0.15) if total else 10)
    ):
        eta_text = format_inventory_elapsed(eta_seconds, absent="")

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
    rate = rate_override if rate_override is not None else ((processed / elapsed_seconds) if elapsed_seconds > 0 else 0.0)
    elapsed_text = format_inventory_elapsed(elapsed_seconds, absent="0s")
    eta_display = eta_text if eta_text else "—"

    label = (phase_label or "Collecting").strip()
    if colors.colors_enabled():
        palette = colors.get_palette()
        label = colors.apply(label, palette.header, bold=True)

    # Two-line layout: keep the progress bar readable and move timing/rate to line 2.
    line1 = f"{label}  [{bar}] {processed}/{total} ({percentage:.1f}%)"

    line2 = (
        f"Elapsed {elapsed_text} · ETA {eta_display} · {_format_rate(rate)}"
    )
    if split_processed and show_splits:
        line2 += f" · split APKs {split_processed}"
    if total > 0 and (path_calls_completed is not None or metadata_calls_completed is not None):
        path_text = path_calls_completed if path_calls_completed is not None else 0
        meta_text = metadata_calls_completed if metadata_calls_completed is not None else 0
        line2 += f" · paths {path_text}/{total} · metadata {meta_text}/{total}"

    line3: str | None = None
    if current_package:
        stage_label = (current_stage or "working").strip()
        verb = "Active" if active else "Last"
        line3 = f"{verb} {stage_label}: {_compact_package_name(current_package)}"
    return line1, line2, line3


def make_cli_progress_printer(ui_prefs=None):
    """Return a progress callback that renders a two-line, updating progress block."""

    stream = getattr(sys, "stdout", None)
    live_redraw = bool(stream and hasattr(stream, "isatty") and stream.isatty())
    current_phase_label: str | None = None
    last_elapsed: float = 0.0
    last_processed: int = 0
    ema_rate: float = 0.0
    split_milestones_seen: set[int] = set()
    rendered_lines = 2

    def _printer(event: dict[str, object]) -> bool | None:
        nonlocal current_phase_label, last_elapsed, last_processed, ema_rate, split_milestones_seen, rendered_lines
        phase = event.get("phase")
        if phase == "start":
            current_phase_label = event.get("phase_label") or "Collecting packages"
            last_processed = 0
            last_elapsed = 0.0
            ema_rate = 0.0
            split_milestones_seen.clear()
            rendered_lines = 3
            if live_redraw:
                mark_live_inventory_progress_active(rows=3)
                print()  # visual separation after snapshot block
                print()  # reserve line2
                print()  # reserve line3
                print(ansi.CURSOR_UP_ONE, end="")
                print(ansi.CURSOR_UP_ONE, end="")  # move cursor back to line1
            else:
                mark_live_inventory_progress_done()
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
            current_package = str(event.get("current_package") or "").strip() or None
            current_stage = str(event.get("current_stage") or "").strip() or None
            path_calls_completed = event.get("path_calls_completed")
            metadata_calls_completed = event.get("metadata_calls_completed")
            active = bool(event.get("active", False))
            show_splits = False
            for mark in (25, 50, 75, 100):
                if pct >= mark and mark not in split_milestones_seen:
                    split_milestones_seen.add(mark)
                    show_splits = True
            last_elapsed = elapsed
            last_processed = processed
            line1, line2, line3 = _format_progress_lines(
                processed=processed,
                total=total,
                elapsed_seconds=elapsed,
                eta_seconds=eta_smoothed,
                split_processed=split_processed,
                rate_override=effective_rate,
                show_splits=show_splits,
                phase_label=current_phase_label,
                current_package=current_package,
                current_stage=current_stage,
                path_calls_completed=int(path_calls_completed) if path_calls_completed is not None else None,
                metadata_calls_completed=int(metadata_calls_completed) if metadata_calls_completed is not None else None,
                active=active,
            )
            lines_to_render = [line1, line2]
            if line3:
                lines_to_render.append(line3)
            rendered_lines = max(rendered_lines, len(lines_to_render))
            if live_redraw:
                record_live_inventory_row_count(rendered_lines)
                padded_lines = list(lines_to_render)
                while len(padded_lines) < rendered_lines:
                    padded_lines.append("")
                # Clear each line before redraw to avoid visual residue/trailing spaces.
                payload = f"{ansi.CR}{ansi.CLEAR_LINE}{padded_lines[0]}"
                for extra_line in padded_lines[1:]:
                    payload += f"\n{ansi.CLEAR_LINE}{extra_line}"
                for _ in range(len(padded_lines) - 1):
                    payload += ansi.CURSOR_UP_ONE
                print(payload, end="", flush=True)
            else:
                for rendered in lines_to_render:
                    print(rendered)
        elif phase == "complete":
            mark_live_inventory_progress_done()
            if live_redraw:
                # Ensure we end on a clean line below the progress block.
                print(ansi.CR, end="")
                for _ in range(rendered_lines):
                    print()
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
    status_text = "none"
    age_text = "never"
    pkg_text = "—"

    if previous_meta and getattr(previous_meta, "captured_at", None):
        age_seconds = max(
            (datetime.now(UTC) - previous_meta.captured_at).total_seconds(), 0.0
        )
        is_stale = age_seconds >= INVENTORY_STALE_SECONDS
        status_text = "STALE" if is_stale else "FRESH"
        age_text = format_inventory_elapsed(age_seconds)
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

    # Compact header — not SECTION_HEADLINE, so we do not repeat the scope menu title.
    print(text_blocks.headline(SNAPSHOT_PANEL_HEADLINE, width=70))
    if colors.colors_enabled():
        palette = colors.get_palette()
        def _style(line: str) -> str:
            return colors.apply(line, palette.header, bold=True)
    else:
        def _style(line: str) -> str:
            return line

    print(_style(f"Device       : {device_text}"))
    if prev_id is not None:
        print(_style(f"Previous snap: {prev_id}"))
    print(_style(f"Inventory    : {status_text}"))
    last_sync_line = age_text if age_text == "never" else f"{age_text} ago"
    print(_style(f"Last sync    : {last_sync_line}"))
    print(_style(f"Packages     : {pkg_text}"))
    print(_style(f"Mode         : {mode_text}"))
    if allow_fallbacks is True:
        print(_style(f"Policy       : {NON_ROOT_POLICY_CARD_LINE}"))
    print(status_messages.status(PROGRESS_FOOTER_TIP, level="info"))


__all__ = [
    "finalize_inventory_live_tty",
    "make_cli_progress_printer",
    "mark_live_inventory_progress_done",
    "render_snapshot_block",
]
