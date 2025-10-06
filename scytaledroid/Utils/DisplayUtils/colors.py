"""colors.py - Terminal color palette helpers for CLI rendering.

The colour utilities in this module are intentionally lightweight so they can
be shared across all CLI surfaces.  Recent UX polishing highlighted a couple of
recurring needs while working on the DisplayUtils package:

* Temporarily swapping palettes when rendering nested widgets (e.g. tables in
  popovers) without permanently mutating global state.
* Constructing style tuples from palette attribute names in a safe, discoverable
  way rather than hard-coding numeric ANSI sequences throughout the codebase.
* Stripping ANSI escape codes when measuring widths for alignment.

This revision keeps the original surface area intact while layering in helpers
to address those use cases.  The new tools make it easier for menu renderers to
compose styles cleanly and for table helpers to colourise headers without
breaking alignment when colours are disabled.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Iterator, Tuple
import os
import re
import sys

RESET = "\033[0m"


@dataclass(frozen=True)
class Palette:
    """ANSI color palette tuned for dark terminal themes."""

    text: Tuple[str, ...] = ("38;5;252",)
    info: Tuple[str, ...] = ("38;5;81",)
    success: Tuple[str, ...] = ("38;5;78",)
    warning: Tuple[str, ...] = ("38;5;215",)
    error: Tuple[str, ...] = ("38;5;203",)
    accent: Tuple[str, ...] = ("38;5;117",)
    muted: Tuple[str, ...] = ("38;5;243",)
    header: Tuple[str, ...] = ("1", "38;5;153")
    divider: Tuple[str, ...] = ("38;5;238",)
    option_key: Tuple[str, ...] = ("1", "38;5;110")
    option_default: Tuple[str, ...] = ("1", "38;5;214")
    option_text: Tuple[str, ...] = ("38;5;249",)
    hint: Tuple[str, ...] = ("38;5;150",)
    highlight: Tuple[str, ...] = ("1", "48;5;236", "38;5;195")
    badge: Tuple[str, ...] = ("1", "38;5;45")
    disabled: Tuple[str, ...] = ("38;5;239",)
    prompt: Tuple[str, ...] = ("38;5;110",)
    error_panel_border: Tuple[str, ...] = ("38;5;203",)
    error_panel_title: Tuple[str, ...] = ("1", "38;5;210")
    error_panel_message: Tuple[str, ...] = ("38;5;252",)
    error_panel_hint: Tuple[str, ...] = ("38;5;114",)
    info_panel_border: Tuple[str, ...] = ("38;5;33",)
    info_panel_title: Tuple[str, ...] = ("1", "38;5;111")
    info_panel_message: Tuple[str, ...] = ("38;5;252",)
    info_panel_hint: Tuple[str, ...] = ("38;5;115",)
    warning_panel_border: Tuple[str, ...] = ("38;5;214",)
    warning_panel_title: Tuple[str, ...] = ("1", "38;5;220")
    warning_panel_message: Tuple[str, ...] = ("38;5;252",)
    warning_panel_hint: Tuple[str, ...] = ("38;5;221",)
    success_panel_border: Tuple[str, ...] = ("38;5;78",)
    success_panel_title: Tuple[str, ...] = ("1", "38;5;120")
    success_panel_message: Tuple[str, ...] = ("38;5;252",)
    success_panel_hint: Tuple[str, ...] = ("38;5;150",)


_DEFAULT_PALETTE = Palette()
_current_palette = _DEFAULT_PALETTE
_ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


def set_palette(palette: Palette) -> None:
    """Override the active palette (primarily for tests or theming)."""

    global _current_palette
    _current_palette = palette


def get_palette() -> Palette:
    """Return the active palette instance."""

    return _current_palette


def reset_palette() -> None:
    """Restore the default palette."""

    set_palette(_DEFAULT_PALETTE)


@contextmanager
def palette_context(palette: Palette) -> Iterator[Palette]:
    """Temporarily apply *palette* within the context manager.

    This is primarily useful for nested rendering helpers that need to tweak
    colours without permanently altering the global palette.  The previous
    palette is restored even if an exception is raised.
    """

    previous = get_palette()
    set_palette(palette)
    try:
        yield palette
    finally:
        set_palette(previous)


def _flatten(styles: Iterable[Iterable[str] | str]) -> Tuple[str, ...]:
    parts: list[str] = []
    for style in styles:
        if isinstance(style, (list, tuple, set)):
            for code in style:
                if code:
                    parts.append(str(code))
        elif style:
            parts.append(str(style))
    return tuple(parts)


@lru_cache(maxsize=1)
def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = getattr(sys, "stdout", None)
    if stream is None:
        return False
    try:
        return stream.isatty()
    except AttributeError:
        return False


def apply(text: str, *styles: Iterable[str] | str, bold: bool = False) -> str:
    """Wrap *text* with ANSI codes derived from the provided *styles*."""

    codes = list(_flatten(styles))
    if bold and "1" not in codes:
        codes.insert(0, "1")
    if not codes or not colors_enabled():
        return text
    return f"\033[{';'.join(codes)}m{text}{RESET}"


def highlight(text: str) -> str:
    """Convenience wrapper for the palette's highlight style."""

    palette = get_palette()
    return apply(text, palette.highlight)


def style(*names: str, palette: Palette | None = None) -> Tuple[str, ...]:
    """Return a tuple of ANSI codes for the requested palette attribute names."""

    palette = palette or get_palette()
    codes: list[str] = []
    for name in names:
        try:
            value = getattr(palette, name)
        except AttributeError as exc:  # pragma: no cover - defensive path
            raise AttributeError(f"Unknown palette attribute: {name}") from exc
        codes.extend(value)
    return tuple(codes)


def strip(text: str) -> str:
    """Remove ANSI escape codes from *text* for layout measurements."""

    return _ANSI_PATTERN.sub("", text)


def colors_enabled(*, force_refresh: bool = False) -> bool:
    """Return ``True`` when colours should be emitted for the active stream."""

    if force_refresh:
        _colors_enabled.cache_clear()
    return _colors_enabled()


__all__ = [
    "Palette",
    "RESET",
    "apply",
    "colors_enabled",
    "get_palette",
    "highlight",
    "palette_context",
    "reset_palette",
    "set_palette",
    "strip",
    "style",
]
