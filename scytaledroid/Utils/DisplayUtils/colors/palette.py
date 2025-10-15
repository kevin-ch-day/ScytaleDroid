"""Palette registry and state management helpers."""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Tuple


@dataclass(frozen=True)
class Palette:
    """ANSI colour palette tuned for text-based user interfaces."""

    text: Tuple[str, ...]
    info: Tuple[str, ...]
    success: Tuple[str, ...]
    warning: Tuple[str, ...]
    error: Tuple[str, ...]
    accent: Tuple[str, ...]
    muted: Tuple[str, ...]
    header: Tuple[str, ...]
    divider: Tuple[str, ...]
    option_key: Tuple[str, ...]
    option_default: Tuple[str, ...]
    option_text: Tuple[str, ...]
    hint: Tuple[str, ...]
    highlight: Tuple[str, ...]
    badge: Tuple[str, ...]
    disabled: Tuple[str, ...]
    prompt: Tuple[str, ...]
    error_panel_border: Tuple[str, ...]
    error_panel_title: Tuple[str, ...]
    error_panel_message: Tuple[str, ...]
    error_panel_hint: Tuple[str, ...]
    info_panel_border: Tuple[str, ...]
    info_panel_title: Tuple[str, ...]
    info_panel_message: Tuple[str, ...]
    info_panel_hint: Tuple[str, ...]
    warning_panel_border: Tuple[str, ...]
    warning_panel_title: Tuple[str, ...]
    warning_panel_message: Tuple[str, ...]
    warning_panel_hint: Tuple[str, ...]
    success_panel_border: Tuple[str, ...]
    success_panel_title: Tuple[str, ...]
    success_panel_message: Tuple[str, ...]
    success_panel_hint: Tuple[str, ...]


_PALETTE_REGISTRY: dict[str, Palette] = {
    "fedora-dark": Palette(
        text=("38;5;252",),
        info=("38;5;74",),
        success=("38;5;71",),
        warning=("38;5;221",),
        error=("38;5;203",),
        accent=("38;5;117",),
        muted=("38;5;244",),
        header=("1", "38;5;111"),
        divider=("38;5;238",),
        option_key=("1", "38;5;39"),
        option_default=("1", "38;5;214"),
        option_text=("38;5;251",),
        hint=("38;5;151",),
        highlight=("1", "48;5;24", "38;5;195"),
        badge=("1", "38;5;81"),
        disabled=("38;5;240",),
        prompt=("38;5;110",),
        error_panel_border=("1", "38;5;203"),
        error_panel_title=("1", "38;5;210"),
        error_panel_message=("38;5;252",),
        error_panel_hint=("38;5;111",),
        info_panel_border=("1", "38;5;74"),
        info_panel_title=("1", "38;5;116"),
        info_panel_message=("38;5;252",),
        info_panel_hint=("38;5;109",),
        warning_panel_border=("1", "38;5;221"),
        warning_panel_title=("1", "38;5;223"),
        warning_panel_message=("38;5;252",),
        warning_panel_hint=("38;5;220"),
        success_panel_border=("1", "38;5;78"),
        success_panel_title=("1", "38;5;115"),
        success_panel_message=("38;5;252",),
        success_panel_hint=("38;5;114",),
    ),
    "fedora-light": Palette(
        text=("38;5;236",),
        info=("38;5;24",),
        success=("38;5;28",),
        warning=("38;5;166",),
        error=("38;5;124",),
        accent=("38;5;18",),
        muted=("38;5;244",),
        header=("1", "38;5;24"),
        divider=("38;5;250",),
        option_key=("1", "38;5;25"),
        option_default=("1", "38;5;130"),
        option_text=("38;5;236",),
        hint=("38;5;243",),
        highlight=("1", "48;5;186", "38;5;17"),
        badge=("1", "38;5;24"),
        disabled=("38;5;245",),
        prompt=("38;5;24",),
        error_panel_border=("1", "38;5;124"),
        error_panel_title=("1", "38;5;160"),
        error_panel_message=("38;5;236",),
        error_panel_hint=("38;5;95",),
        info_panel_border=("1", "38;5;25"),
        info_panel_title=("1", "38;5;31"),
        info_panel_message=("38;5;236",),
        info_panel_hint=("38;5;66",),
        warning_panel_border=("1", "38;5;166"),
        warning_panel_title=("1", "38;5;172"),
        warning_panel_message=("38;5;236",),
        warning_panel_hint=("38;5;172"),
        success_panel_border=("1", "38;5;28"),
        success_panel_title=("1", "38;5;34"),
        success_panel_message=("38;5;236",),
        success_panel_hint=("38;5;65"),
    ),
    "high-contrast": Palette(
        text=("1", "38;5;15"),
        info=("1", "38;5;12"),
        success=("1", "38;5;10"),
        warning=("1", "38;5;11"),
        error=("1", "38;5;9"),
        accent=("1", "38;5;14"),
        muted=("38;5;7",),
        header=("1", "38;5;15", "48;5;0"),
        divider=("1", "38;5;15"),
        option_key=("1", "38;5;15", "48;5;4"),
        option_default=("1", "38;5;0", "48;5;11"),
        option_text=("1", "38;5;15"),
        hint=("1", "38;5;12"),
        highlight=("1", "48;5;0", "38;5;11"),
        badge=("1", "38;5;11", "48;5;0"),
        disabled=("1", "38;5;8"),
        prompt=("1", "38;5;14"),
        error_panel_border=("1", "38;5;9"),
        error_panel_title=("1", "38;5;15", "48;5;9"),
        error_panel_message=("1", "38;5;15"),
        error_panel_hint=("1", "38;5;11"),
        info_panel_border=("1", "38;5;12"),
        info_panel_title=("1", "38;5;15", "48;5;12"),
        info_panel_message=("1", "38;5;15"),
        info_panel_hint=("1", "38;5;14"),
        warning_panel_border=("1", "38;5;11"),
        warning_panel_title=("1", "38;5;0", "48;5;11"),
        warning_panel_message=("1", "38;5;15"),
        warning_panel_hint=("1", "38;5;11"),
        success_panel_border=("1", "38;5;10"),
        success_panel_title=("1", "38;5;15", "48;5;10"),
        success_panel_message=("1", "38;5;15"),
        success_panel_hint=("1", "38;5;14"),
    ),
}

_PALETTE_ALIASES = {
    "default": "fedora-dark",
    "dark": "fedora-dark",
    "fedora": "fedora-dark",
    "light": "fedora-light",
    "hc": "high-contrast",
    "high_contrast": "high-contrast",
}

_CURRENT_PALETTE_NAME = ""
_CURRENT_PALETTE: Palette
_INITIALISED = False
_DEFAULT_PALETTE_NAME: str
_DEFAULT_PALETTE: Palette


def available_palettes() -> list[str]:
    """Return the sorted list of built-in palette names."""

    return sorted(_PALETTE_REGISTRY)


def _normalise_palette_name(name: str) -> str:
    key = name.strip().lower()
    key = _PALETTE_ALIASES.get(key, key)
    if key not in _PALETTE_REGISTRY:
        raise KeyError(
            f"Unknown palette '{name}'. Available: {', '.join(available_palettes())}"
        )
    return key


def detect_palette_name() -> str:
    """Return the palette name that best matches the current environment."""

    env = os.environ.get("SCYTALE_UI_THEME")
    if env:
        try:
            return _normalise_palette_name(env)
        except KeyError:
            pass

    if os.environ.get("SCYTALE_UI_HIGH_CONTRAST"):
        return "high-contrast"

    gtk_theme = os.environ.get("GTK_THEME", "").lower()
    if gtk_theme:
        if "dark" in gtk_theme:
            return "fedora-dark"
        if "light" in gtk_theme:
            return "fedora-light"

    colorfgbg = os.environ.get("COLORFGBG", "")
    if colorfgbg:
        try:
            bg = int(colorfgbg.split(";")[-1])
            if bg >= 7:
                return "fedora-light"
        except ValueError:
            pass

    return "fedora-dark"


def _initialise_palette() -> None:
    global _CURRENT_PALETTE_NAME, _CURRENT_PALETTE, _DEFAULT_PALETTE_NAME, _DEFAULT_PALETTE
    name = detect_palette_name()
    palette = _PALETTE_REGISTRY[name]
    _DEFAULT_PALETTE_NAME = name
    _DEFAULT_PALETTE = palette
    _CURRENT_PALETTE_NAME = name
    _CURRENT_PALETTE = palette


def _ensure_initialised() -> None:
    global _INITIALISED
    if not _INITIALISED:
        _initialise_palette()
        _INITIALISED = True


def set_palette(palette: Palette, *, name: str | None = None) -> None:
    """Override the active palette (primarily for tests or custom themes)."""

    _ensure_initialised()
    global _CURRENT_PALETTE, _CURRENT_PALETTE_NAME
    _CURRENT_PALETTE = palette
    _CURRENT_PALETTE_NAME = name or "custom"


def set_palette_by_name(name: str) -> Palette:
    """Switch to one of the registered palettes by *name*."""

    canonical = _normalise_palette_name(name)
    palette = _PALETTE_REGISTRY[canonical]
    set_palette(palette, name=canonical)
    return palette


def get_palette() -> Palette:
    """Return the active palette instance."""

    _ensure_initialised()
    return _CURRENT_PALETTE


def current_palette_name() -> str:
    """Return the identifier of the currently active palette."""

    _ensure_initialised()
    return _CURRENT_PALETTE_NAME


def reset_palette() -> None:
    """Restore the default palette, re-evaluating environment hints."""

    name = detect_palette_name()
    palette = _PALETTE_REGISTRY[_normalise_palette_name(name)]
    global _DEFAULT_PALETTE_NAME, _DEFAULT_PALETTE
    _DEFAULT_PALETTE_NAME = name
    _DEFAULT_PALETTE = palette
    set_palette(palette, name=name)


@contextmanager
def palette_context(palette: Palette) -> Iterator[Palette]:
    """Temporarily apply *palette* within the context manager."""

    _ensure_initialised()
    previous = get_palette()
    previous_name = current_palette_name()
    set_palette(palette)
    try:
        yield palette
    finally:
        set_palette(previous, name=previous_name)


__all__ = [
    "Palette",
    "available_palettes",
    "current_palette_name",
    "detect_palette_name",
    "get_palette",
    "palette_context",
    "reset_palette",
    "set_palette",
    "set_palette_by_name",
]
