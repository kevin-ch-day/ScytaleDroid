"""ui_prefs.py - Simple, process-local UI preferences for the CLI.

This module intentionally keeps settings in-memory for the current run.
If persistence is needed later, we can extend it to read/write JSON under
``data/state/ui_prefs.json``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class _UIPrefs:
    clear_on_nav: bool = False  # default off to avoid surprising clears
    max_width: int = 100        # soft cap used by some menus
    compact_mode: bool = False
    use_color: bool = True
    use_unicode: bool = True
    theme_name: str | None = None


_PREFS = _UIPrefs()


def should_clear() -> bool:
    return bool(_PREFS.clear_on_nav)


def set_clear(enabled: bool) -> None:
    _PREFS.clear_on_nav = bool(enabled)


def toggle_clear() -> bool:
    _PREFS.clear_on_nav = not _PREFS.clear_on_nav
    return _PREFS.clear_on_nav


def get_max_width() -> int:
    return int(_PREFS.max_width or 100)


def set_max_width(width: int) -> int:
    try:
        w = int(width)
    except Exception:
        w = 100
    _PREFS.max_width = max(60, min(140, w))
    return _PREFS.max_width


def is_compact() -> bool:
    return bool(_PREFS.compact_mode)


def set_compact(enabled: bool) -> None:
    _PREFS.compact_mode = bool(enabled)


def toggle_compact() -> bool:
    _PREFS.compact_mode = not _PREFS.compact_mode
    return _PREFS.compact_mode


def use_color() -> bool:
    return bool(_PREFS.use_color)


def set_use_color(enabled: bool) -> None:
    _PREFS.use_color = bool(enabled)
    from . import colors

    colors.colors_enabled(force_refresh=True)


def use_unicode() -> bool:
    return bool(_PREFS.use_unicode)


def set_use_unicode(enabled: bool) -> None:
    _PREFS.use_unicode = bool(enabled)
    from .terminal import use_ascii_ui

    use_ascii_ui(force_refresh=True)


def get_theme() -> str:
    from . import colors

    if _PREFS.theme_name:
        return _PREFS.theme_name
    return colors.current_palette_name()


def set_theme(name: str) -> str:
    from . import colors

    _ = colors.set_palette_by_name(name)
    resolved = colors.current_palette_name()
    _PREFS.theme_name = resolved
    return resolved


def reset_theme_auto() -> str:
    from . import colors

    _PREFS.theme_name = None
    colors.reset_palette()
    return colors.current_palette_name()


__all__ = [
    "should_clear",
    "set_clear",
    "toggle_clear",
    "get_max_width",
    "set_max_width",
    "is_compact",
    "set_compact",
    "toggle_compact",
    "use_color",
    "set_use_color",
    "use_unicode",
    "set_use_unicode",
    "get_theme",
    "set_theme",
    "reset_theme_auto",
]
