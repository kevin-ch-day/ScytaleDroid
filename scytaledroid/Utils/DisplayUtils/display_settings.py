"""Helpers to apply UI preferences to rendering defaults."""

from __future__ import annotations

from . import ui_prefs


def default_width(provided: int | None = None) -> int:
    """Return a safe width based on provided value or ui_prefs."""
    if provided is not None:
        return provided
    return ui_prefs.get_max_width()


def apply_menu_defaults(spec_kwargs: dict) -> dict:
    """Inject compact/width defaults into MenuSpec kwargs."""
    kw = dict(spec_kwargs)
    kw.setdefault("compact", ui_prefs.is_compact())
    kw.setdefault("width", ui_prefs.get_max_width())
    return kw


def apply_table_defaults(kwargs: dict) -> dict:
    """Inject compact defaults into table rendering kwargs."""
    kw = dict(kwargs)
    kw.setdefault("compact", ui_prefs.is_compact())
    return kw


def use_unicode() -> bool:
    return ui_prefs.use_unicode()


def use_color() -> bool:
    return ui_prefs.use_color()


__all__ = [
    "default_width",
    "apply_menu_defaults",
    "apply_table_defaults",
    "use_unicode",
    "use_color",
]
