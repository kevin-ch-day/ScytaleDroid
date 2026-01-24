"""Public interface for ScytaleDroid CLI colour utilities."""

from __future__ import annotations

from .ansi import RESET, apply, colors_enabled, highlight, strip, style
from .palette import (
    Palette,
    available_palettes,
    confidence_color,
    current_palette_name,
    detect_palette_name,
    get_palette,
    palette_context,
    progress_color,
    register_palette,
    risk_color,
    reset_palette,
    set_palette,
    set_palette_by_name,
    unregister_palette,
)

__all__ = [
    "Palette",
    "RESET",
    "apply",
    "available_palettes",
    "colors_enabled",
    "confidence_color",
    "current_palette_name",
    "detect_palette_name",
    "get_palette",
    "highlight",
    "palette_context",
    "progress_color",
    "register_palette",
    "risk_color",
    "reset_palette",
    "set_palette",
    "set_palette_by_name",
    "unregister_palette",
    "strip",
    "style",
]
