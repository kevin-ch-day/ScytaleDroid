"""Core data structures for CLI colour handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


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


__all__ = ["Palette"]

