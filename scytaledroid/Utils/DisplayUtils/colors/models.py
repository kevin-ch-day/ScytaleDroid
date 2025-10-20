"""Core data structures for CLI colour handling."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    banner_primary: Tuple[str, ...] = field(default_factory=tuple)
    banner_secondary: Tuple[str, ...] = field(default_factory=tuple)
    progress: Tuple[str, ...] = field(default_factory=tuple)
    emphasis: Tuple[str, ...] = field(default_factory=tuple)
    severity_critical: Tuple[str, ...] = field(default_factory=tuple)
    severity_high: Tuple[str, ...] = field(default_factory=tuple)
    severity_medium: Tuple[str, ...] = field(default_factory=tuple)
    severity_low: Tuple[str, ...] = field(default_factory=tuple)
    severity_info: Tuple[str, ...] = field(default_factory=tuple)


__all__ = ["Palette"]

