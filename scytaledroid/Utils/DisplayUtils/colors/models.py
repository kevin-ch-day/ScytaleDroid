"""Core data structures for CLI colour handling."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Palette:
    """ANSI colour palette tuned for text-based user interfaces."""

    text: tuple[str, ...]
    info: tuple[str, ...]
    success: tuple[str, ...]
    warning: tuple[str, ...]
    error: tuple[str, ...]
    accent: tuple[str, ...]
    muted: tuple[str, ...]
    header: tuple[str, ...]
    divider: tuple[str, ...]
    option_key: tuple[str, ...]
    option_default: tuple[str, ...]
    option_text: tuple[str, ...]
    hint: tuple[str, ...]
    highlight: tuple[str, ...]
    badge: tuple[str, ...]
    disabled: tuple[str, ...]
    prompt: tuple[str, ...]
    error_panel_border: tuple[str, ...]
    error_panel_title: tuple[str, ...]
    error_panel_message: tuple[str, ...]
    error_panel_hint: tuple[str, ...]
    info_panel_border: tuple[str, ...]
    info_panel_title: tuple[str, ...]
    info_panel_message: tuple[str, ...]
    info_panel_hint: tuple[str, ...]
    warning_panel_border: tuple[str, ...]
    warning_panel_title: tuple[str, ...]
    warning_panel_message: tuple[str, ...]
    warning_panel_hint: tuple[str, ...]
    success_panel_border: tuple[str, ...]
    success_panel_title: tuple[str, ...]
    success_panel_message: tuple[str, ...]
    success_panel_hint: tuple[str, ...]
    banner_primary: tuple[str, ...] = field(default_factory=tuple)
    banner_secondary: tuple[str, ...] = field(default_factory=tuple)
    progress: tuple[str, ...] = field(default_factory=tuple)
    emphasis: tuple[str, ...] = field(default_factory=tuple)
    severity_critical: tuple[str, ...] = field(default_factory=tuple)
    severity_high: tuple[str, ...] = field(default_factory=tuple)
    severity_medium: tuple[str, ...] = field(default_factory=tuple)
    severity_low: tuple[str, ...] = field(default_factory=tuple)
    severity_info: tuple[str, ...] = field(default_factory=tuple)


__all__ = ["Palette"]
