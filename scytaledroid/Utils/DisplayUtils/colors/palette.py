"""Palette registry and state management helpers."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterable, Iterator, MutableMapping

from .environment import detect_palette_name
from .models import Palette
from .presets import DEFAULT_PRESETS, PALETTE_ALIASES

_PALETTE_REGISTRY: MutableMapping[str, Palette] = dict(DEFAULT_PRESETS)
_PALETTE_ALIASES: MutableMapping[str, str] = dict(PALETTE_ALIASES)
_CURRENT_PALETTE_NAME = ""
_CURRENT_PALETTE: Palette
_INITIALISED = False
_DEFAULT_PALETTE_NAME = ""
_DEFAULT_PALETTE: Palette


def available_palettes() -> list[str]:
    """Return the sorted list of registered palette names."""

    return sorted(_PALETTE_REGISTRY)


def register_palette(
    name: str, palette: Palette, *, aliases: Iterable[str] = ()
) -> None:
    """Register a custom palette under ``name`` with optional *aliases*."""

    canonical = name.strip().lower()
    if not canonical:
        raise ValueError("Palette name cannot be empty")

    _PALETTE_REGISTRY[canonical] = palette
    for alias in aliases:
        alias_key = alias.strip().lower()
        if alias_key:
            _PALETTE_ALIASES[alias_key] = canonical

    if _INITIALISED and _CURRENT_PALETTE_NAME == canonical:
        set_palette(palette, name=canonical)


def unregister_palette(name: str) -> None:
    """Remove the palette identified by *name* (and its aliases)."""

    canonical = _normalise_palette_name(name)
    if canonical in DEFAULT_PRESETS:
        raise ValueError("Cannot remove built-in palettes")

    _PALETTE_REGISTRY.pop(canonical, None)
    aliases_to_remove = [alias for alias, target in _PALETTE_ALIASES.items() if target == canonical]
    for alias in aliases_to_remove:
        _PALETTE_ALIASES.pop(alias, None)

    if _INITIALISED and _CURRENT_PALETTE_NAME == canonical:
        reset_palette()


def _normalise_palette_name(name: str) -> str:
    key = name.strip().lower()
    key = _PALETTE_ALIASES.get(key, key)
    if key not in _PALETTE_REGISTRY:
        raise KeyError(
            f"Unknown palette '{name}'. Available: {', '.join(available_palettes())}"
        )
    return key


def _detect_default_palette() -> str:
    return detect_palette_name(_normalise_palette_name)


def _initialise_palette() -> None:
    global _CURRENT_PALETTE_NAME, _CURRENT_PALETTE, _DEFAULT_PALETTE_NAME, _DEFAULT_PALETTE

    name = _detect_default_palette()
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

    name = _detect_default_palette()
    canonical = _normalise_palette_name(name)
    palette = _PALETTE_REGISTRY[canonical]
    global _DEFAULT_PALETTE_NAME, _DEFAULT_PALETTE
    _DEFAULT_PALETTE_NAME = canonical
    _DEFAULT_PALETTE = palette
    set_palette(palette, name=canonical)


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
    "register_palette",
    "unregister_palette",
    "current_palette_name",
    "detect_palette_name",
    "get_palette",
    "palette_context",
    "reset_palette",
    "set_palette",
    "set_palette_by_name",
]

