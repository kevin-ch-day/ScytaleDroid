"""ANSI helpers for applying palette-driven styling."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from functools import lru_cache

from .. import ui_prefs
from .models import Palette
from .palette import get_palette

RESET = "\033[0m"
_ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


def _flatten(styles: Iterable[Iterable[str] | str]) -> tuple[str, ...]:
    """Normalise nested style definitions into a tuple of ANSI codes."""

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
    """Return ``True`` if ANSI colour codes should be emitted."""

    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not ui_prefs.use_color():
        return False

    stream = getattr(sys, "stdout", None)
    if stream is None:
        return False

    try:
        return stream.isatty()
    except AttributeError:  # pragma: no cover - extremely defensive
        return False


def colors_enabled(*, force_refresh: bool = False) -> bool:
    """Expose the cached colours-enabled flag with optional refresh."""

    if force_refresh:
        _colors_enabled.cache_clear()
    return _colors_enabled()


def apply(text: str, *styles: Iterable[str] | str, bold: bool = False) -> str:
    """Wrap *text* in ANSI escape sequences derived from *styles*."""

    codes = list(_flatten(styles))
    if bold and "1" not in codes:
        codes.insert(0, "1")
    if not codes or not colors_enabled():
        return text
    return f"\033[{';'.join(codes)}m{text}{RESET}"


def highlight(text: str) -> str:
    """Apply the palette's highlight styling to *text*."""

    palette = get_palette()
    return apply(text, palette.highlight)


def style(*names: str, palette: Palette | None = None) -> tuple[str, ...]:
    """Return ANSI codes for the palette attribute names in *names*."""

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
    """Remove ANSI escape sequences from *text*."""

    return _ANSI_PATTERN.sub("", text)


__all__ = [
    "RESET",
    "apply",
    "colors_enabled",
    "highlight",
    "strip",
    "style",
]
