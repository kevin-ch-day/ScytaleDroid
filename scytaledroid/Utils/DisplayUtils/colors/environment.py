"""Environment detection helpers for palette selection."""

from __future__ import annotations

import os
from collections.abc import Callable


def detect_palette_name(normaliser: Callable[[str], str]) -> str:
    """Return the palette name that best matches the current environment."""

    env = os.environ.get("SCYTALE_UI_THEME")
    if env:
        try:
            return normaliser(env)
        except KeyError:
            pass

    if os.environ.get("SCYTALE_UI_HIGH_CONTRAST"):
        return normaliser("high-contrast")

    gtk_theme = os.environ.get("GTK_THEME", "").lower()
    if gtk_theme:
        if "dark" in gtk_theme:
            return normaliser("fedora-dark")
        if "light" in gtk_theme:
            return normaliser("fedora-light")

    colorfgbg = os.environ.get("COLORFGBG", "")
    if colorfgbg:
        try:
            bg = int(colorfgbg.split(";")[-1])
            if bg >= 7:
                return normaliser("fedora-light")
        except ValueError:
            pass

    return normaliser("fedora-dark")


__all__ = ["detect_palette_name"]

