"""Environment detection helpers for palette selection."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path


def _host_looks_like_fedora() -> bool:
    os_release = Path("/etc/os-release")
    try:
        payload = os_release.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        payload = ""
    if "id=fedora" in payload or "id_like=\"fedora\"" in payload or "id_like=fedora" in payload:
        return True

    for key in ("XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"):
        value = str(os.environ.get(key, "")).strip().lower()
        if value.startswith("fedora"):
            return True
    return False


def detect_palette_name(normaliser: Callable[[str], str]) -> str:
    """Return the palette name that best matches the current environment."""

    env = os.environ.get("SCYTALEDROID_UI_THEME") or os.environ.get("SCYTALE_UI_THEME")
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
            return normaliser("fedora-dark" if _host_looks_like_fedora() else "scytale-dark")
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

    if _host_looks_like_fedora():
        return normaliser("fedora-dark")
    return normaliser("scytale-dark")


__all__ = ["detect_palette_name"]
