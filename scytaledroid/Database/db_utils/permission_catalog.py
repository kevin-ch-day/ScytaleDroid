"""Utilities to refresh the Android framework permission catalog."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import status_messages


def refresh_framework_catalog(catalog_path: object | None = None) -> None:
    """Deprecated: AOSP dictionary is now managed by governance imports."""

    print(status_messages.status(
        "Framework permission catalog import is deprecated. "
        "Use the AOSP permission dict governance import instead.",
        level="warn",
    ))
    return


__all__ = ["refresh_framework_catalog"]
