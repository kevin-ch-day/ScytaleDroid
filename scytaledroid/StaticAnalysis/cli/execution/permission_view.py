"""Output helpers for permission scan flow."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import status_messages

from ...modules.permissions.permission_console_rendering import (
    render_permission_postcard,
)


def render_compact_notice() -> None:
    print(
        status_messages.status(
            "Permission snapshot: compact summary (set SCYTALEDROID_PERM_SNAPSHOT_COMPACT=0 for full).",
            level="info",
        )
    )


def render_permission_profile(
    *,
    package_name: str,
    app_label: str,
    permissions,
    defined,
    sdk,
    index: int,
    total: int,
    compact: bool,
    silent: bool = False,
):
    return render_permission_postcard(
        package_name,
        app_label,
        permissions,
        defined,
        sdk=sdk,
        index=index,
        total=total,
        compact=compact,
        silent=silent,
    )


def render_permission_persisted(counts: dict | None) -> None:
    counts = counts or {}
    total = sum(counts.values()) if isinstance(counts, dict) else 0
    print(
        status_messages.status(
            f"Permission Analysis persisted: total={total} "
            f"(aosp={counts.get('aosp', 0)}, oem={counts.get('oem', 0)}, "
            f"app={counts.get('app_defined', 0)}, unk={counts.get('unknown', 0)})",
            level="info",
        )
    )


def render_permission_persist_failed() -> None:
    print(
        status_messages.status(
            "Persistence failed — see logs for traceback.",
            level="warn",
        )
    )


__all__ = [
    "render_compact_notice",
    "render_permission_profile",
    "render_permission_persisted",
    "render_permission_persist_failed",
]
