from __future__ import annotations

from typing import Sequence


def render_declared_permissions(lines, permissions, wrap_lines, output_prefs) -> None:
    lines.append("Permissions (declared)")
    declared = (
        list(permissions["declared"])
        if isinstance(permissions.get("declared"), Sequence)
        else []
    )
    counts = permissions["counts"]
    lines.append(
        f"  Counts: dangerous={counts['dangerous']}  signature={counts['signature']}  custom={counts['custom']}"
    )
    # Compact high-signal preview; full list only when verbose mode is set
    try:
        verbose = output_prefs.get().verbose
    except Exception:
        verbose = False
    if declared:
        # Extract high-signal subset
        high_keys = {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
        }
        top = [name.split(".")[-1] for name in declared if name in high_keys]
        if top:
            top_line = ", ".join(sorted(set(top)))
            lines.append("  High-signal: " + top_line)
        if verbose:
            full = ", ".join(declared)
            lines.extend(wrap_lines("  " + full, indent=0, subsequent_indent=2))
