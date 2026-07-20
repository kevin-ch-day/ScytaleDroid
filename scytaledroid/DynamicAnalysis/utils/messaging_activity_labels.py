"""Display labels for dynamic messaging activity tags."""

from __future__ import annotations

_MESSAGING_ACTIVITY_LABELS = {
    "connected_idle": "Connected idle",
    "idle": "Idle",
    "manual_freeform": "Freeform / setup",
    "manual_mixed": "Mixed known activities",
    "mixed": "Mixed known activities",
    "none": "None",
    "text_only": "Text",
    "voice_call": "Voice Call",
    "video_call": "Video Call",
}


def messaging_activity_label(value: object) -> str:
    """Return a stable operator-facing label while preserving raw stored tags elsewhere."""

    raw = str(value or "").strip()
    if not raw:
        return "—"
    normalized = raw.lower()
    if normalized in _MESSAGING_ACTIVITY_LABELS:
        return _MESSAGING_ACTIVITY_LABELS[normalized]
    return raw.replace("_", " ").strip().title() or raw


__all__ = ["messaging_activity_label"]
