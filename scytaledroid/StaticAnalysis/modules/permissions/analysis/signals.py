"""Signal classification for manifest permissions.

Computes capability group strengths from declared permissions.
This centralizes the mapping used by renderers and scoring.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

_GROUP_ORDER = (
    "LOC",  # Location
    "CAM",  # Camera
    "MIC",  # Microphone
    "CNT",  # Contacts/Accounts
    "CAL",  # Calendar
    "PHN",  # Phone
    "SMS",  # SMS
    "STR",  # Storage/Media
    "SENS", # Sensors/Health
    "ACT",  # Activity Recognition
    "BT",   # Bluetooth/Nearby
    "OVR",  # Overlay
    "NOT",  # Notifications
    "ADS",  # Ads/Attribution (vendor)
)


def compute_group_strengths(
    declared: Iterable[tuple[str, str]],
    protection_map: Mapping[str, str | None] | None = None,
) -> tuple[dict[str, int], set[str]]:
    """Return (group_strengths, fw_ds) from manifest declared permissions.

    group_strengths: mapping of group key -> 0/1/2 (none/present/strong)
    fw_ds: set of framework permissions that are dangerous/signature
    """

    protection_map = protection_map or {}
    groups: dict[str, int] = {key: 0 for key in _GROUP_ORDER}
    fw_ds: set[str] = set()

    def _bump(key: str, strong: bool) -> None:
        current = groups.get(key, 0)
        target = 2 if strong else 1
        if target > current:
            groups[key] = target

    for name, _tag in declared:
        is_framework = name.startswith("android.")
        short = name.split(".")[-1].upper()
        prot = (protection_map.get(short) or "").lower()
        is_ds = prot in {"dangerous", "signature"}
        if is_framework and is_ds:
            fw_ds.add(short)

        for key, strong in iter_group_hits(short, is_ds=is_ds):
            _bump(key, strong)
        # Ads/Attribution (vendor is handled by caller)

    return groups, fw_ds


def iter_group_hits(short: str, *, is_ds: bool) -> Iterable[tuple[str, bool]]:
    s = short
    # Location
    if s == "ACCESS_BACKGROUND_LOCATION":
        yield "LOC", True
    if s in {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_MEDIA_LOCATION"}:
        yield "LOC", is_ds
    # Camera / Mic
    if s == "CAMERA":
        yield "CAM", True
    if s in {"RECORD_AUDIO", "CAPTURE_AUDIO_OUTPUT"}:
        yield "MIC", True
    # Contacts/Accounts
    if s in {"READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "MANAGE_ACCOUNTS"}:
        yield "CNT", is_ds
    # Calendar
    if s in {"READ_CALENDAR", "WRITE_CALENDAR"}:
        yield "CAL", is_ds
    # Phone / SMS
    if s in {"READ_CALL_LOG", "CALL_PHONE", "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "ANSWER_PHONE_CALLS"}:
        yield "PHN", is_ds
    if s in {"SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH"}:
        yield "SMS", is_ds
    # Storage/Media
    if "READ_MEDIA_" in s or s in {"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"}:
        yield "STR", is_ds or s == "MANAGE_EXTERNAL_STORAGE"
    # Sensors/Activity
    if s in {"BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "HEALTH_CONNECT"}:
        yield "SENS", is_ds
    if s in {"ACTIVITY_RECOGNITION"}:
        yield "ACT", is_ds
    # Bluetooth/Nearby
    if s in {"BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT", "NEARBY_WIFI_DEVICES"}:
        yield "BT", is_ds
    # Overlay/Notifications
    if s in {"SYSTEM_ALERT_WINDOW", "SYSTEM_OVERLAY_WINDOW"}:
        yield "OVR", True
    if s in {"POST_NOTIFICATIONS", "BIND_NOTIFICATION_LISTENER_SERVICE", "ACCESS_NOTIFICATION_POLICY"}:
        yield "NOT", is_ds


__all__ = ["compute_group_strengths", "iter_group_hits", "_GROUP_ORDER"]