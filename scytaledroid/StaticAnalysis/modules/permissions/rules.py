"""Static rule definitions used by the permission profiler."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class PermissionGroupRule:
    """Describes notable permission stacks that warrant highlighting."""

    key: str
    title: str
    members: tuple[str, ...]
    threshold: int = 1


GROUP_RULES: tuple[PermissionGroupRule, ...] = (
    PermissionGroupRule(
        key="location_precise",
        title="Location access",
        members=(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
        ),
    ),
    PermissionGroupRule(
        key="location_background",
        title="Background location",
        members=("android.permission.ACCESS_BACKGROUND_LOCATION",),
    ),
    PermissionGroupRule(
        key="contacts",
        title="Contacts & accounts",
        members=(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
        ),
    ),
    PermissionGroupRule(
        key="sms",
        title="SMS & MMS stack",
        members=(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_WAP_PUSH",
        ),
        threshold=2,
    ),
    PermissionGroupRule(
        key="call_logs",
        title="Call logs & phone state",
        members=(
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.CALL_PHONE",
        ),
        threshold=2,
    ),
    PermissionGroupRule(
        key="microphone",
        title="Microphone recording",
        members=("android.permission.RECORD_AUDIO",),
    ),
    PermissionGroupRule(
        key="camera",
        title="Camera capture",
        members=("android.permission.CAMERA",),
    ),
    PermissionGroupRule(
        key="overlay",
        title="Screen overlay",
        members=("android.permission.SYSTEM_ALERT_WINDOW",),
    ),
    PermissionGroupRule(
        key="accessibility",
        title="Accessibility service binding",
        members=("android.permission.BIND_ACCESSIBILITY_SERVICE",),
    ),
    PermissionGroupRule(
        key="usage_stats",
        title="Usage statistics access",
        members=("android.permission.PACKAGE_USAGE_STATS",),
    ),
    PermissionGroupRule(
        key="install_packages",
        title="Unknown app install flow",
        members=("android.permission.REQUEST_INSTALL_PACKAGES",),
    ),
    PermissionGroupRule(
        key="manage_external_storage",
        title="Full file access",
        members=("android.permission.MANAGE_EXTERNAL_STORAGE",),
    ),
    PermissionGroupRule(
        key="notification_listener",
        title="Notification listener",
        members=(
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.BIND_NOTIFICATION_RANKER_SERVICE",
        ),
    ),
)

SENSITIVITY_WEIGHTS: Mapping[str, int] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 100,
    "android.permission.SYSTEM_ALERT_WINDOW": 95,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 90,
    "android.permission.READ_SMS": 88,
    "android.permission.RECEIVE_SMS": 86,
    "android.permission.SEND_SMS": 84,
    "android.permission.RECEIVE_MMS": 84,
    "android.permission.RECORD_AUDIO": 82,
    "android.permission.CAMERA": 80,
    "android.permission.READ_CONTACTS": 78,
    "android.permission.WRITE_CONTACTS": 76,
    "android.permission.GET_ACCOUNTS": 74,
    "android.permission.ACCESS_FINE_LOCATION": 72,
    "android.permission.ACCESS_COARSE_LOCATION": 70,
    "android.permission.READ_CALL_LOG": 68,
    "android.permission.WRITE_CALL_LOG": 66,
    "android.permission.PROCESS_OUTGOING_CALLS": 64,
    "android.permission.CALL_PHONE": 62,
    "android.permission.READ_PHONE_STATE": 60,
    "android.permission.PACKAGE_USAGE_STATS": 58,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 56,
    "android.permission.REQUEST_INSTALL_PACKAGES": 54,
}

SPECIAL_ACCESS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_NOTIFICATION_RANKER_SERVICE",
        "android.permission.SCHEDULE_EXACT_ALARM",
        "android.permission.USE_FULL_SCREEN_INTENT",
    }
)


__all__ = [
    "PermissionGroupRule",
    "GROUP_RULES",
    "SENSITIVITY_WEIGHTS",
    "SPECIAL_ACCESS_PERMISSIONS",
]
