"""Regex classifiers for permission names used by scoring and analysis.

Substring checks such as ``"background" in name`` over-count process-control
permissions (START_*_FROM_BACKGROUND, KILL_BACKGROUND_PROCESSES). These
patterns match Privacy/Health Connect capture names only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_BACKGROUND_SENSITIVE_RE = re.compile(
    r"(?:"
    r"(?:^|[._])access_background_location(?:$|[._])|"
    r"(?:^|[._])background_camera(?:$|[._])|"
    r"(?:^|[._])record_background_audio(?:$|[._])|"
    r"(?:^|[._])body_sensors_background(?:$|[._])|"
    r"(?:^|[._])read_health_data_in_background(?:$|[._])|"
    r"android\.permission\.health\.[a-z0-9_.]*in_background"
    r")",
    re.IGNORECASE,
)

_HEALTH_RE = re.compile(
    r"(?:android\.permission\.health\.)|"
    r"(?:^|[._])(?:body_sensors|health_connect)(?:$|[._])",
    re.IGNORECASE,
)

_PROCESS_BACKGROUND_RE = re.compile(
    r"(?:"
    r"start_(?:activities|foreground_services)_from_background|"
    r"kill_background_processes|"
    r"companion_(?:run_in_background|use_data_in_background|"
    r"start_foreground_services_from_background)"
    r")",
    re.IGNORECASE,
)

_CAPTURE_GROUP_KEYS = frozenset(
    {
        "cam",
        "mic",
        "loc",
        "camera",
        "microphone",
        "location",
    }
)
_HEALTH_GROUP_KEYS = frozenset(
    {
        "sens",
        "health",
        "sensors",
        "sensors_activity",
    }
)


def is_background_sensitive_name(name: str | None) -> bool:
    text = str(name or "")
    if not text or _PROCESS_BACKGROUND_RE.search(text):
        return False
    return _BACKGROUND_SENSITIVE_RE.search(text) is not None


def is_health_permission_name(name: str | None) -> bool:
    text = str(name or "")
    return bool(text) and _HEALTH_RE.search(text) is not None


def is_process_background_name(name: str | None) -> bool:
    return bool(name) and _PROCESS_BACKGROUND_RE.search(str(name)) is not None


def capture_group_count(groups: Mapping[str, int] | None) -> int:
    if not groups:
        return 0
    return sum(
        1
        for key, value in groups.items()
        if int(value or 0) >= 1 and str(key).strip().lower() in _CAPTURE_GROUP_KEYS
    )


def health_group_count(groups: Mapping[str, int] | None) -> int:
    if not groups:
        return 0
    return sum(
        1
        for key, value in groups.items()
        if int(value or 0) >= 1 and str(key).strip().lower() in _HEALTH_GROUP_KEYS
    )


__all__ = [
    "capture_group_count",
    "health_group_count",
    "is_background_sensitive_name",
    "is_health_permission_name",
    "is_process_background_name",
]
