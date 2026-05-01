"""Signal configuration and helpers for permission audit."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

SIGNAL_OBSERVATION_CONFIG: Mapping[str, dict[str, object]] = {
    "sms": {
        "severity_band": "WARN",
        "score": 8,
        "rationale": "SMS permissions requested.",
        "permissions": (
            "READ_SMS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "RECEIVE_MMS",
            "RECEIVE_WAP_PUSH",
            "READ_CELL_BROADCASTS",
        ),
    },
    "calls": {
        "severity_band": "WARN",
        "score": 6,
        "rationale": "Call log or phone permissions requested.",
        "permissions": (
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "CALL_PHONE",
            "READ_PHONE_STATE",
            "PROCESS_OUTGOING_CALLS",
            "ANSWER_PHONE_CALLS",
        ),
    },
    "contacts": {
        "severity_band": "WARN",
        "score": 6,
        "rationale": "Contacts permissions requested.",
        "permissions": ("READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"),
    },
    "calendar": {
        "severity_band": "WARN",
        "score": 5,
        "rationale": "Calendar permissions requested.",
        "permissions": ("READ_CALENDAR", "WRITE_CALENDAR"),
    },
    "sensors": {
        "severity_band": "WARN",
        "score": 6,
        "rationale": "Body sensors or health data permissions requested.",
        "permissions": ("BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "HEALTH_CONNECT"),
    },
    "activity_recognition": {
        "severity_band": "WARN",
        "score": 5,
        "rationale": "Activity recognition permission requested.",
        "permissions": ("ACTIVITY_RECOGNITION",),
    },
    "background_location": {
        "severity_band": "WARN",
        "score": 7,
        "rationale": "Background location requested.",
        "permissions": ("ACCESS_BACKGROUND_LOCATION",),
    },
    "storage_broad": {
        "severity_band": "WARN",
        "score": 6,
        "rationale": "Broad external storage access requested.",
        "permissions": ("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"),
    },
    "overlay": {
        "severity_band": "WARN",
        "score": 5,
        "rationale": "System overlay permission requested.",
        "permissions": ("SYSTEM_ALERT_WINDOW",),
    },
    "accessibility_binding": {
        "severity_band": "FAIL",
        "score": 9,
        "rationale": "Accessibility service binding requested.",
        "permissions": ("BIND_ACCESSIBILITY_SERVICE",),
    },
    "query_all_packages": {
        "severity_band": "WARN",
        "score": 5,
        "rationale": "QUERY_ALL_PACKAGES requested.",
        "permissions": ("QUERY_ALL_PACKAGES",),
    },
    "usage_stats": {
        "severity_band": "WARN",
        "score": 5,
        "rationale": "Usage stats access requested.",
        "permissions": ("PACKAGE_USAGE_STATS",),
    },
    "ads_attr": {
        "severity_band": "INFO",
        "score": 2,
        "rationale": "Advertising ID / attribution permission requested.",
        "permissions": ("ACCESS_ADSERVICES_AD_ID", "com.google.android.gms.permission.AD_ID"),
    },
}


def _normalize_perm_token(value: str) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    if token.startswith("android.permission."):
        return token.split(".", maxsplit=2)[-1]
    return token


def match_permissions(declared: Sequence[str], candidates: Sequence[str]) -> list[str]:
    if not declared:
        return []
    normalized = {perm: _normalize_perm_token(perm).upper() for perm in declared}
    candidate_set = {str(candidate).upper() for candidate in candidates}
    matches = [perm for perm, short in normalized.items() if short in candidate_set]
    if "AD_ID" in candidate_set:
        matches.extend(
            perm
            for perm in declared
            if "AD_ID" in perm.upper() and perm not in matches
        )
    return matches


__all__ = ["SIGNAL_OBSERVATION_CONFIG", "match_permissions"]