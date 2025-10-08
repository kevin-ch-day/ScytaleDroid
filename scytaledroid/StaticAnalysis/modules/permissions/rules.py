"""Static permission weighting heuristics for report rendering.

These tables centralise the risk weights that drive the report badges. They are
kept separate so the reporting layer can stay lightweight and so unit tests can
stub them easily.
"""

from __future__ import annotations

# The weights loosely follow the Android protection levels and raise the score
# for highly sensitive capabilities. Values are intentionally conservative so
# the renderer can still layer additional context (dangerous/signature/etc.).
SENSITIVITY_WEIGHTS: dict[str, int] = {
    # Telephony / SMS
    "android.permission.READ_PHONE_STATE": 80,
    "android.permission.READ_CALL_LOG": 90,
    "android.permission.WRITE_CALL_LOG": 85,
    "android.permission.PROCESS_OUTGOING_CALLS": 80,
    "android.permission.CALL_PHONE": 70,
    "android.permission.ANSWER_PHONE_CALLS": 70,
    "android.permission.SEND_SMS": 80,
    "android.permission.RECEIVE_SMS": 80,
    "android.permission.READ_SMS": 95,
    "android.permission.RECEIVE_MMS": 75,
    "android.permission.RECEIVE_WAP_PUSH": 75,
    "android.permission.READ_CELL_BROADCASTS": 60,
    # Communications / Contacts
    "android.permission.READ_CONTACTS": 80,
    "android.permission.WRITE_CONTACTS": 75,
    "android.permission.GET_ACCOUNTS": 65,
    "android.permission.MANAGE_ACCOUNTS": 75,
    "android.permission.AUTHENTICATE_ACCOUNTS": 75,
    # Calendar / Tasks
    "android.permission.READ_CALENDAR": 55,
    "android.permission.WRITE_CALENDAR": 55,
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": 55,
    "android.permission.WRITE_EXTERNAL_STORAGE": 60,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 95,
    # Media / Sensors
    "android.permission.CAMERA": 75,
    "android.permission.RECORD_AUDIO": 90,
    "android.permission.CAPTURE_AUDIO_OUTPUT": 95,
    "android.permission.CAPTURE_VIDEO_OUTPUT": 85,
    "android.permission.BODY_SENSORS": 70,
    "android.permission.ACTIVITY_RECOGNITION": 55,
    # Location
    "android.permission.ACCESS_FINE_LOCATION": 90,
    "android.permission.ACCESS_COARSE_LOCATION": 70,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 95,
    # Network / System level
    "android.permission.ACCESS_WIFI_STATE": 35,
    "android.permission.CHANGE_WIFI_STATE": 45,
    "android.permission.CHANGE_NETWORK_STATE": 45,
    "android.permission.ACCESS_NETWORK_STATE": 30,
    "android.permission.CHANGE_CONFIGURATION": 60,
    # Package / Device Admin style capabilities
    "android.permission.REQUEST_INSTALL_PACKAGES": 85,
    "android.permission.REQUEST_DELETE_PACKAGES": 75,
    "android.permission.INSTALL_PACKAGES": 95,
    "android.permission.DELETE_PACKAGES": 90,
    "android.permission.BIND_DEVICE_ADMIN": 95,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 95,
    "android.permission.BIND_VPN_SERVICE": 85,
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 85,
    "android.permission.QUERY_ALL_PACKAGES": 85,
    # Power / Optimisation bypasses
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 70,
    "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND": 65,
    "android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND": 65,
    "android.permission.SCHEDULE_EXACT_ALARM": 70,
    # UI overlays / intrusive capabilities
    "android.permission.SYSTEM_ALERT_WINDOW": 90,
    "android.permission.WRITE_SETTINGS": 90,
    "android.permission.USE_FULL_SCREEN_INTENT": 60,
    # Usage / statistics
    "android.permission.PACKAGE_USAGE_STATS": 80,
    # Notifications / Do-not-disturb
    "android.permission.ACCESS_NOTIFICATION_POLICY": 75,
}

# Permissions that require manual user approval through the "Special app
# access" surfaces in Android. Rendering highlights these separately to draw
# operator attention when they appear alongside more common dangerous
# permissions.
SPECIAL_ACCESS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "android.permission.ACCESS_NOTIFICATION_POLICY",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_VPN_SERVICE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.REQUEST_DELETE_PACKAGES",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SCHEDULE_EXACT_ALARM",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
    }
)

__all__ = ["SENSITIVITY_WEIGHTS", "SPECIAL_ACCESS_PERMISSIONS"]
