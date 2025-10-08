"""Minimal helpers for printing permission data directly to the console."""

from __future__ import annotations

from androguard.core.apk import APK

# A small curated set of dangerous permissions for quick counting.
_DANGEROUS_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}


def collect_permissions(apk_path: str) -> tuple[list[str], list[tuple[str, str | None]]]:
    """Return declared and custom permissions for the supplied APK."""

    apk = APK(apk_path)
    declared = sorted(set(apk.get_permissions() or ()))

    defined: list[tuple[str, str | None]] = []
    try:
        for entry in apk.get_declared_permissions() or ():
            name = entry.get("name") or entry.get("android:name")
            protection = entry.get("protectionLevel") or entry.get("android:protectionLevel")
            if name:
                defined.append((name, protection))
    except Exception:
        # Some APKs may have unexpected structures; ignore parsing issues.
        pass

    return declared, defined


def print_permission_report(
    *,
    package_name: str,
    artifact_label: str,
    declared: list[str],
    defined: list[tuple[str, str | None]],
) -> None:
    """Pretty-print permission information for a single APK artifact."""

    print(f"Permission Analysis — {package_name}")
    if artifact_label:
        print(f"Artifact: {artifact_label}")
    print("-" * 40)

    if declared:
        print("Declared (uses-permission*):")
        for permission in declared:
            print(f"  {permission}")
    else:
        print("Declared (uses-permission*): none")

    dangerous_count = sum(1 for permission in declared if permission in _DANGEROUS_PERMISSIONS)
    total_count = len(declared)
    other_count = total_count - dangerous_count
    print(f"Counts: total={total_count} dangerous={dangerous_count} other={other_count}")

    if defined:
        print("Custom permissions declared:")
        for name, protection in defined:
            label = protection or "-"
            print(f"  {name} (protection={label})")

    print()
