"""Minimal helpers for printing manifest permissions directly to the console."""

from __future__ import annotations

from xml.etree import ElementTree as ET
from typing import Dict, List, Sequence, Tuple, Mapping, Optional
import os

from scytaledroid.StaticAnalysis._androguard import APK
from .analysis.capability_signal_classifier import compute_group_strengths
from .analysis.risk_scoring_engine import (
    permission_risk_score_detail,
    permission_risk_grade,
)
from .audit import PermissionAuditAccumulator

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _extract_declared_permissions(apk: APK) -> List[Tuple[str, str]]:
    """Return manifest declared permissions with their element type."""

    try:
        axml = apk.get_android_manifest_axml()
        if axml is None:
            raise ValueError("missing manifest")
        xml_data = axml.get_xml()
        root = ET.fromstring(xml_data)
    except Exception:
        names = sorted(set(apk.get_permissions() or []))
        return [(name, "uses-permission") for name in names]

    declared: List[Tuple[str, str]] = []
    for element in root.iter():
        tag = element.tag.split('}')[-1]
        if tag not in ("uses-permission", "uses-permission-sdk-23"):
            continue
        name = element.get(f"{_ANDROID_NS}name") or element.get("name")
        if name:
            declared.append((name, tag))

    seen = set()
    ordered: List[Tuple[str, str]] = []
    for item in declared:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    return ordered


def collect_permissions_and_sdk(
    apk_path: str,
) -> Tuple[List[Tuple[str, str]], List[Dict[str, str | None]], Dict[str, str | None]]:
    """Collect declared permissions, custom definitions and SDK info."""

    apk = APK(apk_path)

    try:
        declared = _extract_declared_permissions(apk)
    except Exception:
        declared = []

    defined: List[Dict[str, str | None]] = []
    try:
        for entry in apk.get_declared_permissions() or ():
            name = entry.get("name") or entry.get("android:name")
            protection = entry.get("protectionLevel") or entry.get("android:protectionLevel")
            if name:
                defined.append({"name": name, "protection": protection})
    except Exception:
        pass

    try:
        min_sdk = apk.get_min_sdk_version()
    except Exception:
        min_sdk = None
    try:
        target_sdk = apk.get_target_sdk_version()
    except Exception:
        target_sdk = None

    return declared, defined, {"min": min_sdk, "target": target_sdk}


def _format_permission(name: str, element_type: str) -> str:
    if element_type == "uses-permission-sdk-23":
        return f"{name} (uses-permission-sdk-23)"
    return name


def _fetch_protections(names: Sequence[str]) -> Mapping[str, Optional[str]]:
    """Best-effort DB lookup of framework protection levels for given names.

    Returns a mapping of perm_name -> protection or None. On any error, returns
    an empty mapping.
    """
    try:  # optional DB dependency
        from scytaledroid.Database.db_func.permissions.detected_permissions import (
            framework_protection_map,
        )

        return framework_protection_map(names)
    except Exception:
        return {}


def print_permissions_block(
    package_name: str,
    artifact_label: str,
    declared: Sequence[Tuple[str, str]],
    defined: Sequence[Dict[str, str | None]],
    sdk: Dict[str, str | None],
) -> None:
    """Print a narrow permission summary directly to stdout."""

    print(f"Permission Analysis — {package_name}")
    print(f"Artifact: {artifact_label}")
    min_sdk = sdk.get("min") or "-"
    target_sdk = sdk.get("target") or "-"
    print(f"SDKs: min={min_sdk}  target={target_sdk}")
    print("-" * 40)

    # Deduplicate declared names (ignore sdk-23 suffix for risk lookup)
    unique_declared: List[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for name, element_type in declared:
        key = (name, element_type)
        if key not in seen:
            seen.add(key)
            unique_declared.append((name, element_type))

    # Protective annotations from framework table when available
    # Build short, uppercase keys for framework permissions
    shorts_only = [n.split(".")[-1].upper() for n, _ in unique_declared if n.startswith("android.")]
    protection_map = _fetch_protections(shorts_only)

    android_perms: List[str] = []
    custom_perms: List[str] = []
    risk_counts: Dict[str, int] = {"dangerous": 0, "signature": 0, "normal": 0, "other": 0}
    for name, element_type in unique_declared:
        if name.startswith("android."):
            # Framework: show short, uppercase (strip android.permission.)
            short_key = name.split(".")[-1].upper()
            prot = protection_map.get(short_key)
            suffix = " (uses-permission-sdk-23)" if element_type == "uses-permission-sdk-23" else ""
            if prot:
                tag = f" [{prot}]"
                risk_counts[prot] = risk_counts.get(prot, 0) + 1
            else:
                tag = ""
                risk_counts["other"] = risk_counts.get("other", 0) + 1
            android_perms.append(f"{short_key}{suffix}{tag}")
        else:
            # Vendor/custom: keep fully-qualified name, include sdk-23 note when present
            formatted = _format_permission(name, element_type)
            custom_perms.append(formatted)

    if android_perms:
        print(f"Framework permissions ({len(android_perms)}):")
        for permission in android_perms:
            print(f"  {permission}")

    if custom_perms:
        print(f"Custom/vendor permissions ({len(custom_perms)}):")
        for permission in custom_perms:
            print(f"  {permission}")

    if defined:
        print("\nCustom permissions declared:")
        for entry in defined:
            name = entry.get("name")
            protection = entry.get("protection") or "-"
            if name:
                print(f"  {name}  (protection={protection})")

    total_declared = len(unique_declared)
    print(
        "\nCounts: total_declared="
        f"{total_declared}  android={len(android_perms)}  custom={len(custom_perms)}  "
        f"custom_defined={len(defined)}"
    )
    # Risk breakdown (android only)
    if shorts_only:
        summary = ", ".join(
            f"{k}={v}" for k, v in (
                ("dangerous", risk_counts.get("dangerous", 0)),
                ("signature", risk_counts.get("signature", 0)),
                ("normal", risk_counts.get("normal", 0)),
                ("other", risk_counts.get("other", 0)),
            )
        )
        print(f"Risk breakdown: {summary}")


# ------------------------------
# Permission-first renderers
# ------------------------------

_GROUP_ORDER = (
    "LOC",  # Location
    "CAM",  # Camera
    "MIC",  # Microphone
    "CNT",  # Contacts/Accounts
    "PHN",  # Phone
    "SMS",  # SMS
    "STR",  # Storage/Media
    "BT",   # Bluetooth/Nearby
    "OVR",  # Overlay
    "NOT",  # Notifications
    "ADS",  # Ads/Attribution (vendor)
)


def _classify_permissions(
    declared: Sequence[Tuple[str, str]],
    protection_map: Mapping[str, Optional[str]],
) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int], set[str], set[str]]:
    """Return counts per class and group signals.

    Returns (risk_counts, group_strength, vendor_counts)
    - risk_counts: counts of framework protections (dangerous/signature/normal/other)
    - group_strength: 0/1/2 intensity for each group key
    - vendor_counts: count of vendor permissions overall and by group
    """

    risk_counts: Dict[str, int] = {"dangerous": 0, "signature": 0, "normal": 0, "other": 0}
    group_strength, fw_ds = compute_group_strengths(declared, protection_map)
    vendor_counts: Dict[str, int] = {"ADS": 0}
    vendor_names: set[str] = set()

    for name, _tag in declared:
        is_framework = name.startswith("android.")
        short = name.split(".")[-1].upper()
        prot = protection_map.get(short)
        if is_framework:
            if prot in {"dangerous", "signature", "normal"}:
                risk_counts[prot] = risk_counts.get(prot, 0) + 1
            else:
                risk_counts["other"] = risk_counts.get("other", 0) + 1
        else:
            # Vendor/custom
            if "AD_ID" in short or "ADVERTISING" in short or "INSTALL_REFERRER" in short:
                vendor_counts["ADS"] = vendor_counts.get("ADS", 0) + 1
            vendor_names.add(name)

    return risk_counts, group_strength, vendor_counts, fw_ds, vendor_names


def _normalize_permission_key(name: str) -> str:
    if name.startswith("android."):
        return name.split(".")[-1].upper()
    return name


def _collect_declared_tokens(
    declared_sources: Mapping[str, Sequence[Tuple[str, str]]],
) -> List[str]:
    tokens: set[str] = set()
    for perms in declared_sources.values():
        for perm_name, _ in perms:
            tokens.add(_normalize_permission_key(str(perm_name)))
    return sorted(tokens)


def _build_declared_origins(
    declared_sources: Mapping[str, Sequence[Tuple[str, str]]],
    fw_ds: Sequence[str],
    vendor_names: Sequence[str],
) -> Dict[str, str]:
    origins: Dict[str, str] = {}
    fw_set = {key.upper() for key in fw_ds}
    vendor_set = set(vendor_names)
    for artifact_label, perms in declared_sources.items():
        origin = "base" if artifact_label == "base" else f"split:{artifact_label}"
        for perm_name, _ in perms:
            key = _normalize_permission_key(str(perm_name))
            upper_key = key.upper()
            if upper_key in fw_set and upper_key not in origins:
                origins[upper_key] = origin
            if perm_name in vendor_set and perm_name not in origins:
                origins[perm_name] = origin
    return origins


def _risk_bar(score: float, width: int = 8) -> str:
    filled = int(round((score / 10.0) * width))
    blocks = "▓" * max(0, min(width, filled))
    empty = "░" * max(0, width - len(blocks))
    return blocks + empty


def _footprint_bar(group_strength: Mapping[str, int]) -> str:
    parts: List[str] = []
    for key in _GROUP_ORDER:
        val = group_strength.get(key, 0)
        if val >= 2:
            cell = "▓▓"
        elif val == 1:
            cell = "▓░"
        else:
            cell = "░░"
        parts.append(f"{key} {cell}")
    return " | ".join(parts)


def _footprint_multiline(groups: Mapping[str, int]) -> List[str]:
    """Return a multi-line footprint with short descriptors per capability."""
    descriptors = {
        "LOC": "location (precise/bg)",
        "CAM": "camera",
        "MIC": "microphone",
        "CNT": "contacts/accounts",
        "PHN": "calls/phone state",
        "SMS": "sms",
        "STR": "media/storage",
        "BT": "nearby/bluetooth",
        "OVR": "overlay",
        "NOT": "notifications",
        "ADS": "ads/attribution",
    }
    label_map = {
        "LOC": "Location",
        "CAM": "Camera",
        "MIC": "Microphone",
        "CNT": "Contacts",
        "PHN": "Phone",
        "SMS": "SMS",
        "STR": "Storage",
        "BT": "Bluetooth",
        "OVR": "Overlay",
        "NOT": "Notifications",
        "ADS": "Ads",
    }
    bar_width = 4
    from scytaledroid.Utils.DisplayUtils import table_utils
    rows: List[List[str]] = []
    for key in _GROUP_ORDER:
        val = groups.get(key, 0)
        if val >= 2:
            bar = "▓" * bar_width
        elif val == 1:
            bar = "▓" * (bar_width // 2) + "░" * (bar_width - bar_width // 2)
        else:
            bar = "░" * bar_width
        name = label_map.get(key, key)
        desc = descriptors.get(key, key)
        rows.append([name, bar])
    # Print as a tiny table for alignment
    print("Footprint:")
    table_utils.render_table(["Capability", "Level"], rows)
    return []


def _high_signal_tags(groups: Mapping[str, int]) -> List[str]:
    tags: List[str] = []
    mapping = {
        "LOC": "location",
        "CAM": "camera",
        "MIC": "microphone",
        "CNT": "contacts",
        "PHN": "phone",
        "SMS": "sms",
        "STR": "storage",
        "BT": "bluetooth",
        "OVR": "overlay",
        "NOT": "notifications",
    }
    for key, label in mapping.items():
        if groups.get(key, 0) >= 2:
            tags.append(label)
    return tags[:5]


def _persona(groups: Mapping[str, int]) -> str:
    if groups.get("OVR", 0) >= 1 and groups.get("NOT", 0) >= 1:
        return "Overlay Notifier"
    if groups.get("CAM", 0) >= 1 and groups.get("MIC", 0) >= 1 and groups.get("CNT", 0) >= 1:
        return "Broad Access Communicator"
    if groups.get("STR", 0) >= 1 and groups.get("NOT", 0) >= 1 and groups.get("ADS", 0) >= 1:
        return "Ad-Heavy Media"
    return "General"


def _group_trigger_debug(
    declared: Sequence[Tuple[str, str]],
    protection_map: Mapping[str, Optional[str]],
) -> Dict[str, Dict[str, List[str]]]:
    """Return group -> {strong: [...], weak: [...]} for debugging footprint.

    Mirrors the mapping rules in analysis/signals.py to show which permissions
    contributed to each capability and with what strength.
    """
    out: Dict[str, Dict[str, List[str]]] = {k: {"strong": [], "weak": []} for k in _GROUP_ORDER}

    def _tag(key: str, short: str, strong: bool) -> None:
        bucket = "strong" if strong else "weak"
        if short not in out[key][bucket]:
            out[key][bucket].append(short)

    for name, _tagtype in declared:
        is_framework = name.startswith("android.")
        short = name.split(".")[-1].upper()
        prot = (protection_map.get(short) or "").lower()
        is_ds = prot in {"dangerous", "signature"}

        s = short
        # Location
        if s == "ACCESS_BACKGROUND_LOCATION":
            _tag("LOC", s, True)
        if s in {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_MEDIA_LOCATION"}:
            _tag("LOC", s, is_ds)
        # Camera / Mic
        if s == "CAMERA":
            _tag("CAM", s, True)
        if s in {"RECORD_AUDIO", "CAPTURE_AUDIO_OUTPUT"}:
            _tag("MIC", s, True)
        # Contacts/Accounts
        if s in {"READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "MANAGE_ACCOUNTS"}:
            _tag("CNT", s, is_ds)
        # Phone / SMS
        if s in {"READ_CALL_LOG", "CALL_PHONE", "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "ANSWER_PHONE_CALLS"}:
            _tag("PHN", s, is_ds)
        if s in {"SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH"}:
            _tag("SMS", s, is_ds)
        # Storage/Media
        if "READ_MEDIA_" in s or s in {"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"}:
            _tag("STR", s, is_ds or s == "MANAGE_EXTERNAL_STORAGE")
        # Bluetooth/Nearby
        if s in {"BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT", "NEARBY_WIFI_DEVICES"}:
            _tag("BT", s, is_ds)
        # Overlay/Notifications
        if s in {"SYSTEM_ALERT_WINDOW", "SYSTEM_OVERLAY_WINDOW"}:
            _tag("OVR", s, True)
        if s in {"POST_NOTIFICATIONS", "BIND_NOTIFICATION_LISTENER_SERVICE", "ACCESS_NOTIFICATION_POLICY"}:
            _tag("NOT", s, is_ds)

    return out


def render_permission_postcard(
    package_name: str,
    app_label: str,
    declared: Sequence[Tuple[str, str]],
    defined: Sequence[Dict[str, str | None]],
    *,
    index: int,
    total: int,
) -> Dict[str, object]:
    """Analyze and print a compact permission-first postcard.

    Returns a profile dict for summary usage.
    """
    # Framework protections lookup
    shorts_only = [n.split(".")[-1].upper() for n, _ in declared if n.startswith("android.")]
    protection_map = _fetch_protections(shorts_only)
    risk_counts, groups, vendor, fw_ds, vendor_names = _classify_permissions(declared, protection_map)

    d = risk_counts.get("dangerous", 0)
    s = risk_counts.get("signature", 0)
    v = vendor.get("ADS", 0)
    detail = dict(
        permission_risk_score_detail(
            dangerous=d,
            signature=s,
            vendor=v,
            groups=groups,
        )
    )
    score = float(detail.get("score_3dp", detail.get("score_capped", 0.0)))
    score = round(score, 3)
    detail["score_3dp"] = score
    detail.setdefault("score_capped", float(detail.get("score_capped", score)))
    detail.setdefault("score_raw", float(detail.get("score_raw", score)))
    bar = _risk_bar(score)
    high_tags = _high_signal_tags(groups)
    footprint = _footprint_bar(groups)
    persona = _persona(groups)

    grade = permission_risk_grade(score)
    detail["grade"] = grade
    detail.setdefault("combo_total", 0.0)
    detail.setdefault("combos_fired", [])
    detail.setdefault("surprise_total", 0.0)
    detail.setdefault("surprises", [])
    detail.setdefault("legacy_total", 0.0)
    detail.setdefault("legacy_penalties", [])
    detail.setdefault("vendor_modifier", 0.0)
    detail.setdefault("modernization_credit", 0.0)
    detail.setdefault("hard_gates_triggered", [])
    detail.setdefault("expected_mask_hit", [])
    detail.setdefault("unexpected_signals", [])
    detail.setdefault("grade_basis", "fixed_thresholds")
    print(f"[{index}/{total}] {app_label}  {bar}  Risk {score:.3f}   (D:{d}  S:{s}  V:{v})  Grade {grade}")
    if high_tags:
        tags = "".join(f"[{t}]" for t in high_tags)
        print(f"High-signal:  {tags}")
    _footprint_multiline(groups)
    # Optional debug block to explain footprint composition
    if os.environ.get("SCY_PERM_DEBUG") == "1":
        debug = _group_trigger_debug(declared, protection_map)
        print("Debug — group triggers (strong/weak):")
        for key in _GROUP_ORDER:
            strong = ", ".join(debug[key]["strong"]) or "-"
            weak = ", ".join(debug[key]["weak"]) or "-"
            print(f"  {key}: strong=[{strong}] weak=[{weak}]")
    print(f"Profile: {persona}")

    return {
        "package": package_name,
        "label": app_label,
        "risk": score,
        "D": d,
        "S": s,
        "V": v,
        "groups": groups,
        "footprint": footprint,
        "persona": persona,
        "fw_ds": fw_ds,
        "vendor_names": vendor_names,
        "risk_counts": risk_counts,
        "score_detail": detail,
    }


def render_barcode_line(package_name: str, label: str, profile: Mapping[str, object]) -> str:
    return (
        f"{label}  | "
        + " | ".join(f"{key} {'▓▓' if profile['groups'].get(key, 0) >= 2 else ('▓░' if profile['groups'].get(key, 0) == 1 else '░░')}" for key in _GROUP_ORDER)
    )


def render_after_run_summary(rows: Sequence[Mapping[str, object]]) -> None:
    from scytaledroid.Utils.DisplayUtils import table_utils
    headers = ["Abbr", "Score", "Grade", "D", "S", "V"]
    formatted = []
    for item in rows:
        label = f"{item['label']}"
        abbr = _abbr_from_name(label).strip()
        score = float(item.get("risk", 0.0) or 0.0)
        grade = permission_risk_grade(score)
        formatted.append([
            abbr,
            f"{score:.3f}",
            grade,
            str(item.get("D", 0)),
            str(item.get("S", 0)),
            str(item.get("V", 0)),
        ])
    print("Risk Summary — Top apps (by permission risk)")
    print("-" * 75)
    table_utils.render_table(headers, formatted)


def render_signal_matrix(items: Sequence[Mapping[str, object]]) -> None:
    from scytaledroid.Utils.DisplayUtils import table_utils
    if not items:
        return
    # Use abbreviations in headers
    headers = ["Signal"] + [ _abbr_from_name(item["label"]).strip() for item in items ]
    rows = []
    def _cell(item, key):
        g = item["groups"].get(key, 0)
        if key in {"OVR", "NOT"}:
            return "S" if g >= 2 else ("D" if g == 1 else "·")
        if key == "ADS":
            return "A" if item.get("V", 0) > 0 else "·"
        return "D" if g >= 1 else "·"
    signals = [
        ("Precise location", "LOC"),
        ("Camera", "CAM"),
        ("Microphone", "MIC"),
        ("Overlay (draw over)", "OVR"),
        ("Contacts", "CNT"),
        ("SMS", "SMS"),
        ("Calls", "PHN"),
        ("Storage/Media (broad)", "STR"),
        ("Bluetooth/Nearby", "BT"),
        ("Notifications", "NOT"),
        ("Ads/Attribution", "ADS"),
    ]
    print("\nSignal Matrix — Dangerous + Signature")
    print("-" * 66)
    for title, key in signals:
        row = [title]
        for item in items:
            row.append(_cell(item, key))
        rows.append(row)
    table_utils.render_table(headers, rows)


def render_contribution_summary(items: Sequence[Mapping[str, object]]) -> None:
    from scytaledroid.Utils.DisplayUtils import table_utils

    if not items:
        return

    headers = [
        "Abbr",
        "Score",
        "Grade",
        "SigTotal",
        "Combo",
        "Surprise",
        "Legacy",
        "Vendor",
        "Credit",
        "Gates",
    ]
    rows: list[list[str]] = []
    for item in items:
        label = str(item.get("label", ""))
        abbr = _abbr_from_name(label).strip()
        detail = item.get("score_detail") or {}
        try:
            score = float(detail.get("score_3dp", item.get("risk", 0.0)))
        except (TypeError, ValueError):
            score = float(item.get("risk", 0.0) or 0.0)
        grade = detail.get("grade") or permission_risk_grade(score)
        rows.append(
            [
                abbr,
                f"{score:.3f}",
                str(grade),
                f"{float(detail.get('signal_score_subtotal', 0.0)):.3f}",
                f"{float(detail.get('combo_total', 0.0)):.3f}",
                f"{float(detail.get('surprise_total', 0.0)):.3f}",
                f"{float(detail.get('legacy_total', 0.0)):.3f}",
                f"{float(detail.get('vendor_modifier', 0.0)):.3f}",
                f"{float(detail.get('modernization_credit', 0.0)):.3f}",
                str(detail.get("hard_gates_triggered", [])),
            ]
        )

    print("\nContribution Summary (top apps)")
    print("-" * 72)
    table_utils.render_table(headers, rows)


# ------------------------------
# Application Permission Matrix (compact)
# ------------------------------

def _abbr_from_name(name: str) -> str:
    base = name if "." not in name else name.split(".")[-1]
    label = "".join(ch for ch in base if ch.isalnum())
    if not label:
        return "APP"
    up = label.upper()
    head = up[0]
    tail = up[1:]
    no_vowels = "".join(ch for ch in tail if ch not in "AEIOU")
    token = (head + no_vowels)[:5]
    return token.ljust(5, " ")


_MATRIX_ROWS = [
    ("Location", ["ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]),
    ("Camera & Microphone", ["CAMERA", "RECORD_AUDIO"]),
    ("Overlay & Notifications", ["SYSTEM_ALERT_WINDOW", "POST_NOTIFICATIONS"]),
    ("Contacts & Accounts", ["READ_CONTACTS", "GET_ACCOUNTS"]),
    ("Phone & SMS", ["READ_CALL_LOG", "READ_PHONE_STATE", "SEND_SMS"]),
    ("Storage & Media", ["READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "ACCESS_MEDIA_LOCATION"]),
    ("Bluetooth & Nearby", ["BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT"]),
    ("Ads / Attribution", ["ACCESS_ADSERVICES_AD_ID", "com.google.android.gms.permission.AD_ID"]),
]


def render_permission_matrix(
    profiles: Sequence[Mapping[str, object]],
    *,
    scope_label: str,
    show: int = 4,
) -> None:
    from datetime import datetime
    from scytaledroid.Utils.DisplayUtils import table_utils

    if not profiles:
        return

    top = list(sorted(profiles, key=lambda p: p.get("risk", 0.0), reverse=True))[: max(1, show)]
    abbrev = [(_abbr_from_name(p["label"]), p["label"]) for p in top]
    now = datetime.now().strftime("%Y-%m-%d %-I:%M %p") if hasattr(datetime.now(), 'strftime') else datetime.now().strftime("%Y-%m-%d %I:%M %p")

    print("\nApplication Permission Matrix")
    print(f"Scope: {scope_label}")
    print(f"Snapshot: {now}")
    print(f"View: Apps 1–{len(top)}/{len(profiles)}")
    print()

    headers = ["Permission"] + [abbr.strip() for abbr, _ in abbrev]
    rows: list[list[str]] = []

    for group_title, perms in _MATRIX_ROWS:
        rows.append([group_title] + ["" for _ in top])
        for perm in perms:
            display = perm
            row = [f"  {display}"]
            for item in top:
                fw_ds = item.get("fw_ds", set())
                vendor = item.get("vendor_names", set())
                mark = "-"
                if perm.startswith("com."):
                    mark = "*" if perm in vendor else "-"
                else:
                    mark = "x" if perm in fw_ds else "-"
                # Apply subtle coloring to marks when available
                from scytaledroid.Utils.DisplayUtils import colors as _colors
                _pal = _colors.get_palette() if _colors.colors_enabled() else None
                if _pal:
                    if mark == "x":
                        row.append(_colors.apply(mark, _pal.accent, bold=True))
                    elif mark == "*":
                        row.append(_colors.apply(mark, _pal.warning, bold=True))
                    else:
                        row.append(_colors.apply(mark, _pal.muted))
                else:
                    row.append(mark)
            rows.append(row)

    table_utils.render_table(headers, rows, accent_first_column=False)
    print("\nLegend:")
    print("x = framework (dangerous/signature)")
    print("* = vendor/custom/ads")
    print("- = not requested")
