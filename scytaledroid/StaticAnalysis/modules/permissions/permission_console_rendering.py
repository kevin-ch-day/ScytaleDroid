# File: permission_console_rendering.py
"""Console rendering utilities for permission analysis."""

from __future__ import annotations

from typing import Dict, List, Mapping, Optional, Sequence, Tuple
import os

from .analysis.capability_signal_classifier import (
    compute_group_strengths,
    iter_group_hits,
    _GROUP_ORDER,
)
from .analysis.risk_scoring_engine import (
    permission_risk_score_detail,
    permission_risk_grade,
)
from .permission_manifest_extract import _format_permission
from .permission_protection_lookup import _fetch_protections


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

    try:
        target_sdk_val = int(target_sdk) if target_sdk not in (None, "-") else None
    except Exception:
        target_sdk_val = None
    allow_backup_flag = None if sdk.get("allow_backup") is None else bool(sdk.get("allow_backup"))
    legacy_ext_flag = None if sdk.get("legacy_external_storage") is None else bool(sdk.get("legacy_external_storage"))

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
    protection_map = _fetch_protections(shorts_only, target_sdk=target_sdk_val)

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
        print(f"Custom/OEM permissions ({len(custom_perms)}):")
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


def _classify_permissions(
    declared: Sequence[Tuple[str, str]],
    protection_map: Mapping[str, Optional[str]],
) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int], set[str], set[str]]:
    """Return counts per class and group signals.

    Returns (risk_counts, group_strength, oem_counts)
    - risk_counts: counts of framework protections (dangerous/signature/normal/other)
    - group_strength: 0/1/2 intensity for each group key
    - oem_counts: count of OEM/custom permissions overall and by group
    """

    risk_counts: Dict[str, int] = {"dangerous": 0, "signature": 0, "normal": 0, "other": 0}
    group_strength, fw_ds = compute_group_strengths(declared, protection_map)
    oem_counts: Dict[str, int] = {"ADS": 0}
    oem_names: set[str] = set()

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
                oem_counts["ADS"] = oem_counts.get("ADS", 0) + 1
            oem_names.add(name)

    return risk_counts, group_strength, oem_counts, fw_ds, oem_names


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
    oem_names: Sequence[str],
) -> Dict[str, str]:
    origins: Dict[str, str] = {}
    fw_set = {key.upper() for key in fw_ds}
    vendor_set = set(oem_names)
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
        "CAL": "calendar",
        "PHN": "calls/phone state",
        "SMS": "sms",
        "STR": "media/storage",
        "SENS": "sensors/health",
        "ACT": "activity recognition",
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
        "CAL": "Calendar",
        "PHN": "Phone",
        "SMS": "SMS",
        "STR": "Storage",
        "SENS": "Sensors",
        "ACT": "Activity",
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
        "CAL": "calendar",
        "PHN": "phone",
        "SMS": "sms",
        "STR": "storage",
        "SENS": "sensors",
        "ACT": "activity",
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
        short = name.split(".")[-1].upper()
        prot = (protection_map.get(short) or "").lower()
        is_ds = prot in {"dangerous", "signature"}

        for key, strong in iter_group_hits(short, is_ds=is_ds):
            _tag(key, short, strong)

    return out


def render_permission_postcard(
    package_name: str,
    app_label: str,
    declared: Sequence[Tuple[str, str]],
    defined: Sequence[Dict[str, str | None]],
    sdk: Dict[str, str | None] | None = None,
    *,
    index: int,
    total: int,
) -> Dict[str, object]:
    """Analyze and print a compact permission-first postcard.

    Returns a profile dict for summary usage.
    """
    # Framework protections lookup
    shorts_only = [n.split(".")[-1].upper() for n, _ in declared if n.startswith("android.")]
    target_sdk_val = None
    allow_backup_flag = None
    legacy_ext_flag = None
    if isinstance(sdk, dict):
        try:
            target_sdk_val = int(sdk.get("target")) if sdk.get("target") is not None else None
        except Exception:
            target_sdk_val = None
        ab = sdk.get("allow_backup")
        allow_backup_flag = bool(ab) if ab is not None else None
        le = sdk.get("legacy_external_storage")
        legacy_ext_flag = bool(le) if le is not None else None

    protection_map = _fetch_protections(shorts_only, target_sdk=target_sdk_val)
    risk_counts, groups, oem_counts, fw_ds, oem_names = _classify_permissions(declared, protection_map)

    d = risk_counts.get("dangerous", 0)
    s = risk_counts.get("signature", 0)
    v = oem_counts.get("ADS", 0)

    detail = dict(
        permission_risk_score_detail(
            dangerous=d,
            signature=s,
            vendor=v,
            groups=groups,
            target_sdk=target_sdk_val,
            allow_backup=allow_backup_flag,
            legacy_external_storage=legacy_ext_flag,
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
    print(f"[{index}/{total}] {app_label}  {bar}")
    print(f"Risk {score:.3f}   (D:{d}  S:{s}  O:{v})  Grade {grade}")
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
    print()

    return {
        "package": package_name,
        "label": app_label,
        "risk": score,
        "D": d,
        "S": s,
        "V": v,
        "O": v,
        "groups": groups,
        "footprint": footprint,
        "persona": persona,
        "fw_ds": fw_ds,
        "vendor_names": oem_names,
        "risk_counts": risk_counts,
        "score_detail": detail,
    }


def render_barcode_line(package_name: str, label: str, profile: Mapping[str, object]) -> str:
    return (
        f"{label}  | "
        + " | ".join(
            f"{key} {'▓▓' if profile['groups'].get(key, 0) >= 2 else ('▓░' if profile['groups'].get(key, 0) == 1 else '░░')}"
            for key in _GROUP_ORDER
        )
    )


def render_after_run_summary(rows: Sequence[Mapping[str, object]]) -> None:
    from scytaledroid.Utils.DisplayUtils import table_utils
    headers = ["Abbr", "Score", "Grade", "D", "S", "O"]
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
            str(item.get("O", item.get("V", 0))),
        ])
    print("Risk Summary — Top apps (by permission risk)")
    print("-" * 75)
    table_utils.render_table(headers, formatted)


def render_signal_matrix(items: Sequence[Mapping[str, object]]) -> None:
    from scytaledroid.Utils.DisplayUtils import table_utils
    if not items:
        return
    # Use abbreviations in headers
    headers = ["Signal"] + [_abbr_from_name(item["label"]).strip() for item in items]
    rows = []

    def _cell(item: Mapping[str, object], key: str) -> str:
        g = item["groups"].get(key, 0)
        if key in {"OVR", "NOT"}:
            return "S" if g >= 2 else ("D" if g == 1 else "·")
        if key == "ADS":
            return "A" if item.get("O", item.get("V", 0)) > 0 else "·"
        return "D" if g >= 1 else "·"

    signals = [
        ("Precise location", "LOC"),
        ("Camera", "CAM"),
        ("Microphone", "MIC"),
        ("Overlay (draw over)", "OVR"),
        ("Contacts", "CNT"),
        ("Calendar", "CAL"),
        ("SMS", "SMS"),
        ("Calls", "PHN"),
        ("Storage/Media (broad)", "STR"),
        ("Sensors/Health", "SENS"),
        ("Activity Recognition", "ACT"),
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


def render_scoring_legend() -> None:
    """Print the scoring model weights and grade thresholds for clarity."""
    try:
        from .analysis.scoring import get_scoring_params  # type: ignore
        p = get_scoring_params()
        dw = p.dangerous_weight
        sw = p.signature_weight
        vw = p.vendor_weight
        step = p.breadth_step
        cap = p.breadth_cap
    except Exception:
        dw = sw = vw = step = cap = 0.0

    print("\nScoring Model — Weights & Thresholds")
    print("-" * 38)
    print(f"Weights: dangerous={dw:.2f}, signature={sw:.2f}, oem={vw:.2f}")
    print(f"Breadth bonus: step={step:.2f}, cap={cap:.2f}")
    print("Modernization credit (max 0.8): +0.3 if targetSdk≥34; +0.3 if requestLegacyExternalStorage is absent; +0.2 if allowBackup=false")
    print("Grades: A≤2.0  B≤4.0  C≤6.5  D≤8.0  F>8.0")
    print("Notes: OEM reflects ads/attribution; breadth counts distinct capability groups requested.")


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
    from scytaledroid.Utils.DisplayUtils import text_blocks

    if not profiles:
        return

    top = list(sorted(profiles, key=lambda p: p.get("risk", 0.0), reverse=True))[: max(1, show)]
    display_labels = []
    for profile in top:
        label = str(profile.get("display_name") or profile.get("label") or "").strip()
        if not label:
            label = str(profile.get("package") or "")
        if not label:
            label = _abbr_from_name(profile.get("label") or "APP").strip()
        display_labels.append(label)
    now = datetime.now().strftime("%Y-%m-%d %-I:%M %p") if hasattr(datetime.now(), "strftime") else datetime.now().strftime("%Y-%m-%d %I:%M %p")

    print("\nApplication Permission Matrix")
    print(f"Scope: {scope_label}")
    print(f"Snapshot: {now}")
    print(f"View: Apps 1–{len(top)}/{len(profiles)}")
    print()

    headers = ["Permission"] + display_labels
    rows: list[list[str]] = []

    def _pad_center(value: str, width: int) -> str:
        visible = text_blocks.visible_width(value)
        if visible >= width:
            return value
        total = width - visible
        left = total // 2
        right = total - left
        return (" " * left) + value + (" " * right)

    for group_title, perms in _MATRIX_ROWS:
        rows.append([group_title] + ["" for _ in top])
        for perm in perms:
            display = perm
            row = [f"  {display}"]
            for item in top:
                fw_ds = {key.upper() for key in item.get("fw_ds", set())}
                vendor = set(item.get("vendor_names", set()))
                mark = "-"
                if perm.startswith("com."):
                    mark = "*" if perm in vendor else "-"
                else:
                    mark = "X" if perm.upper() in fw_ds else "-"
                from scytaledroid.Utils.DisplayUtils import colors as _colors
                _pal = _colors.get_palette() if _colors.colors_enabled() else None
                if _pal:
                    if mark == "X":
                        row.append(_colors.apply(mark, _pal.accent, bold=True))
                    elif mark == "*":
                        row.append(_colors.apply(mark, _pal.warning, bold=True))
                    else:
                        row.append(_colors.apply(mark, _pal.muted))
                else:
                    row.append(mark)
            rows.append(row)

    headers = [text_blocks.truncate_visible(label, 18) for label in headers]
    first_col = max(text_blocks.visible_width("Permission"), *(text_blocks.visible_width(row[0]) for row in rows))
    app_col = max(5, *(text_blocks.visible_width(label) for label in headers[1:]))
    widths = [first_col] + [app_col for _ in headers[1:]]
    pad = "  "

    header_cells = [
        row.ljust(widths[idx])
        for idx, row in enumerate(headers)
    ]
    print(pad.join(header_cells))
    print(pad.join("-" * width for width in widths))

    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            text = str(cell)
            if idx == 0:
                cells.append(text.ljust(widths[idx]))
            else:
                cells.append(_pad_center(text, widths[idx]))
        print(pad.join(cells))

    print("\nLegend:")
    print("X = framework (dangerous/signature)")
    print("* = oem/custom/ads")
    print("- = not requested")


__all__ = [
    "print_permissions_block",
    "render_permission_postcard",
    "render_after_run_summary",
    "render_signal_matrix",
    "render_permission_matrix",
    "render_barcode_line",
    "render_contribution_summary",
    "render_scoring_legend",
    "_abbr_from_name",
]
