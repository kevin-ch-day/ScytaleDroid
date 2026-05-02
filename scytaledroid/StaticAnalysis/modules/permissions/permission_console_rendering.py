# File: permission_console_rendering.py
"""Console rendering utilities for permission analysis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.StaticAnalysis.risk.permission import (
    permission_risk_grade,
    permission_risk_score_detail,
)

from .analysis.capability_signal_classifier import (
    _GROUP_ORDER,
    compute_group_strengths,
    iter_group_hits,
)
from .permission_manifest_extract import _format_permission, collect_permissions_and_sdk
from .permission_matrix_view import render_permission_matrix
from .permission_protection_lookup import _fetch_protections


def print_permissions_block(
    package_name: str,
    artifact_label: str,
    declared: Sequence[tuple[str, str]],
    defined: Sequence[dict[str, str | None]],
    sdk: dict[str, str | None],
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
    # Deduplicate declared names (ignore sdk-23 suffix for risk lookup)
    unique_declared: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, element_type in declared:
        key = (name, element_type)
        if key not in seen:
            seen.add(key)
            unique_declared.append((name, element_type))

    # Protective annotations from framework table when available
    # Build short, uppercase keys for framework permissions
    shorts_only = [n.split(".")[-1].upper() for n, _ in unique_declared if n.startswith("android.")]
    protection_map = _fetch_protections(shorts_only, target_sdk=target_sdk_val)

    android_perms: list[str] = []
    custom_perms: list[str] = []
    risk_counts: dict[str, int] = {"dangerous": 0, "signature": 0, "normal": 0, "other": 0}
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
    declared: Sequence[tuple[str, str]],
    protection_map: Mapping[str, str | None],
) -> tuple[dict[str, int], dict[str, int], dict[str, int], set[str], set[str]]:
    """Return counts per class and group signals.

    Returns (risk_counts, group_strength, oem_counts)
    - risk_counts: counts of framework protections (dangerous/signature/normal/other)
    - group_strength: 0/1/2 intensity for each group key
    - oem_counts: count of OEM/custom permissions overall and by group
    """

    risk_counts: dict[str, int] = {"dangerous": 0, "signature": 0, "normal": 0, "other": 0}
    group_strength, fw_ds = compute_group_strengths(declared, protection_map)
    oem_counts: dict[str, int] = {"ADS": 0}
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


def _resolve_declared_permissions_and_sdk(
    *,
    report: object | None,
    sdk: Mapping[str, str | None] | None = None,
    declared: Sequence[tuple[str, str]] | None = None,
) -> tuple[list[tuple[str, str]], dict[str, str | None], int | None, bool | None, bool | None]:
    declared_pairs = list(declared or ())
    resolved_sdk: dict[str, str | None] = dict(sdk or {})

    report_file = getattr(report, "file_path", None) if report is not None else None
    if report_file:
        try:
            extracted_declared, _defined, extracted_sdk = collect_permissions_and_sdk(str(report_file))
            if extracted_declared:
                declared_pairs = list(extracted_declared)
            if isinstance(extracted_sdk, Mapping):
                for key, value in extracted_sdk.items():
                    if value is not None and resolved_sdk.get(key) is None:
                        resolved_sdk[key] = value
        except Exception:
            pass

    if not declared_pairs and report is not None:
        try:
            report_declared = list(getattr(getattr(report, "permissions", None), "declared", None) or ())
            declared_pairs = [(str(name), "uses-permission") for name in report_declared if name]
        except Exception:
            declared_pairs = []

    target_sdk_val = None
    try:
        target_raw = resolved_sdk.get("target")
        if target_raw is None:
            target_raw = resolved_sdk.get("target_sdk")
        target_sdk_val = int(target_raw) if target_raw is not None else None
    except Exception:
        target_sdk_val = None

    manifest = getattr(report, "manifest", None) if report is not None else None
    if target_sdk_val is None and manifest is not None:
        try:
            manifest_target = getattr(manifest, "target_sdk", None)
            target_sdk_val = int(manifest_target) if manifest_target is not None else None
        except Exception:
            target_sdk_val = None

    allow_backup_flag = resolved_sdk.get("allow_backup")
    if allow_backup_flag is not None:
        allow_backup_flag = bool(allow_backup_flag)
    legacy_ext_flag = resolved_sdk.get("legacy_external_storage")
    if legacy_ext_flag is not None:
        legacy_ext_flag = bool(legacy_ext_flag)

    manifest_flags = getattr(report, "manifest_flags", None) if report is not None else None
    if allow_backup_flag is None and manifest_flags is not None:
        allow_backup_raw = getattr(manifest_flags, "allow_backup", None)
        allow_backup_flag = bool(allow_backup_raw) if allow_backup_raw is not None else None
    if legacy_ext_flag is None and manifest_flags is not None:
        legacy_ext_raw = getattr(manifest_flags, "request_legacy_external_storage", None)
        legacy_ext_flag = bool(legacy_ext_raw) if legacy_ext_raw is not None else None

    return declared_pairs, resolved_sdk, target_sdk_val, allow_backup_flag, legacy_ext_flag


def _normalize_permission_key(name: str) -> str:
    if name.startswith("android."):
        return name.split(".")[-1].upper()
    return name


def _collect_declared_tokens(
    declared_sources: Mapping[str, Sequence[tuple[str, str]]],
) -> list[str]:
    tokens: set[str] = set()
    for perms in declared_sources.values():
        for perm_name, _ in perms:
            tokens.add(_normalize_permission_key(str(perm_name)))
    return sorted(tokens)


def _build_declared_origins(
    declared_sources: Mapping[str, Sequence[tuple[str, str]]],
    fw_ds: Sequence[str],
    oem_names: Sequence[str],
) -> dict[str, str]:
    origins: dict[str, str] = {}
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
    parts: list[str] = []
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


def _footprint_multiline(groups: Mapping[str, int]) -> list[str]:
    """Return a multi-line footprint with short descriptors per capability."""
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
    rows: list[list[str]] = []
    for key in _GROUP_ORDER:
        val = groups.get(key, 0)
        if val >= 2:
            bar = "▓" * bar_width
        elif val == 1:
            bar = "▓" * (bar_width // 2) + "░" * (bar_width - bar_width // 2)
        else:
            bar = "░" * bar_width
        name = label_map.get(key, key)
        rows.append([name, bar])
    # Print as a tiny table for alignment
    print("Footprint:")
    table_utils.render_table(["Capability", "Level"], rows)
    return []


def _high_signal_tags(groups: Mapping[str, int]) -> list[str]:
    tags: list[str] = []
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
    declared: Sequence[tuple[str, str]],
    protection_map: Mapping[str, str | None],
) -> dict[str, dict[str, list[str]]]:
    """Return group -> {strong: [...], weak: [...]} for debugging footprint.

    Mirrors the mapping rules in analysis/signals.py to show which permissions
    contributed to each capability and with what strength.
    """
    out: dict[str, dict[str, list[str]]] = {k: {"strong": [], "weak": []} for k in _GROUP_ORDER}

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
    declared: Sequence[tuple[str, str]],
    defined: Sequence[dict[str, str | None]],
    sdk: dict[str, str | None] | None = None,
    report: object | None = None,
    *,
    index: int,
    total: int,
    compact: bool = False,
    silent: bool = False,
    debug: bool = False,
) -> dict[str, object]:
    """Analyze and print a compact permission-first postcard.

    Returns a profile dict for summary usage.
    """
    declared, _resolved_sdk, target_sdk_val, allow_backup_flag, legacy_ext_flag = (
        _resolve_declared_permissions_and_sdk(report=report, sdk=sdk, declared=declared)
    )
    # Framework protections lookup
    shorts_only = [n.split(".")[-1].upper() for n, _ in declared if n.startswith("android.")]
    protection_map = _fetch_protections(shorts_only, target_sdk=target_sdk_val)
    risk_counts, groups, oem_counts, fw_ds, oem_names = _classify_permissions(declared, protection_map)

    d = risk_counts.get("dangerous", 0)
    s = risk_counts.get("signature", 0)
    v = oem_counts.get("ADS", 0)

    detector_metrics = getattr(report, "detector_metrics", None) if report is not None else None
    permissions_metrics: Mapping[str, object] | None = None
    if isinstance(detector_metrics, Mapping):
        permissions_metrics = detector_metrics.get("permissions_profile")

    profiles_section = {}
    if isinstance(permissions_metrics, Mapping):
        raw_profiles = permissions_metrics.get("permission_profiles")
        if isinstance(raw_profiles, Mapping):
            profiles_section = raw_profiles

    flagged_normals_set: set[str] = set()
    noteworthy_normals_set: set[str] = set()
    special_risk_normals_set: set[str] = set()
    weak_guard_count = 0
    if profiles_section:
        for perm_name, data in profiles_section.items():
            if not isinstance(data, Mapping):
                continue
            if data.get("is_flagged_normal"):
                flagged_normals_set.add(str(perm_name))
            flagged_class = str(data.get("flagged_normal_class") or "").strip().lower()
            if flagged_class == "noteworthy_normal":
                noteworthy_normals_set.add(str(perm_name))
            elif flagged_class == "special_risk_normal":
                special_risk_normals_set.add(str(perm_name))
            guard_strength = str(data.get("guard_strength") or "").lower()
            if guard_strength in {"weak", "unknown"} and data.get("is_runtime_dangerous"):
                weak_guard_count += 1
    elif isinstance(permissions_metrics, Mapping):
        flagged_list = permissions_metrics.get("flagged_normal_permissions")
        if isinstance(flagged_list, (list, tuple, set)):
            flagged_normals_set.update(str(item) for item in flagged_list)
    flagged_normals = len(flagged_normals_set)
    noteworthy_normals = len(noteworthy_normals_set)
    special_risk_normals = len(special_risk_normals_set)

    detail = dict(
        permission_risk_score_detail(
            dangerous=d,
            signature=s,
            vendor=v,
            groups=groups,
            target_sdk=target_sdk_val,
            allow_backup=allow_backup_flag,
            legacy_external_storage=legacy_ext_flag,
            flagged_normals=flagged_normals,
            noteworthy_normals=noteworthy_normals,
            special_risk_normals=special_risk_normals,
            weak_guards=weak_guard_count,
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
    if flagged_normals_set and "flagged_permissions" not in detail:
        detail["flagged_permissions"] = sorted(flagged_normals_set)
    if not silent:
        print(f"[{index}/{total}] {app_label}  {bar}")
        print(f"Risk {score:.3f}   (D:{d}  S:{s}  O:{v})  Grade {grade}")
        if high_tags:
            tag_list = list(high_tags)
            if compact and len(tag_list) > 5:
                shown = tag_list[:5]
                tags = "".join(f"[{t}]" for t in shown) + f"[+{len(tag_list) - 5}]"
            else:
                tags = "".join(f"[{t}]" for t in tag_list)
            print(f"High-signal:  {tags}")
        if not compact:
            _footprint_multiline(groups)
            # Optional debug block to explain footprint composition.
            # Debug must be driven by explicit config, not environment reads mid-run.
            if debug:
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
        from scytaledroid.StaticAnalysis.risk.permission import get_scoring_params
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
