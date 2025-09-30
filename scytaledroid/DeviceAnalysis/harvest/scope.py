"""Scope selection helpers for APK harvesting."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, text_blocks

PLAY_STORE_INSTALLER = "com.android.vending"


@dataclass(frozen=True)
class PackageInfo:
    """Derived metadata used when filtering packages prior to harvest."""

    package: Dict[str, object]
    package_name: str
    profile_name: str
    is_play_store: bool
    is_user_app: bool
    is_motorola: bool
    is_android_core: bool
    is_google_core: bool
    is_social: bool
    is_messaging: bool
    is_shopping: bool


def select_package_scope(
    packages: Sequence[Dict[str, object]],
) -> Tuple[Optional[str], List[Dict[str, object]]]:
    """Prompt the analyst to choose a harvesting scope and return the filtered list."""

    analysed = [_analyse_package(pkg) for pkg in packages]
    summary = _summarise_scope(analysed)

    _print_scope_overview(summary)

    profile_counts = _profile_counts(analysed)

    option_handlers: Dict[str, Callable[[], Tuple[str, List[Dict[str, object]], bool]]] = {
        "1": lambda: _apply_predicate(
            "Play Store & user-installed apps",
            analysed,
            lambda info: info.is_play_store
            or (
                info.is_user_app
                and not info.is_android_core
                and not info.is_motorola
                and not (info.is_google_core and not info.is_play_store)
            ),
        ),
        "3": lambda: _apply_predicate(
            "Google core modules",
            analysed,
            lambda info: info.is_google_core and not info.is_play_store,
        ),
        "4": lambda: _apply_predicate(
            "Android core modules",
            analysed,
            lambda info: info.is_android_core,
        ),
        "5": lambda: _apply_predicate(
            "Motorola components",
            analysed,
            lambda info: info.is_motorola,
        ),
        "6": lambda: _custom_package_selection(analysed),
        "7": lambda: _apply_predicate(
            "All packages",
            analysed,
            lambda _: True,
        ),
    }

    menu_entries: List[Tuple[str, str]] = [
        ("1", "Play Store & user-installed apps"),
    ]

    has_profiles = bool(profile_counts)
    if has_profiles:
        option_handlers["2"] = lambda: _select_profile_group(profile_counts, analysed)
        menu_entries.append(("2", "Profile targets..."))

    menu_entries.extend(
        [
            ("3", "Google core modules"),
            ("4", "Android core modules"),
            ("5", "Motorola components"),
            ("6", "Custom selection..."),
            ("7", "All packages"),
        ]
    )

    print()
    menu_utils.print_header("APK Pull Scope")
    menu_utils.print_menu(dict(menu_entries), is_main=False)

    while True:
        choice = menu_utils.get_choice(list(option_handlers.keys()) + ["0"], default="1")

        if choice == "0":
            return None, []

        handler = option_handlers.get(choice)
        if handler is None:
            print(status_messages.status("Selection not available.", level="warn"))
            continue
        label, filtered, aborted = handler()
        if aborted:
            continue
        return label, filtered


def _analyse_package(pkg: Dict[str, object]) -> PackageInfo:
    package_name = str(pkg.get("package_name") or "")
    installer = str(pkg.get("installer") or "")
    source = str(pkg.get("source") or "")
    category = str(pkg.get("category") or "")
    primary_path = str(pkg.get("primary_path") or "")
    if not primary_path and pkg.get("apk_paths"):
        first_path = pkg.get("apk_paths")[0]
        primary_path = str(first_path) if first_path else ""

    profile_name = str(pkg.get("profile_name") or "")
    profile_slug = profile_name.lower()

    is_play_store = installer == PLAY_STORE_INSTALLER or source.lower() == "play store"
    is_user_app = category == "User" or primary_path.startswith("/data/")
    is_motorola = package_name.startswith("com.motorola.")
    is_android_core = package_name.startswith("com.android.")
    is_google_core = package_name.startswith("com.google.")
    is_social = profile_slug == "social"
    is_messaging = profile_slug.startswith("messaging") or "messaging" in profile_slug or "comms" in profile_slug
    is_shopping = profile_slug == "shopping"

    return PackageInfo(
        package=pkg,
        package_name=package_name,
        profile_name=profile_name,
        is_play_store=is_play_store,
        is_user_app=is_user_app,
        is_motorola=is_motorola,
        is_android_core=is_android_core,
        is_google_core=is_google_core,
        is_social=is_social,
        is_messaging=is_messaging,
        is_shopping=is_shopping,
    )


def _summarise_scope(analysed: Sequence[PackageInfo]) -> Dict[str, int]:
    summary = {
        "total": 0,
        "play_store": 0,
        "user_sideload": 0,
        "motorola": 0,
        "google_core": 0,
        "android_core": 0,
        "other_system": 0,
        "social": 0,
        "messaging": 0,
        "shopping": 0,
    }

    for info in analysed:
        summary["total"] += 1
        if info.is_play_store:
            summary["play_store"] += 1
        if info.is_user_app and not info.is_play_store:
            summary["user_sideload"] += 1
        if info.is_motorola:
            summary["motorola"] += 1
        if info.is_google_core:
            summary["google_core"] += 1
        if info.is_android_core:
            summary["android_core"] += 1
        if (
            not info.is_user_app
            and not info.is_motorola
            and not info.is_android_core
            and not info.is_google_core
        ):
            summary["other_system"] += 1
        if info.is_social:
            summary["social"] += 1
        if info.is_messaging:
            summary["messaging"] += 1
        if info.is_shopping:
            summary["shopping"] += 1

    return summary


def _profile_counts(analysed: Sequence[PackageInfo]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for info in analysed:
        if info.profile_name:
            counts[info.profile_name] += 1
    return counts


def _print_scope_overview(summary: Dict[str, int]) -> None:
    print()
    print(text_blocks.headline("Package Scope Overview", width=70))
    bullets = [
        f"Total packages discovered: {summary['total']}",
        f"Play Store apps: {summary['play_store']}",
        f"User / sideloaded apps: {summary['user_sideload']}",
        f"Motorola components: {summary['motorola']}",
        f"Google core modules: {summary['google_core']}",
        f"Android core modules: {summary['android_core']}",
        f"Other system/OEM entries: {summary['other_system']}",
        f"Social profile apps: {summary['social']}",
        f"Messaging / comms apps: {summary['messaging']}",
        f"Shopping apps: {summary['shopping']}",
    ]
    for line in bullets:
        print(status_messages.status(line))


def _apply_predicate(
    label: str,
    analysed: Sequence[PackageInfo],
    predicate: Callable[[PackageInfo], bool],
) -> Tuple[str, List[Dict[str, object]], bool]:
    filtered = [info.package for info in analysed if predicate(info)]
    return label, filtered, False


def _custom_package_selection(
    analysed: Sequence[PackageInfo],
) -> Tuple[str, List[Dict[str, object]], bool]:
    print()
    print(
        status_messages.status(
            "Enter package names (comma separated, prefix * wildcards supported). Leave blank to cancel.",
            level="info",
        )
    )
    raw = input("Packages: ").strip()
    if not raw:
        print(status_messages.status("Custom selection cancelled.", level="warn"))
        return "Custom selection", [], True

    patterns = [token.strip().lower() for token in re.split(r"[\s,]+", raw) if token.strip()]
    if not patterns:
        print(status_messages.status("No valid package identifiers provided.", level="warn"))
        return "Custom selection", [], True

    matches: List[Dict[str, object]] = []
    for info in analysed:
        name = info.package_name.lower()
        if any(_pattern_matches(pattern, name) for pattern in patterns):
            matches.append(info.package)

    if not matches:
        print(status_messages.status("No packages matched the provided patterns.", level="warn"))

    label = f"Custom selection ({', '.join(patterns)})"
    return label, matches, False


def _pattern_matches(pattern: str, value: str) -> bool:
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        return re.match(regex, value) is not None
    if "." not in pattern:
        return pattern in value
    return pattern == value


def _select_profile_group(
    profile_counts: Counter,
    analysed: Sequence[PackageInfo],
) -> Tuple[str, List[Dict[str, object]], bool]:
    if not profile_counts:
        print(status_messages.status("No profiled packages available.", level="warn"))
        return "Profiles", [], True

    print()
    menu_utils.print_header("Select profile")
    sorted_profiles = sorted(profile_counts.items(), key=lambda item: (-item[1], item[0].lower()))
    profile_menu: Dict[str, str] = {}
    for index, (profile, count) in enumerate(sorted_profiles, start=1):
        profile_menu[str(index)] = f"{profile} ({count})"

    menu_utils.print_menu(profile_menu, is_main=False)
    choice = menu_utils.get_choice(list(profile_menu.keys()) + ["0"], default="1")

    if choice == "0":
        return "Profiles", [], True

    selected_profile, _ = sorted_profiles[int(choice) - 1]
    filtered = [info.package for info in analysed if info.profile_name == selected_profile]
    return f"Profile: {selected_profile}", filtered, False
