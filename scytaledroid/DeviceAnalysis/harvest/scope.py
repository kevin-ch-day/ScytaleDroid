"""Scope selection helpers for APK harvesting."""

from __future__ import annotations

import re
from collections import Counter
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .models import InventoryRow, ScopeSelection
from . import rules


def _maybe_str(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

_LAST_SCOPE: Optional[ScopeSelection] = None


def _append_non_root_note(label: str) -> str:
    if "→" in label:
        head, tail = label.split("→", 1)
        head = head.rstrip()
        if "(non-root" not in head:
            head = f"{head} (non-root skip) "
        return f"{head}→{tail}"
    if "(non-root" in label:
        return label
    return f"{label} (non-root skip)"


def build_inventory_rows(packages: Sequence[Dict[str, object]]) -> List[InventoryRow]:
    """Normalise raw inventory package dictionaries into ``InventoryRow`` entries."""

    rows: List[InventoryRow] = []
    for pkg in packages:
        package_name = str(pkg.get("package_name") or "").strip()
        if not package_name:
            continue
        apk_paths = [
            str(path).strip()
            for path in pkg.get("apk_paths", [])  # type: ignore[arg-type]
            if str(path).strip()
        ]
        split_count = int(pkg.get("split_count") or len(apk_paths) or 0)
        rows.append(
            InventoryRow(
                raw=dict(pkg),
                package_name=package_name,
                app_label=_maybe_str(pkg.get("app_label")),
                installer=_maybe_str(pkg.get("installer")),
                category=_maybe_str(pkg.get("category")),
                primary_path=_maybe_str(pkg.get("primary_path")),
                profile=_maybe_str(pkg.get("profile_name")),
                version_name=_maybe_str(pkg.get("version_name")),
                version_code=_maybe_str(pkg.get("version_code")),
                apk_paths=apk_paths,
                split_count=split_count,
            )
        )
    return rows


def select_package_scope(
    rows: Sequence[InventoryRow],
    *,
    device_serial: str,
    is_rooted: bool,
    google_allowlist: Optional[Iterable[str]] = None,
) -> Optional[ScopeSelection]:
    """Prompt the analyst to choose a harvesting scope and return the filtered list."""

    if not rows:
        print(status_messages.status("No inventory data available for harvest.", level="warn"))
        return None

    allow = set(google_allowlist or rules.GOOGLE_ALLOWLIST)
    context = _build_scope_context(rows, allow)
    profile_counts: Counter[str] = context["profile_counts"]  # type: ignore[assignment]

    while True:
        _print_scope_overview(rows, device_serial, is_rooted, context)
        menu_entries: List[Tuple[str, str]] = [
            ("1", _format_option_label("Play Store & user-installed apps", context["default_counts"])),
        ]

        option_handlers: Dict[str, Callable[[], Optional[ScopeSelection]]] = {
            "1": lambda: _scope_default(rows, allow),
        }

        if profile_counts:
            menu_entries.append(
                ("2", _format_option_label("Profile targets…", context["profile_summary"]))
            )
            option_handlers["2"] = lambda: _scope_profiles(rows, profile_counts, allow)

        menu_entries.extend(
            [
                ("3", _format_option_label("Google exceptions", context["google_exceptions"])),
                ("4", _format_option_label("Families (Android/Google/Motorola system)", context["families"])),
                ("5", "Custom patterns (comma, supports prefix *)"),
                ("9", _format_option_label("Everything (include system/vendor)", context["everything"])),
            ]
        )

        option_handlers.update(
            {
                "3": lambda: _scope_google_allowlist(rows, allow),
                "4": lambda: _scope_families(rows),
                "5": lambda: _scope_custom(rows, allow),
                "9": lambda: ScopeSelection(
                    label="Everything",
                    packages=list(rows),
                    kind="everything",
                    metadata={"estimated_files": context["everything"].get("files", 0)},
                ),
            }
        )

        if _LAST_SCOPE is not None:
            menu_entries.insert(0, ("R", _format_rerun_label(_LAST_SCOPE)))
            option_handlers["R"] = lambda: _LAST_SCOPE

        menu_utils.print_header("APK Pull Scope")
        if _LAST_SCOPE is not None:
            menu_utils.print_hint("Press R to re-run the previous selection instantly.")
        if not is_rooted:
            menu_entries = [
                (
                    key,
                    _append_non_root_note(label) if key == "4" else label,
                )
                for key, label in menu_entries
            ]
        menu_utils.print_menu(menu_entries, is_main=False, default="1", exit_label="Cancel")

        choice = prompt_utils.get_choice([key for key, _ in menu_entries] + ["0"], default="1")
        if choice == "0":
            return None

        handler = option_handlers.get(choice)
        if handler is None:
            print(status_messages.status("Selection not available.", level="warn"))
            continue

        selection = handler()
        if selection is None:
            continue

        _store_last_scope(selection)
        return selection


def _format_option_label(label: str, stats: Dict[str, int]) -> str:
    packages = stats.get("packages", 0)
    files = stats.get("files", 0)
    if packages:
        return f"{label:<55} → {packages} pkg(s) / ~{files} file(s)"
    return f"{label:<55} → 0"


def _format_rerun_label(selection: ScopeSelection) -> str:
    pkg_count = len(selection.packages)
    return f"Re-run last scope ({selection.label} – {pkg_count} pkg(s))"


def _scope_default(rows: Sequence[InventoryRow], allow: Set[str]) -> ScopeSelection:
    selected, excluded = _apply_default_scope(rows, allow)
    metadata = {
        "estimated_files": _estimated_files(selected),
        "allowlist_size": len(allow),
        "excluded_counts": excluded,
    }
    return ScopeSelection("Play Store & user-installed", selected, "default", metadata)


def _scope_profiles(
    rows: Sequence[InventoryRow],
    profile_counts: Counter[str],
    allow: Set[str],
) -> Optional[ScopeSelection]:
    if not profile_counts:
        print(status_messages.status("No profiled packages available.", level="warn"))
        return None

    print()
    menu_utils.print_header("Choose profile(s)")
    sorted_profiles = sorted(
        [(name, count) for name, count in profile_counts.items() if name],
        key=lambda item: (-item[1], item[0].lower()),
    )
    profile_menu: Dict[str, str] = {}
    for index, (profile, count) in enumerate(sorted_profiles, start=1):
        profile_menu[str(index)] = f"{profile} ({count})"
    profile_menu["A"] = "All profiles"

    menu_utils.print_menu(profile_menu, is_main=False)
    raw = input("Selection (e.g., 1,3 or A): ").strip()
    if not raw:
        print(status_messages.status("Profile selection cancelled.", level="warn"))
        return None

    if raw.upper() == "A":
        selected = {name for name, _ in sorted_profiles}
    else:
        tokens = {token.strip() for token in re.split(r"[,\s]+", raw) if token.strip()}
        selected: Set[str] = set()
        for token in tokens:
            if token in profile_menu and token.isdigit():
                idx = int(token) - 1
                if 0 <= idx < len(sorted_profiles):
                    selected.add(sorted_profiles[idx][0])
            else:
                selected.add(token)
        selected = {name for name in selected if name}

    if not selected:
        print(status_messages.status("No valid profiles selected.", level="warn"))
        return None

    profile_rows = [row for row in rows if row.profile and row.profile in selected]
    if not profile_rows:
        print(status_messages.status("No packages matched the selected profiles.", level="warn"))
        return None

    filtered, excluded = _apply_default_scope(profile_rows, allow)
    if not filtered:
        print(
            status_messages.status(
                "Selected profiles matched only packages filtered by scope rules.",
                level="warn",
            )
        )
        return None

    metadata = {
        "profiles": sorted(selected),
        "estimated_files": _estimated_files(filtered),
        "excluded_counts": excluded,
    }
    return ScopeSelection(
        label=f"Profiles: {', '.join(sorted(selected))}",
        packages=filtered,
        kind="profiles",
        metadata=metadata,
    )


def _scope_google_allowlist(
    rows: Sequence[InventoryRow], allow: Set[str]
) -> Optional[ScopeSelection]:
    candidates = [row for row in rows if row.package_name in allow]
    if not candidates:
        print(status_messages.status("No Google allow-list packages found in inventory.", level="warn"))
        return None
    filtered, excluded = _apply_default_scope(candidates, allow)
    if not filtered:
        message = (
            "Google allow-list packages present but filtered by scope policy."
            if excluded
            else "No Google allow-list packages matched the current scope."
        )
        print(status_messages.status(message, level="warn"))
        return None
    metadata = {
        "estimated_files": _estimated_files(filtered),
        "excluded_counts": excluded,
    }
    return ScopeSelection("Google exceptions", filtered, "google_allow", metadata)


def _scope_families(rows: Sequence[InventoryRow]) -> Optional[ScopeSelection]:
    filtered = [row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]
    if not filtered:
        print(status_messages.status("No Android/Google/Motorola packages found.", level="warn"))
        return None
    metadata = {"estimated_files": _estimated_files(filtered)}
    return ScopeSelection("System families", filtered, "families", metadata)


def _scope_custom(rows: Sequence[InventoryRow], allow: Set[str]) -> Optional[ScopeSelection]:
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
        return None

    patterns = [token.strip().lower() for token in re.split(r"[\s,]+", raw) if token.strip()]
    if not patterns:
        print(status_messages.status("No valid package identifiers provided.", level="warn"))
        return None

    matches: List[InventoryRow] = []
    for row in rows:
        name = row.package_name.lower()
        if any(_pattern_matches(pattern, name) for pattern in patterns):
            matches.append(row)

    if not matches:
        print(status_messages.status("No packages matched the provided patterns.", level="warn"))
        return None

    filtered, excluded = _apply_default_scope(matches, allow)
    if not filtered:
        print(
            status_messages.status(
                "Custom patterns matched packages filtered by scope policy.",
                level="warn",
            )
        )
        return None

    metadata = {
        "patterns": patterns,
        "estimated_files": _estimated_files(filtered),
        "excluded_counts": excluded,
    }
    return ScopeSelection(
        label=f"Custom ({', '.join(patterns)})",
        packages=filtered,
        kind="custom",
        metadata=metadata,
    )


def _store_last_scope(selection: ScopeSelection) -> None:
    global _LAST_SCOPE
    _LAST_SCOPE = selection


def _build_scope_context(rows: Sequence[InventoryRow], allow: Set[str]) -> Dict[str, object]:
    def estimate(selection: Sequence[InventoryRow]) -> Dict[str, int]:
        return {"packages": len(selection), "files": _estimated_files(selection)}

    profile_counts: Counter[str] = Counter(row.profile for row in rows if row.profile)
    profile_total_rows = [row for row in rows if row.profile]

    default_rows, default_excluded = _apply_default_scope(rows, allow)
    google_rows = [row for row in rows if row.package_name in allow]
    google_filtered, _ = _apply_default_scope(google_rows, allow)

    return {
        "default_counts": estimate(default_rows),
        "default_excluded": default_excluded,
        "profile_counts": profile_counts,
        "profile_summary": estimate(profile_total_rows),
        "google_exceptions": estimate(google_filtered),
        "families": estimate([row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]),
        "everything": estimate(rows),
    }


def _estimated_files(rows: Sequence[InventoryRow]) -> int:
    total = 0
    for row in rows:
        if row.split_count:
            total += row.split_count
        elif row.apk_paths:
            total += len(row.apk_paths)
        else:
            total += 1
    return total


def _in_default_scope(row: InventoryRow, allow: Set[str]) -> bool:
    include, _ = _default_scope_decision(row, allow)
    return include


def _apply_default_scope(
    rows: Sequence[InventoryRow], allow: Set[str]
) -> Tuple[List[InventoryRow], Dict[str, int]]:
    selected: List[InventoryRow] = []
    excluded: Dict[str, int] = {}
    for row in rows:
        include, reason = _default_scope_decision(row, allow)
        if include:
            selected.append(row)
        elif reason:
            excluded[reason] = excluded.get(reason, 0) + 1
    return selected, dict(sorted(excluded.items()))


def _default_scope_decision(row: InventoryRow, allow: Set[str]) -> Tuple[bool, Optional[str]]:
    is_play = row.installer == rules.PLAY_STORE_INSTALLER
    is_user = rules.is_user_path(row.primary_path)
    if not (is_play or is_user):
        return False, "not_in_scope"

    fam = rules.family(row.package_name)
    if fam in {"android", "motorola"}:
        if is_play:
            return True, None
        return False, "family_excluded"
    if fam == "google":
        if is_play or row.package_name in allow:
            return True, None
        return False, "google_core"
    return True, None


def _pattern_matches(pattern: str, value: str) -> bool:
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        return re.match(regex, value) is not None
    if "." not in pattern:
        return pattern in value
    return pattern == value


def _print_scope_overview(
    rows: Sequence[InventoryRow],
    device_serial: str,
    is_rooted: bool,
    context: Dict[str, Dict[str, int]],
) -> None:
    print()
    menu_utils.print_header(
        "Package Scope Overview",
        subtitle=f"{device_serial} · {'root' if is_rooted else 'non-root'}",
    )

    metrics = [
        ("Total packages", len(rows)),
        ("Play Store apps", sum(1 for row in rows if row.installer == rules.PLAY_STORE_INSTALLER)),
        ("User / sideloaded", sum(1 for row in rows if rules.is_user_path(row.primary_path))),
        ("Google core", sum(1 for row in rows if rules.family(row.package_name) == "google")),
        ("Android core", sum(1 for row in rows if rules.family(row.package_name) == "android")),
        ("Motorola components", sum(1 for row in rows if rules.family(row.package_name) == "motorola")),
    ]
    menu_utils.print_metrics(metrics)

    default_stats = context["default_counts"]
    menu_utils.print_hint(
        f"Default scope → {default_stats.get('packages', 0)} pkg(s) / ~{default_stats.get('files', 0)} file(s)"
    )


def reset_last_scope() -> None:
    """Reset cached scope state (mainly used in tests)."""

    global _LAST_SCOPE
    _LAST_SCOPE = None


__all__ = [
    "build_inventory_rows",
    "reset_last_scope",
    "select_package_scope",
]

