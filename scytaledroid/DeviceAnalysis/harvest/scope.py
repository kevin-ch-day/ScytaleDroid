"""Scope selection helpers for APK harvesting."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from scytaledroid.Database.db_core import db_queries
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption

from .models import InventoryRow, ScopeSelection
from . import rules
from .watchlists import Watchlist, filter_rows_by_watchlist, load_watchlists


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


@dataclass(frozen=True)
class _WatchlistEntry:
    watchlist: Watchlist
    filtered: List[InventoryRow]
    excluded: Dict[str, int]
    counts: Dict[str, int]
    preview: str


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
    category_groups: Dict[str, List[InventoryRow]] = context.get("category_groups", {})  # type: ignore[assignment]

    watchlist_entries: List[_WatchlistEntry] = context.get("watchlists", [])  # type: ignore[assignment]

    while True:
        _print_scope_overview(rows, device_serial, is_rooted, context)

        option_handlers: Dict[str, Callable[[], Optional[ScopeSelection]]] = {}
        menu_items: List[MenuOption] = []

        if _LAST_SCOPE is not None:
            menu_items.append(
                MenuOption(
                    "R",
                    _format_rerun_label(_LAST_SCOPE),
                    hint="Replay the previous harvest scope",
                )
            )
            option_handlers["R"] = lambda: _LAST_SCOPE

        menu_items.append(
            MenuOption(
                "1",
                "Play Store & user-installed apps",
                description=_format_menu_count(context["default_counts"]),
                badge=str(context["default_counts"].get("packages", 0)),
            )
        )
        option_handlers["1"] = lambda: _scope_default(rows, allow)

        menu_items.append(
            MenuOption(
                "2",
                "Social apps only",
                description=_format_count_summary(category_groups.get("Social")),
            )
        )
        option_handlers["2"] = lambda: _scope_category_subset(
            category_groups, allow, {"Social"}
        )

        menu_items.append(
            MenuOption(
                "3",
                "Messaging apps only",
                description=_format_count_summary(category_groups.get("Messaging")),
            )
        )
        option_handlers["3"] = lambda: _scope_category_subset(
            category_groups, allow, {"Messaging"}
        )

        menu_items.append(
            MenuOption(
                "4",
                "Social + Messaging",
                description=_format_count_summary(
                    (category_groups.get("Social") or [])
                    + (category_groups.get("Messaging") or [])
                ),
            )
        )
        option_handlers["4"] = lambda: _scope_category_subset(
            category_groups,
            allow,
            {"Social", "Messaging"},
            label="Social & Messaging",
        )

        menu_items.append(
            MenuOption(
                "5",
                "Google user apps",
                description=_format_menu_count(context["google_user"]),
            )
        )
        option_handlers["5"] = lambda: _scope_google_user_apps(rows, allow)

        if profile_counts:
            menu_items.append(
                MenuOption(
                    "6",
                    "Profile targets…",
                    description=_format_menu_count(context["profile_summary"]),
                    hint="Select any profile mix",
                )
            )
            option_handlers["6"] = lambda: _scope_profiles(rows, profile_counts, allow)

        if watchlist_entries:
            for idx, entry in enumerate(watchlist_entries, start=1):
                key = f"W{idx}"
                menu_items.append(
                    MenuOption(
                        key,
                        f"Watchlist · {entry.watchlist.name}",
                        description=_format_menu_count(entry.counts),
                        hint=_format_watchlist_hint(entry),
                    )
                )
                option_handlers[key] = lambda e=entry: _scope_watchlist(e)

        menu_items.extend(
            [
                MenuOption(
                    "7",
                    "Google exceptions",
                    description=_format_menu_count(context["google_exceptions"]),
                ),
                MenuOption(
                    "8",
                    "Families (Android/Google/Motorola system)",
                    description=_format_menu_count(context["families"]),
                    hint="Requires root to capture protected partitions.",
                ),
                MenuOption(
                    "9",
                    "Custom patterns…",
                    description="Comma-separated packages; * supports prefix wildcards.",
                ),
                MenuOption(
                    "E",
                    "Everything (include system/vendor)",
                    description=_format_menu_count(context["everything"]),
                ),
            ]
        )
        option_handlers.update(
            {
                "7": lambda: _scope_google_allowlist(rows, allow),
                "8": lambda: _scope_families(rows),
                "9": lambda: _scope_custom(rows, allow),
                "E": lambda: ScopeSelection(
                    label="Everything",
                    packages=list(rows),
                    kind="everything",
                    metadata={"estimated_files": context["everything"].get("files", 0)},
                ),
            }
        )

        if not is_rooted:
            menu_items = [
                MenuOption(
                    item.key,
                    _append_non_root_note(item.label) if item.key == "4" else item.label,
                    item.description,
                    item.badge,
                    item.disabled,
                    item.hint,
                )
                for item in menu_items
            ]

        menu_utils.print_menu(menu_items, is_main=False, default="1", exit_label="Cancel")
        choice = prompt_utils.get_choice(
            [item.key for item in menu_items] + ["0"],
            default="1",
            casefold=True,
        )
        if choice == "0":
            return None

        handler = option_handlers.get(choice.upper()) or option_handlers.get(choice)
        if handler is None:
            print(status_messages.status("Selection not available.", level="warn"))
            continue

        selection = handler()
        if selection is None:
            continue

        _store_last_scope(selection)
        return selection


def _format_rerun_label(selection: ScopeSelection) -> str:
    pkg_count = len(selection.packages)
    return f"Re-run last scope ({selection.label} – {pkg_count} pkg(s))"


def _format_menu_count(stats: Dict[str, int]) -> str:
    packages = stats.get("packages", 0)
    files = stats.get("files", 0)
    return f"{packages} pkg(s) · ~{files} file(s)"


def _format_watchlist_hint(entry: _WatchlistEntry) -> Optional[str]:
    if not entry.preview:
        return None
    if len(entry.filtered) > 3:
        return f"Preview: {entry.preview}, …"
    return f"Preview: {entry.preview}"


def _scope_default(rows: Sequence[InventoryRow], allow: Set[str]) -> ScopeSelection:
    selected, excluded = _apply_default_scope(rows, allow)
    metadata = {
        "estimated_files": _estimated_files(selected),
        "allowlist_size": len(allow),
        "excluded_counts": excluded,
        "sample_names": _sample_names(selected),
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
        "sample_names": _sample_names(filtered),
    }
    return ScopeSelection(
        label=f"Profiles: {', '.join(sorted(selected))}",
        packages=filtered,
        kind="profiles",
        metadata=metadata,
    )


def _scope_google_user_apps(
    rows: Sequence[InventoryRow], allow: Set[str]
) -> Optional[ScopeSelection]:
    candidates = [row for row in rows if rules.is_google_user_app(row.package_name)]
    if not candidates:
        print(status_messages.status("No Google user apps present on device.", level="warn"))
        return None

    filtered, excluded = _apply_default_scope(candidates, allow)
    if not filtered:
        print(
            status_messages.status(
                "Google user apps present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "estimated_files": _estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": _sample_names(filtered),
    }
    return ScopeSelection("Google user apps", filtered, "google_user", metadata)


def _scope_profile_subset(
    rows: Sequence[InventoryRow],
    allow: Set[str],
    profiles: Set[str],
    *,
    label: str,
) -> Optional[ScopeSelection]:
    normalized = {profile.lower() for profile in profiles}
    subset = [row for row in rows if row.profile and row.profile.lower() in normalized]
    if not subset:
        print(status_messages.status(f"No packages tagged as {label}.", level="warn"))
        return None

    filtered, excluded = _apply_default_scope(subset, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{label} packages present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "profiles": sorted({row.profile for row in subset if row.profile}),
        "estimated_files": _estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": _sample_names(filtered),
    }
    return ScopeSelection(
        label=f"{label} apps",
        packages=filtered,
        kind="profile_subset",
        metadata=metadata,
    )


def _scope_category_subset(
    category_groups: Dict[str, List[InventoryRow]],
    allow: Set[str],
    categories: Set[str],
    *,
    label: Optional[str] = None,
) -> Optional[ScopeSelection]:
    combined: List[InventoryRow] = []
    for category in categories:
        combined.extend(category_groups.get(category, []))
    if not combined:
        print(status_messages.status(f"No packages tagged as {', '.join(categories)}.", level="warn"))
        return None

    filtered, excluded = _apply_default_scope(combined, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{', '.join(categories)} packages present but filtered by scope policy.",
                level="warn",
            )
        )
        return None

    scope_label = label or " & ".join(sorted(categories))
    metadata = {
        "categories": sorted(categories),
        "estimated_files": _estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": _sample_names(filtered),
    }
    return ScopeSelection(
        label=f"{scope_label} apps",
        packages=filtered,
        kind="category_subset",
        metadata=metadata,
    )


def _scope_watchlist(entry: _WatchlistEntry) -> Optional[ScopeSelection]:
    if not entry.filtered:
        print(status_messages.status("Watchlist contains no packages in scope.", level="warn"))
        return None
    metadata = {
        "watchlist": entry.watchlist.name,
        "watchlist_path": str(entry.watchlist.path),
        "estimated_files": entry.counts.get("files", 0),
        "excluded_counts": entry.excluded,
        "sample_names": _sample_names(entry.filtered),
    }
    return ScopeSelection(
        label=f"Watchlist: {entry.watchlist.name}",
        packages=list(entry.filtered),
        kind="watchlist",
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
        "sample_names": _sample_names(filtered),
    }
    return ScopeSelection("Google exceptions", filtered, "google_allow", metadata)


def _scope_families(rows: Sequence[InventoryRow]) -> Optional[ScopeSelection]:
    filtered = [row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]
    if not filtered:
        print(status_messages.status("No Android/Google/Motorola packages found.", level="warn"))
        return None
    metadata = {
        "estimated_files": _estimated_files(filtered),
        "sample_names": _sample_names(filtered),
    }
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
        "sample_names": _sample_names(filtered),
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
    google_user_rows = [row for row in rows if rules.is_google_user_app(row.package_name)]
    google_user_filtered, _ = _apply_default_scope(google_user_rows, allow)

    watchlist_entries: List[_WatchlistEntry] = []
    watchlist_totals = {"packages": 0, "files": 0}
    for watchlist in load_watchlists():
        watch_rows = filter_rows_by_watchlist(rows, watchlist.packages)
        if not watch_rows:
            continue
        filtered, excluded = _apply_default_scope(watch_rows, allow)
        if not filtered:
            continue
        counts = {"packages": len(filtered), "files": _estimated_files(filtered)}
        preview = ", ".join(row.display_name() for row in filtered[:3])
        watchlist_entries.append(
            _WatchlistEntry(
                watchlist=watchlist,
                filtered=filtered,
                excluded=excluded,
                counts=counts,
                preview=preview,
            )
        )
        watchlist_totals["packages"] += counts["packages"]
        watchlist_totals["files"] += counts["files"]

    category_map = _fetch_category_map([row.package_name for row in rows])
    category_groups: Dict[str, List[InventoryRow]] = {}
    for row in rows:
        category_name = category_map.get(row.package_name)
        if category_name:
            category_groups.setdefault(category_name, []).append(row)

    return {
        "default_counts": estimate(default_rows),
        "default_excluded": default_excluded,
        "profile_counts": profile_counts,
        "profile_summary": estimate(profile_total_rows),
        "google_user": estimate(google_user_filtered),
        "google_exceptions": estimate(google_filtered),
        "families": estimate([row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]),
        "everything": estimate(rows),
        "watchlists": watchlist_entries,
        "watchlist_totals": watchlist_totals,
        "category_groups": category_groups,
    }


def _fetch_category_map(package_names: Sequence[str]) -> Dict[str, str]:
    if not package_names:
        return {}
    placeholders = ", ".join(["%s"] * len(package_names))
    query = (
        "SELECT d.package_name, c.category_name "
        "FROM android_app_definitions d "
        "JOIN android_app_categories c ON c.category_id = d.category_id "
        f"WHERE d.package_name IN ({placeholders})"
    )

    rows = db_queries.run_sql(query, tuple(package_names), fetch="all", dictionary=True)
    mapping: Dict[str, str] = {}
    if rows:
        for row in rows:
            pkg = str(row.get("package_name") or "").strip()
            category = str(row.get("category_name") or "").strip()
            if pkg and category:
                mapping[pkg] = category
    return mapping


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


def _format_count(stats: object, key: str, *, prefix: str = "") -> str:
    if isinstance(stats, dict):
        value = int(stats.get(key, 0))
    else:
        value = 0
    unit = "pkg(s)" if key == "packages" else "file(s)"
    return f"{prefix}{value} {unit}"


def _sample_names(rows: Sequence[InventoryRow], limit: int = 3) -> List[str]:
    names: List[str] = []
    for row in rows:
        if len(names) >= limit:
            break
        names.append(row.display_name())
    return names


def _format_count_summary(rows: Optional[Sequence[InventoryRow]]) -> str:
    if not rows:
        return "0 pkg(s)"
    return f"{len(rows)} pkg(s)"


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
    context: Dict[str, object],
) -> None:
    print()
    menu_utils.print_header(
        "Package Scope Overview",
        subtitle=f"{device_serial} · {'root' if is_rooted else 'non-root'}",
    )
    headers = ("Subset", "Packages", "Artifacts", "Notes")
    rows_summary: List[Tuple[str, str, str, str]] = [
        (
            "Play & user",
            _format_count(context["default_counts"], "packages"),
            _format_count(context["default_counts"], "files", prefix="~"),
            "Default scope",
        ),
    ]

    rows_summary.append(
        (
            "Google user",
            _format_count(context["google_user"], "packages"),
            _format_count(context["google_user"], "files", prefix="~"),
            "YouTube/Maps/Photos/etc.",
        )
    )

    profile_summary = context.get("profile_summary", {"packages": 0})
    if profile_summary.get("packages", 0):
        rows_summary.append(
            (
                "Profiled apps",
                _format_count(profile_summary, "packages"),
                _format_count(profile_summary, "files", prefix="~"),
                "Social/Messaging/Shopping",
            )
        )

    watchlist_totals = context.get("watchlist_totals", {"packages": 0, "files": 0})
    watchlist_lists = context.get("watchlists", [])
    if watchlist_totals.get("packages", 0):
        note = f"{len(watchlist_lists)} list(s)"
        rows_summary.append(
            (
                "Watchlists",
                _format_count(watchlist_totals, "packages"),
                _format_count(watchlist_totals, "files", prefix="~"),
                note,
            )
        )

    rows_summary.extend(
        [
            (
                "Google exceptions",
                _format_count(context["google_exceptions"], "packages"),
                _format_count(context["google_exceptions"], "files", prefix="~"),
                "Allow-list scope",
            ),
            (
                "System families",
                _format_count(context["families"], "packages"),
                _format_count(context["families"], "files", prefix="~"),
                "Android/Google/Motorola",
            ),
            (
                "Everything",
                str(len(rows)),
                _format_count(context["everything"], "files", prefix="~"),
                "Full inventory",
            ),
        ]
    )

    menu_utils.print_table(headers, rows_summary)

    default_stats = context["default_counts"]
    menu_utils.print_hint(
        f"Default scope · {default_stats.get('packages', 0)} pkg(s) / ~{default_stats.get('files', 0)} file(s)"
    )
    if not is_rooted:
        menu_utils.print_hint(
            "System/vendor partitions require root; they are filtered automatically.",
            icon="⚠",
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
