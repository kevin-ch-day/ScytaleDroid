"""Scope selection helpers for APK harvesting."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from . import rules
from .models import InventoryRow, ScopeSelection
from .scope_context import (
    EXCLUSION_LABELS,
    apply_default_scope,
    build_inventory_rows,
    build_scope_context,
    collect_exclusion_samples,
    estimated_files,
    filter_updated_only,
    sample_names,
)
from .watchlists import Watchlist

_LAST_SCOPE: ScopeSelection | None = None

def _append_non_root_note(label: str) -> str:
    return label


@dataclass(frozen=True)
class _WatchlistEntry:
    watchlist: Watchlist
    filtered: list[InventoryRow]
    excluded: dict[str, int]
    counts: dict[str, int]
    preview: str


def select_package_scope(
    rows: Sequence[InventoryRow],
    *,
    device_serial: str,
    is_rooted: bool,
    google_allowlist: Iterable[str | None] = None,
) -> ScopeSelection | None:
    """Prompt the analyst to choose a harvesting scope and return the filtered list."""

    if not rows:
        print(status_messages.status("No inventory data available for harvest.", level="warn"))
        return None

    allow = set(google_allowlist or rules.GOOGLE_ALLOWLIST)
    context = build_scope_context(rows, allow)
    profile_counts = context["profile_counts"]  # type: ignore[assignment]
    profile_key_groups = _group_by_profile_key(rows)

    watchlist_entries: list[_WatchlistEntry] = context.get("watchlists", [])  # type: ignore[assignment]

    default_rows, _ = apply_default_scope(rows, allow)
    updated_rows, updated_meta = filter_updated_only(rows)
    if not is_rooted:
        readable_updated = [
            row for row in updated_rows if any(rules.is_user_path(path) for path in row.apk_paths)
        ]
        if len(readable_updated) != len(updated_rows):
            updated_meta = dict(updated_meta)
            updated_meta["filtered_non_user"] = len(updated_rows) - len(readable_updated)
        updated_rows = readable_updated

    while True:
        _render_scope_table(rows, device_serial, is_rooted, context, default_rows)

        option_handlers: dict[str, Callable[[], ScopeSelection | None]] = {}
        entries: list[dict[str, object]] = []

        def _add_entry(
            key: str,
            label: str,
            *,
            packages: int | None = None,
            files: int | None = None,
            note: str | None = None,
            handler: Callable[[], ScopeSelection | None] | None = None,
            entries: list[dict[str, object]] = entries,
            option_handlers: dict[str, Callable[[], ScopeSelection | None]] = option_handlers,
        ) -> None:
            entries.append(
                {
                    "key": key,
                    "label": label,
                    "packages": packages,
                    "files": files,
                    "note": note,
                }
            )
            if handler:
                option_handlers[key] = handler

        if _LAST_SCOPE is not None:
            _add_entry(
                "R",
                _format_rerun_label(_LAST_SCOPE),
                note="re-run last scope",
                handler=lambda: _LAST_SCOPE,
            )

        _add_entry(
            "1",
            "Play & user apps",
            packages=context["default_counts"].get("packages"),
            files=context["default_counts"].get("files"),
            note="default",
            handler=lambda: _scope_default(rows, allow),
        )
        updated_note = "updated-only"
        filtered_non_user = updated_meta.get("filtered_non_user")
        if filtered_non_user:
            updated_note = f"{updated_note} (filtered_non_user={filtered_non_user})"
        _add_entry(
            "U",
            "Updated apps only",
            packages=len(updated_rows),
            files=estimated_files(updated_rows),
            note=updated_note,
            handler=lambda: _scope_updated_only(rows, updated_rows, updated_meta),
        )
        if filtered_non_user and not updated_rows:
            print(
                status_messages.status(
                    f"Updated-only filtered out {filtered_non_user} system app(s) "
                    "on non-root devices.",
                    level="info",
                )
            )

        social_rows = profile_key_groups.get("SOCIAL")
        _add_entry(
            "2",
            "Profile: Social",
            packages=len(social_rows) if social_rows else 0,
            handler=lambda: _scope_profile_key_subset(
                rows,
                allow,
                {"SOCIAL"},
                label="Profile: Social",
            ),
        )

        messaging_rows = profile_key_groups.get("MESSAGING")
        _add_entry(
            "3",
            "Profile: Messaging",
            packages=len(messaging_rows) if messaging_rows else 0,
            handler=lambda: _scope_profile_key_subset(
                rows,
                allow,
                {"MESSAGING"},
                label="Profile: Messaging",
            ),
        )

        combined_rows = (social_rows or []) + (messaging_rows or [])
        _add_entry(
            "4",
            "Profile: Social + Messaging",
            packages=len(combined_rows) if combined_rows else 0,
            note="profile",
            handler=lambda: _scope_profile_key_subset(
                rows,
                allow,
                {"SOCIAL", "MESSAGING"},
                label="Profile: Social + Messaging",
            ),
        )

        _add_entry(
            "5",
            "Profile: Google user",
            packages=context["google_user"].get("packages"),
            files=context["google_user"].get("files"),
            note="profile",
            handler=lambda: _scope_google_user_apps(rows, allow),
        )

        if profile_counts:
            _add_entry(
                "6",
                "Target profiles",
                packages=context["profile_summary"].get("packages"),
                files=context["profile_summary"].get("files"),
                note="SOCIAL/MESSAGING/MEDIA/BROWSER/PRODUCTIVITY/SHOPPING/NEWS",
                handler=lambda: _scope_profiles(rows, profile_counts, allow),
            )

        if watchlist_entries:
            for idx, entry in enumerate(watchlist_entries, start=1):
                key = f"W{idx}"
                _add_entry(
                    key,
                    f"Watchlist · {entry.watchlist.name}",
                    packages=entry.counts.get("packages"),
                    files=entry.counts.get("files"),
                    note=_format_watchlist_hint(entry),
                    handler=lambda e=entry: _scope_watchlist(e),
                )

        _add_entry(
            "7",
            "Google allow-list",
            packages=context["google_exceptions"].get("packages"),
            files=context["google_exceptions"].get("files"),
            note="allow-list",
            handler=lambda: _scope_google_allowlist(rows, allow),
        )
        _add_entry(
            "8",
            "System families",
            packages=context["families"].get("packages"),
            files=context["families"].get("files"),
            note="root required",
            handler=lambda: _scope_families(rows),
        )
        _add_entry(
            "9",
            "Custom patterns",
            note="pattern list (comma, * prefix)",
            handler=lambda: _scope_custom(rows, allow),
        )
        _add_entry(
            "E",
            "Everything (policy-filtered)" if not is_rooted else "Everything",
            packages=context["everything"].get("packages"),
            files=context["everything"].get("files"),
            note="policy-filtered" if not is_rooted else None,
            handler=lambda: ScopeSelection(
                label="Everything",
                packages=list(rows),
                kind="everything",
                metadata={
                    "estimated_files": context["everything"].get("files", 0),
                    "candidate_count": len(rows),
                    "selected_count": len(rows),
                    "policy": "non_root_paths" if not is_rooted else "none",
                },
            ),
        )

        headers = ["#", "Scope", "Pkgs", "Files", "Notes"]
        table_rows = []
        for entry in entries:
            key = str(entry["key"])
            label = entry["label"]
            packages = entry.get("packages")
            files = entry.get("files")
            note = entry.get("note") or ""
            pkg_cell = packages if isinstance(packages, int) else ""
            files_cell = f"~{files}" if isinstance(files, int) and files else ""
            table_rows.append([key, label, pkg_cell, files_cell, note])

        table_utils.render_table(headers, table_rows, compact=True)
        print("0 back")

        choice = prompt_utils.get_choice(
            [str(entry["key"]) for entry in entries] + ["0"],
            default="1",
            casefold=True,
            prompt="Select scope #: ",
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

        _print_selection_diagnostics(selection)
        _store_last_scope(selection)
        return selection


def select_package_scope_auto(
    rows: Sequence[InventoryRow],
    *,
    device_serial: str,
    is_rooted: bool,
    google_allowlist: Iterable[str | None] = None,
) -> ScopeSelection | None:
    """Select a smart default scope without prompting (updated-only when possible)."""
    if not rows:
        print(status_messages.status("No inventory data available for harvest.", level="warn"))
        return None

    allow = set(google_allowlist or rules.GOOGLE_ALLOWLIST)
    updated_rows, updated_meta = filter_updated_only(rows)
    if not is_rooted:
        readable_updated = [
            row for row in updated_rows if any(rules.is_user_path(path) for path in row.apk_paths)
        ]
        if len(readable_updated) != len(updated_rows):
            updated_meta = dict(updated_meta)
            updated_meta["filtered_non_user"] = len(updated_rows) - len(readable_updated)
        updated_rows = readable_updated

    if updated_rows:
        selection = _scope_updated_only(rows, updated_rows, updated_meta)
        selection.metadata["auto_scope_reason"] = "updated_only"
        return selection

    if _LAST_SCOPE is not None:
        selection = ScopeSelection(
            label=_LAST_SCOPE.label,
            packages=list(_LAST_SCOPE.packages),
            kind=_LAST_SCOPE.kind,
            metadata=dict(_LAST_SCOPE.metadata),
        )
        selection.metadata["auto_scope_reason"] = "last_scope"
        return selection

    selection = _scope_default(rows, allow)
    selection.metadata["auto_scope_reason"] = "default_scope"
    return selection


def _render_scope_table(
    rows: Sequence[InventoryRow],
    device_serial: str,
    is_rooted: bool,
    context: dict[str, object],
    default_rows: Sequence[InventoryRow],
) -> None:
    mode_label = "root" if is_rooted else "non-root"
    print("Pull APKs")
    print(f"Device ({device_serial} • {mode_label})")
    candidates = len(rows)
    eligible = candidates if is_rooted else sum(
        1 for row in rows if any(rules.is_user_path(path) for path in row.apk_paths)
    )
    blocked = max(candidates - eligible, 0)
    policy = "none" if is_rooted else "non_root_paths"
    print(
        f"Status: candidates {candidates} | eligible (policy) {eligible} | "
        f"blocked {blocked} | policy {policy}"
    )
    print("-" * 86)


def _format_rerun_label(selection: ScopeSelection) -> str:
    pkg_count = len(selection.packages)
    return f"Re-run last scope ({selection.label} – {pkg_count} pkg(s))"


def _format_menu_count(stats: dict[str, int]) -> str:
    packages = stats.get("packages", 0)
    files = stats.get("files", 0)
    return f"{packages} pkg(s) · ~{files} file(s)"


def _format_watchlist_hint(entry: _WatchlistEntry) -> str | None:
    if not entry.preview:
        return None
    if len(entry.filtered) > 3:
        return f"Preview: {entry.preview}, …"
    return f"Preview: {entry.preview}"


def _scope_default(rows: Sequence[InventoryRow], allow: set[str]) -> ScopeSelection:
    selected, excluded = apply_default_scope(rows, allow)
    excluded_samples = collect_exclusion_samples(rows, selected, allow)
    metadata = {
        "estimated_files": estimated_files(selected),
        "allowlist_size": len(allow),
        "excluded_counts": excluded,
        "sample_names": sample_names(selected),
        "excluded_samples": excluded_samples,
        "candidate_count": len(rows),
        "selected_count": len(selected),
    }
    return ScopeSelection("Play Store & user-installed", selected, "default", metadata)


def _scope_updated_only(
    rows: Sequence[InventoryRow],
    updated_rows: Sequence[InventoryRow],
    meta: dict[str, int],
) -> ScopeSelection:
    metadata = {
        "estimated_files": estimated_files(updated_rows),
        "candidate_count": len(rows),
        "selected_count": len(updated_rows),
        "updated_only": True,
        "updated_missing_repo": meta.get("missing_repo", 0),
        "updated_version_mismatch": meta.get("version_mismatch", 0),
        "updated_version_match": meta.get("version_match", 0),
    }
    return ScopeSelection("Updated apps only", list(updated_rows), "updated_only", metadata)


def _scope_profiles(
    rows: Sequence[InventoryRow],
    profile_counts: Counter[str],
    allow: set[str],
) -> ScopeSelection | None:
    if not profile_counts:
        print(status_messages.status("No profiled packages available.", level="warn"))
        return None

    print()
    menu_utils.print_header("Choose profile(s)")
    target_profiles = {"SOCIAL", "MESSAGING", "MEDIA", "BROWSER", "PRODUCTIVITY", "SHOPPING", "NEWS"}
    sorted_profiles = sorted(
        [(name, count) for name, count in profile_counts.items() if name in target_profiles],
        key=lambda item: (-item[1], item[0].lower()),
    )
    profile_menu: dict[str, str] = {}
    for index, (profile, count) in enumerate(sorted_profiles, start=1):
        profile_menu[str(index)] = f"{profile} ({count})"
    profile_menu["A"] = "All profiles"

    menu_utils.print_menu(profile_menu, is_main=False)
    raw = prompt_utils.prompt_text("Selection (e.g., 1,3 or A)", default="", required=False).strip()
    if not raw:
        print(status_messages.status("Profile selection cancelled.", level="warn"))
        return None

    if raw.upper() == "A":
        selected = {name for name, _ in sorted_profiles}
    else:
        tokens = {token.strip() for token in re.split(r"[,\s]+", raw) if token.strip()}
        selected: set[str] = set()
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

    profile_rows = [
        row
        for row in rows
        if (row.profile_key or "").upper() in selected
    ]
    if not profile_rows:
        print(status_messages.status("No packages matched the selected profiles.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(profile_rows, allow)
    excluded_samples = collect_exclusion_samples(profile_rows, filtered, allow)
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
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": excluded_samples,
        "candidate_count": len(profile_rows),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"Profiles: {', '.join(sorted(selected))}",
        packages=filtered,
        kind="profiles",
            metadata=metadata,
        )


def _scope_google_user_apps(
    rows: Sequence[InventoryRow], allow: set[str]
) -> ScopeSelection | None:
    candidates = [row for row in rows if rules.is_google_user_app(row.package_name)]
    if not candidates:
        print(status_messages.status("No Google user apps present on device.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(candidates, allow)
    if not filtered:
        print(
            status_messages.status(
                "Google user apps present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "candidate_count": len(candidates),
        "selected_count": len(filtered),
    }
    return ScopeSelection("Google user apps", filtered, "google_user", metadata)


def _scope_profile_subset(
    rows: Sequence[InventoryRow],
    allow: set[str],
    profiles: set[str],
    *,
    label: str,
) -> ScopeSelection | None:
    normalized = {profile.lower() for profile in profiles}
    subset = [row for row in rows if row.profile and row.profile.lower() in normalized]
    if not subset:
        print(status_messages.status(f"No packages tagged as {label}.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(subset, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{label} packages present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "profiles": sorted({row.profile for row in subset if row.profile}),
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "candidate_count": len(subset),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"{label} apps",
        packages=filtered,
        kind="profile_subset",
        metadata=metadata,
    )


def _scope_profile_key_subset(
    rows: Sequence[InventoryRow],
    allow: set[str],
    profiles: set[str],
    *,
    label: str,
) -> ScopeSelection | None:
    normalized = {profile.upper() for profile in profiles}
    subset = [row for row in rows if (row.profile_key or "").upper() in normalized]
    if not subset:
        print(status_messages.status(f"No packages tagged as {label}.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(subset, allow)
    if not filtered:
        print(
            status_messages.status(
                f"{label} packages present but filtered by scope policy.", level="warn"
            )
        )
        return None

    metadata = {
        "profiles": sorted({(row.profile_key or "").upper() for row in subset if row.profile_key}),
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "candidate_count": len(subset),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"{label} apps",
        packages=filtered,
        kind="profile_key_subset",
        metadata=metadata,
    )


def _scope_category_subset(
    category_groups: dict[str, list[InventoryRow]],
    allow: set[str],
    categories: set[str],
    *,
    label: str | None = None,
) -> ScopeSelection | None:
    combined: list[InventoryRow] = []
    for category in categories:
        combined.extend(category_groups.get(category, []))
    if not combined:
        print(status_messages.status(f"No packages tagged as {', '.join(categories)}.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(combined, allow)
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
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        # Capture how many candidates existed vs how many survive policy filters.
        "candidate_count": len(combined),
        "selected_count": len(filtered),
    }
    return ScopeSelection(
        label=f"{scope_label} apps",
        packages=filtered,
        kind="category_subset",
        metadata=metadata,
    )


def _group_by_profile_key(rows: Sequence[InventoryRow]) -> dict[str, list[InventoryRow]]:
    grouped: dict[str, list[InventoryRow]] = {}
    for row in rows:
        key = (row.profile_key or "").strip().upper()
        if not key:
            continue
        grouped.setdefault(key, []).append(row)
    return grouped


def _scope_watchlist(entry: _WatchlistEntry) -> ScopeSelection | None:
    if not entry.filtered:
        print(status_messages.status("Watchlist contains no packages in scope.", level="warn"))
        return None
    metadata = {
        "watchlist": entry.watchlist.name,
        "watchlist_path": str(entry.watchlist.path),
        "estimated_files": entry.counts.get("files", 0),
        "excluded_counts": entry.excluded,
        "sample_names": sample_names(entry.filtered),
        "candidate_count": entry.counts.get("packages", 0) + sum(entry.excluded.values()),
        "selected_count": len(entry.filtered),
    }
    return ScopeSelection(
        label=f"Watchlist: {entry.watchlist.name}",
        packages=list(entry.filtered),
        kind="watchlist",
        metadata=metadata,
    )


def _scope_google_allowlist(
    rows: Sequence[InventoryRow], allow: set[str]
) -> ScopeSelection | None:
    candidates = [row for row in rows if row.package_name in allow]
    if not candidates:
        print(status_messages.status("No Google allow-list packages found in inventory.", level="warn"))
        return None
    filtered, excluded = apply_default_scope(candidates, allow)
    if not filtered:
        message = (
            "Google allow-list packages present but filtered by scope policy."
            if excluded
            else "No Google allow-list packages matched the current scope."
        )
        print(status_messages.status(message, level="warn"))
        return None
    excluded_samples = collect_exclusion_samples(candidates, filtered, allow)
    metadata = {
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": excluded_samples,
        "candidate_count": len(candidates),
        "selected_count": len(filtered),
    }
    return ScopeSelection("Google exceptions", filtered, "google_allow", metadata)


def _scope_families(rows: Sequence[InventoryRow]) -> ScopeSelection | None:
    filtered = [row for row in rows if rules.family(row.package_name) in {"android", "google", "motorola"}]
    if not filtered:
        print(status_messages.status("No Android/Google/Motorola packages found.", level="warn"))
        return None
    excluded_samples: dict[str, list[str]] = {}
    metadata = {
        "estimated_files": estimated_files(filtered),
        "sample_names": sample_names(filtered),
        "candidate_count": len(filtered),
        "selected_count": len(filtered),
        "excluded_counts": {},
        "excluded_samples": excluded_samples,
    }
    return ScopeSelection("System families", filtered, "families", metadata)


def _scope_custom(rows: Sequence[InventoryRow], allow: set[str]) -> ScopeSelection | None:
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

    matches: list[InventoryRow] = []
    for row in rows:
        name = row.package_name.lower()
        if any(_pattern_matches(pattern, name) for pattern in patterns):
            matches.append(row)

    if not matches:
        print(status_messages.status("No packages matched the provided patterns.", level="warn"))
        return None

    filtered, excluded = apply_default_scope(matches, allow)
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
        "estimated_files": estimated_files(filtered),
        "excluded_counts": excluded,
        "sample_names": sample_names(filtered),
        "excluded_samples": collect_exclusion_samples(matches, filtered, allow),
        "candidate_count": len(matches),
        "selected_count": len(filtered),
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


def _format_count(stats: object, key: str, *, prefix: str = "") -> str:
    if isinstance(stats, dict):
        value = int(stats.get(key, 0))
    else:
        value = 0
    unit = "pkg(s)" if key == "packages" else "file(s)"
    return f"{prefix}{value} {unit}"


def _format_count_summary(rows: Sequence[InventoryRow | None]) -> str:
    if not rows:
        return "0 pkg(s)"
    return f"{len(rows)} pkg(s)"


def _print_selection_diagnostics(selection: ScopeSelection) -> None:
    """
    Explain how a chosen scope shrank from all candidates to the kept set, with reasons.
    Always-on so operators see why a category collapsed.
    """
    meta = selection.metadata or {}
    if not meta.get("show_details"):
        return
    excluded_counts = meta.get("excluded_counts") or {}
    selected = int(meta.get("selected_count") or len(selection.packages) or 0)
    candidates = int(meta.get("candidate_count") or 0)
    if not candidates:
        candidates = selected + sum(int(v) for v in excluded_counts.values())
    if not candidates:
        return
    filtered = max(candidates - selected, 0)
    breakdown = []
    for reason, count in sorted(excluded_counts.items()):
        if not count:
            continue
        label = EXCLUSION_LABELS.get(reason, reason)
        breakdown.append(f"{label}={count}")
    detail = f"{selection.label}: candidates={candidates} • kept={selected} • filtered={filtered}"
    if breakdown:
        detail = f"{detail} ({'; '.join(breakdown)})"
    print(status_messages.status(detail, level="info"))


def _scope_option_label(
    title: str,
    *,
    packages: int | None = None,
    files: int | None = None,
    note: str | None = None,
) -> str:
    parts: list[str] = [title]
    metrics: list[str] = []
    if packages is not None:
        metrics.append(f"{packages} pkg(s)")
    if files is not None:
        metrics.append(f"~{files} file(s)")
    if metrics:
        parts.append("· " + " · ".join(metrics))
    if note:
        parts.append(f"— {note}")
    return " ".join(parts)


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
    context: dict[str, object],
) -> None:
    print()
    menu_utils.print_header(
        "Package Scope Overview",
        subtitle=f"{device_serial} · {'root' if is_rooted else 'non-root'}",
    )
    headers = ("Subset", "Packages", "Artifacts", "Notes")
    rows_summary: list[tuple[str, str, str, str]] = [
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
    default_excluded = context.get("default_excluded") or {}
    if default_excluded:
        filtered_bits = []
        for reason, count in sorted(default_excluded.items()):
            label = EXCLUSION_LABELS.get(reason, reason)
            filtered_bits.append(f"{label}={count}")
        if filtered_bits:
            print(status_messages.status("Default scope filters:", level="info"))
            for bit in filtered_bits:
                print(status_messages.status(f"  • {bit}", level="info"))
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
