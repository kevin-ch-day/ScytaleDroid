"""Scope selection helpers for static analysis CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Tuple

from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)

from ..core.repository import ArtifactGroup, list_categories, list_packages
from .models import ScopeSelection


def format_scope_target(selection: ScopeSelection) -> str:
    if selection.scope == "app":
        return f"App={selection.label}"
    if selection.scope == "category":
        return f"Category={selection.label}"
    return "All apps"


def select_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    print()
    menu_utils.print_header("Scope", "Select the analysis scope")
    options = {"1": "App", "2": "Category", "3": "All apps"}
    for key, label in options.items():
        print(f" {key}) {label}")
    choice = prompt_utils.get_choice(list(options.keys()), default="1")

    if choice == "1":
        return select_app_scope(groups)
    if choice == "2":
        return select_category_scope(groups)
    return ScopeSelection("all", "All apps", tuple(groups))


def select_app_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No packages available for analysis.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    print()
    menu_utils.print_header("Scope — App", "Select 1 package")
    rows: list[list[str]] = []
    lookup_labels: list[str] = []
    for idx, (package, version, _count, app_label) in enumerate(packages, start=1):
        display_app = app_label or package
        combined_label = f"{display_app} ({package})" if app_label else package
        rows.append([str(idx), combined_label])
        if app_label:
            lookup_labels.append(f"{app_label} {package}")
        else:
            lookup_labels.append(package)

    table_utils.render_table(["#", "App / Package"], rows, padding=1)

    index = _resolve_index(
        "Select package # or name",
        lookup_labels,
    )
    package_name, _, _, app_label = packages[index]
    selection_label = f"{app_label} ({package_name})" if app_label else package_name
    matching_groups = tuple(group for group in groups if group.package_name == package_name)
    scoped = _select_latest_groups(matching_groups)
    skipped = len(matching_groups) - len(scoped)
    if skipped > 0:
        newest = scoped[0]
        stamp = newest.session_stamp or "undated"
        message = (
            f"Selected newest artifact set for {package_name} (session {stamp}); "
            f"skipped {skipped} older capture{'s' if skipped != 1 else ''}."
        )
        print(status_messages.status(message, level="info"))
    return ScopeSelection("app", selection_label, scoped)


def select_category_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    categories = list_categories(groups)
    if not categories:
        print(status_messages.status("No category data available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    print()
    menu_utils.print_header("Scope — Category", "Select category")
    rows = [[str(idx), category, str(count)] for idx, (category, count) in enumerate(categories, start=1)]
    table_utils.render_table(["#", "Category", "Apps"], rows)

    index = _resolve_index("Select category # or name", [category for category, _ in categories])
    category_name, _ = categories[index]
    scoped = tuple(group for group in groups if getattr(group, "category", None) == category_name)
    return ScopeSelection("category", category_name, scoped)


def _resolve_index(prompt: str, labels: Sequence[str]) -> int:
    valid_range = f"1..{len(labels)}"
    while True:
        response = prompt_utils.prompt_text(
            prompt,
            default="1",
            required=False,
        ).strip()
        if not response:
            response = "1"

        if response.isdigit():
            idx = int(response)
            if 1 <= idx <= len(labels):
                return idx - 1
            print(
                status_messages.status(
                    f"Choice {response} is out of range ({valid_range}).",
                    level="warn",
                )
            )
            continue

        lowered = response.lower()
        matches = [i for i, label in enumerate(labels) if lowered in label.lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            print(
                status_messages.status(
                    f"No match for '{response}'. Enter a number within {valid_range} or a matching name.",
                    level="warn",
                )
            )
            continue

        hint = ", ".join(f"{i + 1}:{labels[i]}" for i in matches[:5])
        print(
            status_messages.status(
                f"Ambiguous input. Matches: {hint}.",
                level="warn",
            )
        )


def _select_latest_groups(groups: Sequence[ArtifactGroup]) -> Tuple[ArtifactGroup, ...]:
    if not groups:
        return tuple()
    if len(groups) == 1:
        return (groups[0],)

    best_group = max(groups, key=_group_recency_key)
    if best_group.session_stamp:
        contemporaries = [group for group in groups if group.session_stamp == best_group.session_stamp]
        if contemporaries:
            return tuple(contemporaries)

    best_mtime = _group_latest_mtime(best_group)
    contemporaries = [
        group for group in groups if abs(_group_latest_mtime(group) - best_mtime) < 0.0001
    ]
    return tuple(contemporaries) if contemporaries else (best_group,)


def _group_recency_key(group: ArtifactGroup) -> tuple[int, str, float]:
    stamp = group.session_stamp or ""
    return (1 if stamp else 0, stamp, _group_latest_mtime(group))


def _group_latest_mtime(group: ArtifactGroup) -> float:
    return max((_artifact_mtime(artifact) for artifact in group.artifacts), default=0.0)


def _artifact_mtime(artifact) -> float:
    path_obj = getattr(artifact, "path", None)
    if isinstance(path_obj, Path):
        target = path_obj
    elif isinstance(path_obj, str):
        target = Path(path_obj)
    else:
        return 0.0
    try:
        return float(target.stat().st_mtime)
    except (OSError, ValueError):
        return 0.0


__all__ = [
    "format_scope_target",
    "select_scope",
    "select_app_scope",
    "select_category_scope",
]
