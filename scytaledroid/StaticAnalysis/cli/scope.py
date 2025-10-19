"""Scope selection helpers for static analysis CLI."""

from __future__ import annotations

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
    rows = [[str(idx), package, version] for idx, (package, version, _count) in enumerate(packages, start=1)]
    table_utils.render_table(["#", "Package", "Version"], rows)

    index = _resolve_index(
        "Select package # or name",
        [package for package, _version, _count in packages],
    )
    package_name, _, _ = packages[index]
    scoped = tuple(group for group in groups if group.package_name == package_name)
    return ScopeSelection("app", package_name, scoped)


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


__all__ = [
    "format_scope_target",
    "select_scope",
    "select_app_scope",
    "select_category_scope",
]


