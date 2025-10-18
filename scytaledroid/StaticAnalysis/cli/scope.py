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
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(packages) + 1)],
        prompt="Select package #: ",
        default="1",
    )
    package_name, _, _ = packages[int(choice) - 1]
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
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(categories) + 1)],
        prompt="Select category #: ",
        default="1",
    )
    category_name, _ = categories[int(choice) - 1]
    scoped = tuple(group for group in groups if getattr(group, "category", None) == category_name)
    return ScopeSelection("category", category_name, scoped)


__all__ = [
    "format_scope_target",
    "select_scope",
    "select_app_scope",
    "select_category_scope",
]

