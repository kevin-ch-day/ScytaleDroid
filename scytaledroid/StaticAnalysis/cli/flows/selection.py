"""Scope selection helpers for static analysis CLI."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)

from ...core.repository import (
    ArtifactGroup,
    list_categories,
    list_packages,
    load_display_name_map,
    load_profile_map,
)
from ..core.models import ScopeSelection


def format_scope_target(selection: ScopeSelection) -> str:
    if selection.scope == "app":
        return selection.label
    if selection.scope == "profile":
        return f"Profile: {selection.label}"
    return "All apps"


def select_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    print()
    menu_utils.print_header("Scope", "Select the analysis scope (app, profile, or all)")
    options = {"1": "App", "2": "Profile", "3": "All apps"}
    for key, label in options.items():
        print(f" {key}) {label}")
    choice = prompt_utils.get_choice(list(options.keys()), default="1")

    if choice == "1":
        return select_app_scope(groups)
    if choice == "2":
        return select_category_scope(groups)
    return _select_all_scope(groups)


def _select_all_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    if not groups:
        return ScopeSelection("all", "All apps", tuple())
    grouped, scoped, skipped_details = _collapse_latest_by_package(groups)
    _maybe_prompt_selection_details(grouped, scoped, skipped_details)

    return ScopeSelection("all", "All apps", scoped)


def select_app_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No packages available for analysis.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    print()
    menu_utils.print_header(
        "Static Analysis · Scope (App)",
        "Select a package (latest capture chosen automatically)",
    )
    rows: list[list[str]] = []
    lookup_labels: list[str] = []
    for idx, (package, _version, _count, app_label) in enumerate(packages, start=1):
        display_app = app_label or package
        combined_label = f"{display_app} ({package})" if app_label else package
        rows.append([str(idx), combined_label])
        if app_label:
            lookup_labels.append(f"{app_label} {package}")
        else:
            lookup_labels.append(package)

    table_utils.render_table(["#", "App / Package"], rows, padding=1, compact=True)

    index = _resolve_index(
        "Select package # or name",
        lookup_labels,
    )
    package_name, _, _, app_label = packages[index]
    selection_label = f"{app_label} ({package_name})" if app_label else package_name
    matching_groups = tuple(group for group in groups if group.package_name == package_name)
    scoped = select_latest_groups(matching_groups)
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
        print(status_messages.status("No profile data available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    # Inject Profile v3 cohort as an explicit "profile" choice so operators don't have to use
    # "All apps" and accidentally analyze 100+ packages.
    catalog_path = Path("profiles") / "profile_v3_app_catalog.json"
    catalog = _load_profile_v3_catalog(catalog_path)
    if catalog:
        wanted = set(catalog.keys())
        available = {g.package_name.strip().lower() for g in groups if g.package_name}
        v3_count = len(wanted.intersection(available))
        categories = list(categories) + [("Profile v3 Structural Cohort", v3_count)]

    print()
    print("Static Analysis · Scope (Profile)")
    print("-" * 86)
    rows = [[str(idx), category, str(count)] for idx, (category, count) in enumerate(categories, start=1)]
    table_utils.render_table(["#", "Profile", "Apps"], rows, compact=True)
    print(f"Status: profiles={len(categories)}")

    index = _resolve_index("Select profile #", [category for category, _ in categories])
    category_name, _ = categories[index]
    if category_name == "Profile v3 Structural Cohort":
        return select_profile_v3_scope(groups)
    profile_map = load_profile_map(groups)
    scoped_all = tuple(
        group
        for group in groups
        if (
            profile_map.get(group.package_name.lower())
            or group.category
            or "Uncategorized"
        )
        == category_name
    )
    grouped, scoped, skipped_details = _collapse_latest_by_package(scoped_all)
    _maybe_prompt_selection_details(grouped, scoped, skipped_details)

    if scoped:
        print()
        menu_utils.print_header("Profile selection", f"{category_name} selected (latest capture)")
        _render_profile_selection_table(scoped)
    return ScopeSelection("profile", category_name, scoped)


def _render_profile_selection_table(groups: Sequence[ArtifactGroup]) -> None:
    display_map = load_display_name_map(groups)
    rows: list[list[str]] = []
    for group in groups:
        base_artifact = group.base_artifact or next(iter(group.artifacts), None)
        metadata = getattr(base_artifact, "metadata", {}) if base_artifact else {}
        app_label = metadata.get("app_label") if isinstance(metadata, dict) else None
        display_name = metadata.get("display_name") if isinstance(metadata, dict) else None
        package = group.package_name
        preferred = display_map.get(package.lower())
        label = app_label or display_name or preferred or package
        rows.append([str(label), group.package_name, str(len(group.artifacts))])

    max_rows = 15
    if len(rows) > max_rows:
        table_utils.render_table(
            ["App", "Package", "Artifacts"],
            rows[:max_rows],
        )
        print(f"Showing {max_rows} of {len(rows)} apps.")
        response = prompt_utils.prompt_text(
            "Press L to list all, or Enter to continue",
            required=False,
        ).strip().lower()
        if response == "l":
            table_utils.render_table(
                ["App", "Package", "Artifacts"],
                rows,
            )
            _ = prompt_utils.prompt_text(
                "Press Enter to continue",
                required=False,
            )
    else:
        table_utils.render_table(["App", "Package", "Artifacts"], rows)


def _collapse_latest_by_package(
    groups: Sequence[ArtifactGroup],
) -> tuple[dict[str, list[ArtifactGroup]], tuple[ArtifactGroup, ...], list[tuple[str, str, int]]]:
    grouped: dict[str, list[ArtifactGroup]] = {}
    order: list[str] = []
    for group in groups:
        package = group.package_name
        if package not in grouped:
            grouped[package] = []
            order.append(package)
        grouped[package].append(group)

    collapsed: list[ArtifactGroup] = []
    skipped_details: list[tuple[str, str, int]] = []
    for package in order:
        package_groups = tuple(grouped[package])
        selected = select_latest_groups(package_groups)
        collapsed.extend(selected)
        skipped = len(package_groups) - len(selected)
        if skipped > 0 and selected:
            newest = selected[0]
            stamp = newest.session_stamp or "undated"
            skipped_details.append((package, stamp, skipped))
    return grouped, tuple(collapsed), skipped_details


def _maybe_prompt_selection_details(
    grouped: dict[str, list[ArtifactGroup]],
    scoped: Sequence[ArtifactGroup],
    skipped_details: Sequence[tuple[str, str, int]],
) -> None:
    if not skipped_details:
        return
    total_packages = len(skipped_details)
    total_skipped = sum(count for _, _, count in skipped_details)
    summary = (
        f"Selected newest artifact sets for {total_packages} package"
        f"{'s' if total_packages != 1 else ''} with multiple captures; "
        f"skipped {total_skipped} older capture"
        f"{'s' if total_skipped != 1 else ''}."
    )
    print(status_messages.status(summary, level="info"))
    response = prompt_utils.prompt_text(
        "Press D for selection details, or Enter to continue",
        required=False,
    ).strip().lower()
    if response == "d":
        _render_selection_details(grouped, scoped, skipped_details)


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


def _allow_multiple_latest() -> bool:
    return os.getenv("SCYTALEDROID_STATIC_ALLOW_MULTI_GROUPS", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def select_latest_groups(groups: Sequence[ArtifactGroup]) -> tuple[ArtifactGroup, ...]:
    if not groups:
        return tuple()
    if len(groups) == 1:
        return (groups[0],)

    best_group = max(groups, key=_group_recency_key)
    if _allow_multiple_latest() and best_group.session_stamp:
        contemporaries = [
            group for group in groups if group.session_stamp == best_group.session_stamp
        ]
        if contemporaries:
            return tuple(contemporaries)

    best_mtime = _group_latest_mtime(best_group)
    if _allow_multiple_latest():
        contemporaries = [
            group for group in groups if abs(_group_latest_mtime(group) - best_mtime) < 0.0001
        ]
        return tuple(contemporaries) if contemporaries else (best_group,)
    return (best_group,)


def _render_selection_details(
    grouped: dict[str, list[ArtifactGroup]],
    selected: Sequence[ArtifactGroup],
    skipped_details: Sequence[tuple[str, str, int]],
) -> None:
    print()
    print("Selection details")
    print("-" * 80)
    selected_by_package: dict[str, list[ArtifactGroup]] = {}
    for group in selected:
        selected_by_package.setdefault(group.package_name, []).append(group)

    rows: list[tuple[str, int, dict[str, int], int]] = []
    for package, package_groups in grouped.items():
        selected_groups = selected_by_package.get(package, [])
        selected_artifacts = sum(len(group.artifacts) for group in selected_groups)
        if selected_artifacts <= 0:
            continue
        capture_counts: dict[str, int] = {}
        for group in package_groups:
            capture = str(group.capture_id or group.session_stamp or "unknown")
            capture_counts[capture] = capture_counts.get(capture, 0) + len(group.artifacts)
        skipped = len(package_groups) - len(selected_groups)
        rows.append((package, selected_artifacts, capture_counts, skipped))

    rows.sort(key=lambda row: row[1], reverse=True)
    top_rows = rows[:10]
    if top_rows:
        print("Top packages by selected artifact count:")
        for package, count, capture_counts, skipped in top_rows:
            capture_text = ", ".join(f"{key}={value}" for key, value in sorted(capture_counts.items()))
            suffix = f" | skipped_old={skipped}" if skipped > 0 else ""
            print(f"- {package}: {count} (capture_id: {capture_text}){suffix}")
    else:
        print("- No package selection rows available.")

    total_packages = len(skipped_details)
    total_skipped = sum(count for _, _, count in skipped_details)
    if total_skipped > 0:
        print(
            f"Old captures skipped: {total_skipped} across {total_packages} package"
            f"{'s' if total_packages != 1 else ''}"
        )
    else:
        print("Old captures skipped: none")
    print("Selection manifest path is printed when the scan starts (output/audit/selection/<session>_selected_artifacts.json).")


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


def _load_profile_v3_catalog(path: Path) -> dict[str, dict[str, str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for pkg, meta in payload.items():
        if not isinstance(pkg, str) or not pkg.strip():
            continue
        if not isinstance(meta, dict):
            continue
        out[pkg.strip().lower()] = {
            "app": str(meta.get("app") or "").strip(),
            "app_category": str(meta.get("app_category") or "").strip(),
        }
    return out


def select_profile_v3_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    """Select the Profile v3 structural cohort (catalog-driven).

    This prevents operator error where "All apps" selects 100+ packages and pollutes
    the static analysis DB/session for cohort work.
    """
    catalog_path = Path("profiles") / "profile_v3_app_catalog.json"
    catalog = _load_profile_v3_catalog(catalog_path)
    if not catalog:
        print(
            status_messages.status(
                f"Profile v3 catalog not found or invalid: {catalog_path}",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    wanted = set(catalog.keys())
    scoped_all = tuple(g for g in groups if g.package_name.strip().lower() in wanted)
    if not scoped_all:
        print(
            status_messages.status(
                "No APK artifacts found for Profile v3 cohort in the local library.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    # Deterministic ordering: by catalog category then package.
    scoped_all = tuple(
        sorted(
            scoped_all,
            key=lambda g: (
                catalog.get(g.package_name.strip().lower(), {}).get("app_category", ""),
                g.package_name.strip().lower(),
            ),
        )
    )

    grouped, scoped, skipped_details = _collapse_latest_by_package(scoped_all)
    _maybe_prompt_selection_details(grouped, scoped, skipped_details)

    if scoped:
        print()
        menu_utils.print_header("Profile selection", "Profile v3 Structural Cohort selected (latest capture)")
        _render_profile_selection_table(scoped)

    return ScopeSelection("profile", "Profile v3 Structural Cohort", scoped)


__all__ = [
    "format_scope_target",
    "select_latest_groups",
    "select_scope",
    "select_app_scope",
    "select_category_scope",
    "select_profile_v3_scope",
]
