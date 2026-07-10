"""Scope selection helpers for static analysis CLI."""

from __future__ import annotations

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
from .profile_prior_session import (
    PriorProfileSessionSnapshot,
    fetch_prior_profile_session_snapshot,
)

_INACTIVE_PROFILE_LABELS = frozenset({"Profile v3 Structural Cohort"})
_RESEARCH_PROFILE_LABELS = frozenset({"Research Dataset Alpha", "Research Dataset Beta"})

_DEFAULT_CAPTURE_RULE = "Newest harvest capture per package"
# Future selection modes (longitudinal / per-app capture / base-only / completeness filters)
# should extend ScopeSelection metadata and this module without renaming operator-visible harvest terms.


def _research_profile_labels() -> set[str]:
    labels = {label.casefold() for label in _RESEARCH_PROFILE_LABELS}
    try:
        from scytaledroid.Database.db_func.research_cohorts import list_active_research_cohorts

        for row in list_active_research_cohorts():
            label = str(row.get("display_name") or "").strip()
            if label:
                labels.add(label.casefold())
    except Exception:
        pass
    return labels


def _is_research_profile_entry(*, label: object = None, profile_key: object = None, cohort_key: object = None) -> bool:
    normalized_label = str(label or "").strip().casefold()
    normalized_profile_key = str(profile_key or "").strip().upper()
    normalized_cohort_key = str(cohort_key or "").strip().lower()
    if normalized_label and normalized_label in _research_profile_labels():
        return True
    if normalized_profile_key.startswith("RESEARCH_DATASET_"):
        return True
    if normalized_cohort_key.startswith("research_dataset_"):
        return True
    return False


def _build_profile_options(groups: Sequence[ArtifactGroup]) -> list[dict[str, object]]:
    categories = [
        (category, count)
        for category, count in list_categories(groups)
        if category not in _INACTIVE_PROFILE_LABELS
        and not _is_research_profile_entry(label=category)
    ]
    options: list[dict[str, object]] = [
        {
            "label": category,
            "count": int(count),
            "profile_key": None,
            "packages": None,
        }
        for category, count in categories
    ]
    seen_labels = {str(item["label"]).casefold() for item in options}

    try:
        from scytaledroid.DynamicAnalysis import profile_loader

        db_profiles = profile_loader.load_operational_profiles()
    except Exception:
        db_profiles = []

    available_packages = {
        str(getattr(group, "package_name", "") or "").strip().lower()
        for group in groups
        if str(getattr(group, "package_name", "") or "").strip()
    }
    for profile in db_profiles:
        label = str(profile.get("display_name") or profile.get("profile_key") or "").strip()
        profile_key = str(profile.get("profile_key") or "").strip()
        if (
            not label
            or not profile_key
            or label in _INACTIVE_PROFILE_LABELS
            or _is_research_profile_entry(
                label=label,
                profile_key=profile_key,
                cohort_key=profile.get("cohort_key"),
            )
        ):
            continue
        try:
            from scytaledroid.DynamicAnalysis import profile_loader

            packages = {
                str(package).strip().lower()
                for package in profile_loader.load_profile_packages(profile_key)
                if str(package).strip()
            }
        except Exception:
            packages = set()
        available_count = len(available_packages.intersection(packages))
        if available_count <= 0:
            continue
        label_key = label.casefold()
        if label_key in seen_labels:
            for item in options:
                if str(item["label"]).casefold() == label_key:
                    if not item.get("profile_key"):
                        item["profile_key"] = profile_key
                        item["packages"] = packages
                    item["count"] = max(int(item.get("count") or 0), available_count)
                    break
            continue
        seen_labels.add(label_key)
        options.append(
            {
                "label": label,
                "count": available_count,
                "profile_key": profile_key,
                "packages": packages,
            }
        )

    options.sort(key=lambda item: str(item["label"]).casefold())
    return options


def _print_workload_summary_lines(
    *,
    profile_title: str,
    scoped: Sequence[ArtifactGroup],
    older_excluded: int,
    rule_line: str,
    scope_noun: str = "Profile",
) -> None:
    _ = scoped, older_excluded, rule_line
    print(f"{scope_noun}: {profile_title}")
    print("Newest harvested capture per package is selected automatically.")


def _print_prior_profile_session_snapshot(snapshot: PriorProfileSessionSnapshot | None) -> None:
    if snapshot is None:
        return
    lw = 24
    pad = "  "
    print()
    print(f"{pad}{'Previous static session':<{lw}}: {snapshot.session_stamp}")
    print(f"{pad}{'Static runs':<{lw}}: {snapshot.static_runs}")
    print(f"{pad}{'Findings':<{lw}}: {snapshot.findings_count}")
    print(f"{pad}{'Permissions':<{lw}}: {snapshot.permissions_count}")
    print(f"{pad}{'Handoff rows':<{lw}}: {snapshot.handoff_rows}")
    ready, total = snapshot.dynamic_ready
    print(f"{pad}{'Dynamic-ready apps':<{lw}}: {ready}/{total}")


def format_scope_target(selection: ScopeSelection) -> str:
    if selection.scope == "app":
        return selection.label
    if selection.scope == "profile":
        return f"Profile: {selection.label}"
    return "All apps"


def select_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    print()
    menu_utils.print_header("Scope", "Select the analysis scope (app, profile, or all)")
    menu_utils.print_hint(
        "Choose a single app, a profile cohort, or all harvested APK groups before building the static run spec."
    )
    options: list[tuple[str, str]] = [("1", "App"), ("2", "Profile"), ("3", "All apps")]
    menu_utils.print_section("Actions")
    menu_utils.print_menu(options, show_exit=False, show_descriptions=False, compact=True)
    choice = prompt_utils.get_choice([key for key, _ in options], default="1")

    if choice == "1":
        return select_app_scope(groups)
    if choice == "2":
        return select_category_scope(groups)
    return _select_all_scope(groups)


def _select_all_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    if not groups:
        return ScopeSelection("all", "All apps", tuple())
    _grouped, scoped, skipped_details = _collapse_latest_by_package(groups)
    older_excluded = sum(count for _, _, count in skipped_details)

    return ScopeSelection(
        "all",
        "All apps",
        scoped,
        older_captures_excluded=older_excluded,
        selection_rule_summary=_DEFAULT_CAPTURE_RULE,
    )


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
    menu_utils.print_hint("The newest harvested capture is chosen automatically when multiple artifact groups exist for a package.")
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
            f"Selected newest harvest capture for {package_name} (session {stamp}); "
            f"excluded {skipped} older capture{'s' if skipped != 1 else ''} from this run."
        )
        print(status_messages.status(message, level="info"))
    return ScopeSelection(
        "app",
        selection_label,
        scoped,
        older_captures_excluded=skipped,
        selection_rule_summary="Newest harvest capture for selected package",
    )


def select_category_scope(groups: Sequence[ArtifactGroup]) -> ScopeSelection:
    profile_options = _build_profile_options(groups)
    if not profile_options:
        print(status_messages.status("No profile data available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return ScopeSelection("all", "All apps", tuple(groups))

    print()
    menu_utils.print_header(
        "Static Analysis · Select Profile",
        "Profiles are package cohorts. Runs use the newest harvest per app (base + split APKs); "
        "the next screen summarizes workload.",
    )
    print()
    rows = [
        [str(idx), str(item["label"]), str(int(item["count"]))]
        for idx, item in enumerate(profile_options, start=1)
    ]
    table_utils.render_table(["#", "Profile", "Apps"], rows, compact=True, padding=2)
    print()
    print(f"Profiles: {len(profile_options)}")

    if len(profile_options) == 1:
        selected = profile_options[0]
        category_name = str(selected["label"])
        print(
            status_messages.status(
                f"Only one active profile is available; selecting {category_name}.",
                level="info",
            )
        )
        return resolve_profile_scope(
            groups,
            category_name,
            profile_key=str(selected.get("profile_key") or "") or None,
            packages=selected.get("packages"),
        )

    index = _resolve_index("Select profile #", [str(item["label"]) for item in profile_options])
    selected = profile_options[index]
    category_name = str(selected["label"])
    return resolve_profile_scope(
        groups,
        category_name,
        profile_key=str(selected.get("profile_key") or "") or None,
        packages=selected.get("packages"),
    )


def resolve_profile_scope(
    groups: Sequence[ArtifactGroup],
    category_name: str,
    *,
    profile_key: str | None = None,
    packages: object | None = None,
) -> ScopeSelection:
    package_filter = {
        str(package).strip().lower()
        for package in (packages or set())
        if str(package).strip()
    }
    if profile_key and package_filter:
        scoped_all = tuple(
            group
            for group in groups
            if str(getattr(group, "package_name", "") or "").strip().lower() in package_filter
        )
    else:
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
    _grouped, scoped, skipped_details = _collapse_latest_by_package(scoped_all)
    older_excluded = sum(count for _, _, count in skipped_details)

    if scoped:
        print()
        menu_utils.print_header(
            "Static Analysis · Profile Workload",
            "Review the cohort list; final package and APK totals are in Run Setup.",
        )
        _print_workload_summary_lines(
            profile_title=category_name,
            scoped=scoped,
            older_excluded=older_excluded,
            rule_line=_DEFAULT_CAPTURE_RULE,
        )
        cohort_packages = frozenset(
            g.package_name.strip().lower()
            for g in scoped
            if str(getattr(g, "package_name", "") or "").strip()
        )
        _print_prior_profile_session_snapshot(
            fetch_prior_profile_session_snapshot(category_name, cohort_packages)
        )
        print()
        _render_profile_selection_table(scoped)
        print()
        print("Final package and APK totals depend on preset and split scan settings; Run Setup shows the exact counts.")
    return ScopeSelection(
        "profile",
        category_name,
        scoped,
        older_captures_excluded=older_excluded,
        selection_rule_summary=_DEFAULT_CAPTURE_RULE,
    )


def _render_profile_selection_table(
    groups: Sequence[ArtifactGroup],
    *,
    label_overrides: dict[str, str] | None = None,
) -> None:
    display_map = load_display_name_map(groups)
    overrides = {str(k).strip().lower(): str(v).strip() for k, v in (label_overrides or {}).items() if str(k).strip()}
    rows: list[list[str]] = []
    for group in groups:
        base_artifact = group.base_artifact or next(iter(group.artifacts), None)
        metadata = getattr(base_artifact, "metadata", {}) if base_artifact else {}
        app_label = metadata.get("app_label") if isinstance(metadata, dict) else None
        display_name = metadata.get("display_name") if isinstance(metadata, dict) else None
        package = group.package_name
        preferred = display_map.get(package.lower())
        override = overrides.get(package.lower())
        label = override or app_label or display_name or preferred or package
        split_n = sum(1 for a in group.artifacts if getattr(a, "is_split_member", False))
        total_a = len(group.artifacts)
        base_n = total_a - split_n
        if split_n > 0:
            breakdown = f"{total_a} ({base_n} base + {split_n} split)"
        else:
            breakdown = str(total_a)
        rows.append([str(label), group.package_name, breakdown])

    # Operator UX: for paper cohorts (<= ~30 apps), show the full list to avoid
    # confusion ("Showing 15 of 21") and extra prompts mid-demo.
    if len(rows) <= 30:
        table_utils.render_table(["App", "Package", "APK files"], rows)
        return

    max_rows = 15
    table_utils.render_table(["App", "Package", "APK files"], rows[:max_rows])
    print(f"Showing {max_rows} of {len(rows)} apps.")
    response = prompt_utils.prompt_text(
        "Press L to list all, or Enter to continue",
        required=False,
    ).strip().lower()
    if response == "l":
        table_utils.render_table(["App", "Package", "APK files"], rows)
        _ = prompt_utils.prompt_text("Press Enter to continue", required=False)


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
    # Paper-grade runs should be deterministic and not influenced by environment toggles
    # that widen the selected cohort inputs.
    strict = os.getenv("SCYTALEDROID_PAPER_STRICT", "0").strip().lower() in {"1", "true", "yes", "on"}
    if strict:
        return False
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

    if _allow_multiple_latest():
        # Prefer deterministic contemporaries: same recency key prefix (capture day + version_code + stamp).
        best_key = _group_recency_key(best_group)
        prefix = best_key[:6]
        contemporaries = [group for group in groups if _group_recency_key(group)[:6] == prefix]
        return tuple(contemporaries) if contemporaries else (best_group,)
    return (best_group,)
def _group_recency_key(group: ArtifactGroup) -> tuple[int, str, float]:
    """Deterministic ordering key for "latest" group selection.

    Avoid relying on filesystem mtimes because they are easy to disturb (copying, rsync, zip/unzip),
    which can silently change "newest capture" selection in paper-grade workflows.
    """

    # Prefer capture day extracted from the session label or artifact path when available.
    capture_day = _group_capture_day(group)
    version_code = _group_version_code(group)
    stamp = group.session_stamp or ""
    # Tie-breakers: stable group_key and latest-mtime only as a last resort.
    return (
        1 if capture_day is not None else 0,
        int(capture_day) if capture_day is not None else 0,
        1 if version_code is not None else 0,
        int(version_code) if version_code is not None else 0,
        1 if stamp else 0,
        stamp,
        str(getattr(group, "group_key", "") or ""),
        _group_latest_mtime(group),
    )


def _group_capture_day(group: ArtifactGroup) -> int | None:
    def _parse_day(part: str) -> int | None:
        token = part.strip()
        if len(token) != 8 or not token.isdigit():
            return None
        value = int(token)
        # Sanity bounds: YYYYMMDD.
        if value < 20000101 or value > 20991231:
            return None
        return value

    best: int | None = None
    for artifact in getattr(group, "artifacts", []) or []:
        path_obj = getattr(artifact, "path", None)
        if not isinstance(path_obj, Path):
            try:
                path_obj = Path(str(path_obj))
            except Exception:
                continue
        for part in path_obj.parts:
            day = _parse_day(part)
            if day is not None and (best is None or day > best):
                best = day
    return best


def _group_version_code(group: ArtifactGroup) -> int | None:
    base = getattr(group, "base_artifact", None)
    if base is None:
        return None
    meta = getattr(base, "metadata", None)
    if not isinstance(meta, dict):
        return None
    raw = meta.get("version_code")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


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
    "resolve_profile_scope",
    "select_latest_groups",
    "select_scope",
    "select_app_scope",
    "select_category_scope",
]
