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
    format_audit_session_command,
)

_INACTIVE_PROFILE_LABELS = frozenset({"Profile v3 Structural Cohort"})

_DEFAULT_CAPTURE_RULE = "Newest harvest capture per package"
_LARGE_SPLIT_APK_THRESHOLD = 20  # flag outlier workload before run setup
# Future selection modes (longitudinal / per-app capture / base-only / completeness filters)
# should extend ScopeSelection metadata and this module without renaming operator-visible harvest terms.


def _apk_totals(groups: Sequence[ArtifactGroup]) -> tuple[int, int, int]:
    """Return (total_apk_files, base_count, split_count)."""

    total = 0
    splits = 0
    for group in groups:
        for artifact in group.artifacts:
            total += 1
            if getattr(artifact, "is_split_member", False):
                splits += 1
    return total, total - splits, splits


def _skipped_count_map(skipped_details: Sequence[tuple[str, str, int]]) -> dict[str, int]:
    return {pkg: count for pkg, _stamp, count in skipped_details}


def _format_version_line(group: ArtifactGroup) -> str:
    base = group.base_artifact
    if base is None:
        return "—"
    meta = base.metadata if isinstance(base.metadata, dict) else {}
    name = meta.get("version_name")
    code = meta.get("version_code")
    parts: list[str] = []
    if isinstance(name, str) and name.strip():
        parts.append(name.strip())
    if code is not None and str(code).strip():
        parts.append(f"({code})")
    return " ".join(parts) if parts else "—"


def _format_capture_time(group: ArtifactGroup) -> str:
    stamp = group.session_stamp or ""
    if stamp.strip():
        return stamp.strip()
    base = group.base_artifact
    if base is None:
        return "unknown"
    meta = base.metadata if isinstance(base.metadata, dict) else {}
    for key in ("captured_at_utc", "snapshot_captured_at", "harvest_completed_at"):
        raw = meta.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()[:32]
    return "unknown"


def _base_sha_prefix(group: ArtifactGroup) -> str:
    base = group.base_artifact
    if base is None:
        return "—"
    sha = getattr(base, "sha256", None) or (
        base.metadata.get("sha256") if isinstance(base.metadata, dict) else None
    )
    if isinstance(sha, str) and len(sha) >= 16:
        return f"{sha[:16]}…"
    if isinstance(sha, str) and sha.strip():
        return f"{sha.strip()[:16]}…"
    return "—"


def _capture_status_word(group: ArtifactGroup) -> str:
    if group.base_artifact is None:
        return "missing base"
    splits = sum(1 for a in group.artifacts if getattr(a, "is_split_member", False))
    reasons = group.harvest_non_canonical_reasons
    if reasons:
        return "partial / " + ", ".join(reasons[:3])
    if splits >= 15:
        return "complete (split-heavy)"
    return "complete"


def _rule_display(rule_line: str) -> str:
    s = (rule_line or "").strip()
    if not s:
        return ""
    return s[0].lower() + s[1:]


def _print_workload_summary_lines(
    *,
    profile_title: str,
    scoped: Sequence[ArtifactGroup],
    older_excluded: int,
    rule_line: str,
) -> None:
    n_pkg = len(scoped)
    n_cap = len(scoped)
    total, base_n, split_n = _apk_totals(scoped)
    label_w = 18
    pad = "  "
    print(f"Profile: {profile_title}")
    print(f"Rule   : {_rule_display(rule_line)}")
    print()
    print("Selected for this run")
    print(f"{pad}{'Packages':<{label_w}}: {n_pkg}")
    print(f"{pad}{'Harvest captures':<{label_w}}: {n_cap}")
    print(f"{pad}{'APK files':<{label_w}}: {total} total ({base_n} base + {split_n} split)")
    if older_excluded > 0:
        print(
            f"{pad}{'Older captures':<{label_w}}: {older_excluded} excluded; "
            "retained for comparison/longitudinal analysis"
        )
    else:
        print(f"{pad}{'Older captures':<{label_w}}: none excluded")
    print(f"{pad}{'Split scan':<{label_w}}: on for Full analysis")


def _print_research_workflow_block() -> None:
    print()
    print("Research workflow")
    print("  Static scan writes canonical DB rows and handoff records.")
    print("  After run, audit with scripts/db/audit_static_session.py.")
    print("  Dynamic planning can use v_static_handoff_v1 when handoff rows are present.")


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
    print(f"{pad}{'Audit (latest cohort)':<{lw}}: {format_audit_session_command(snapshot.session_stamp)}")


def _maybe_print_large_split_warnings(scoped: Sequence[ArtifactGroup], display_map: dict[str, str]) -> None:
    outliers: list[tuple[str, str, int, int, int]] = []
    for group in scoped:
        total = len(group.artifacts)
        splits = sum(1 for a in group.artifacts if getattr(a, "is_split_member", False))
        base_n = total - splits
        if total < _LARGE_SPLIT_APK_THRESHOLD:
            continue
        pkg = group.package_name
        label = display_map.get(pkg.lower()) or pkg
        outliers.append((label, pkg, total, base_n, splits))
    if not outliers:
        return
    print()
    print("Large split workload")
    for label, _pkg, total, base_n, splits in sorted(outliers, key=lambda row: row[2], reverse=True):
        print(f"  {label} — {total} APK files ({base_n} base + {splits} split)")


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
    grouped, scoped, skipped_details = _collapse_latest_by_package(groups)
    older_excluded = sum(count for _, _, count in skipped_details)
    _maybe_prompt_selection_details(grouped, scoped, skipped_details)

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
    categories = [
        (category, count)
        for category, count in list_categories(groups)
        if category not in _INACTIVE_PROFILE_LABELS
    ]
    if not categories:
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
    rows = [[str(idx), category, str(count)] for idx, (category, count) in enumerate(categories, start=1)]
    table_utils.render_table(["#", "Profile", "Apps"], rows, compact=True, padding=2)
    print()
    print(f"Profiles: {len(categories)}")

    if len(categories) == 1:
        category_name, _ = categories[0]
        print(
            status_messages.status(
                f"Only one active profile is available; selecting {category_name}.",
                level="info",
            )
        )
        return resolve_profile_scope(groups, category_name)

    index = _resolve_index("Select profile #", [category for category, _ in categories])
    category_name, _ = categories[index]
    return resolve_profile_scope(groups, category_name)


def resolve_profile_scope(
    groups: Sequence[ArtifactGroup],
    category_name: str,
) -> ScopeSelection:
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
    older_excluded = sum(count for _, _, count in skipped_details)
    _maybe_prompt_selection_details(grouped, scoped, skipped_details)

    if scoped:
        display_map = load_display_name_map(scoped)
        print()
        menu_utils.print_header(
            "Static Analysis · Profile Workload",
            "Review cohort counts and APK workload before Run Setup.",
        )
        _print_workload_summary_lines(
            profile_title=category_name,
            scoped=scoped,
            older_excluded=older_excluded,
            rule_line=_DEFAULT_CAPTURE_RULE,
        )
        _print_research_workflow_block()
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
        _maybe_print_large_split_warnings(scoped, display_map)
        print()
        print("Note: Full analysis scans each selected APK file when split scan is on.")
        print("Use Run Options for base-only or reduced workload.")
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
        f"Selected newest harvest capture for each of {total_packages} package"
        f"{'s' if total_packages != 1 else ''}. "
        f"Excluded {total_skipped} older capture{'s' if total_skipped != 1 else ''} from this run "
        "(older captures remain stored for comparison)."
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


def _render_selection_details(
    grouped: dict[str, list[ArtifactGroup]],
    selected: Sequence[ArtifactGroup],
    skipped_details: Sequence[tuple[str, str, int]],
) -> None:
    print()
    print("Selection details (per package)")
    print("-" * 80)
    skipped_map = _skipped_count_map(skipped_details)
    display_map = load_display_name_map(selected)

    lines: list[tuple[str, str, ArtifactGroup]] = []
    for group in selected:
        pkg = group.package_name
        label = display_map.get(pkg.lower()) or pkg
        lines.append((label.lower(), label, group))
    lines.sort(key=lambda row: row[0])

    for _sort_key, label, group in lines:
        pkg = group.package_name
        total = len(group.artifacts)
        splits = sum(1 for a in group.artifacts if getattr(a, "is_split_member", False))
        base_n = total - splits
        apk_breakdown = f"{total} ({base_n} base + {splits} split)" if splits else str(total)
        older = skipped_map.get(pkg, 0)
        print(f"{label}")
        print(f"  Package             : {pkg}")
        print(f"  Selected capture    : {_format_capture_time(group)}")
        print(f"  Version             : {_format_version_line(group)}")
        print(f"  APK files           : {apk_breakdown}")
        print(f"  Base SHA-256 prefix : {_base_sha_prefix(group)}")
        print(
            f"  Older captures      : {older} excluded from this run"
            if older
            else "  Older captures      : none excluded"
        )
        print(f"  Capture status      : {_capture_status_word(group)}")
        print()

    total_packages = len(skipped_details)
    total_skipped = sum(count for _, _, count in skipped_details)
    if total_skipped > 0:
        print(
            f"Summary: {total_skipped} older capture{'s' if total_skipped != 1 else ''} excluded "
            f"across {total_packages} package{'s' if total_packages != 1 else ''}."
        )
    else:
        print("Summary: no older captures excluded (one capture per package in scope).")


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
