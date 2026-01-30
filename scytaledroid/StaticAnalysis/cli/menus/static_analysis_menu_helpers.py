"""Helper utilities for the static analysis menu flow."""

from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.StaticAnalysis.session import make_session_stamp
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

if TYPE_CHECKING:
    from ..commands.models import Command
    from ..core.models import RunParameters
    from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup

try:  # optional DB access (offline mode)
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - DB optional
    core_q = None

DEV_TARGETS = {
    "C": ("CNN", "com.cnn.mobile.android.phone"),
    "T": ("TikTok", "com.zhiliaoapp.musically"),
    "G": ("Gmail", "com.google.android.gm"),
    "W": ("WhatsApp", "com.whatsapp"),
}


@lru_cache(maxsize=1)
def _load_menu_actions():  # pragma: no cover - simple cache wrapper
    from . import actions

    return actions


def apply_command_overrides(
    params: "RunParameters",
    command: "Command",
) -> "RunParameters":
    actions = _load_menu_actions()
    return actions.apply_command_overrides(params, command)


def ask_run_controls() -> str:
    actions = _load_menu_actions()
    return actions.ask_run_controls()


def confirm_reset() -> bool:
    actions = _load_menu_actions()
    return actions.confirm_reset()


def prompt_session_label(params: "RunParameters") -> "RunParameters":
    actions = _load_menu_actions()
    return actions.prompt_session_label(params)


def render_reset_outcome(outcome: object) -> None:
    actions = _load_menu_actions()
    actions.render_reset_outcome(outcome)


def collect_view_options(command: "Command") -> tuple[bool, bool, bool]:
    prompt = "View options: [D]etails  [S]plit breakdown  [A]rtifact detail  [Enter] continue"
    response = prompt_utils.prompt_text(prompt, required=False).strip().lower()
    want_details = "d" in response
    want_splits = "s" in response
    want_artifacts = "a" in response
    if not want_details:
        return want_details, want_splits, want_artifacts
    print()
    menu_utils.print_section("Details")
    details_map = {
        "1": [
            "Runs all detectors",
            "Resets caches when prompted",
            "Persists results and verification digest",
        ],
        "2": [
            "Runs the lightweight detector set",
            "Persists results and verification digest",
        ],
        "3": [
            "Uses the most recent static run package",
            "Falls back to latest harvested APK if needed",
        ],
        "4": [
            "Diffs latest two stored reports for the package",
            "Same package only (Phase-C)",
        ],
        "5": [
            "Runs full detector set without persisting results",
            "Verbose output surfaces warnings/errors",
            "Artifact detail requires [A]rtifact detail toggle",
            "Intended for debugging pipeline issues",
        ],
    }
    for line in details_map.get(command.id, ("No additional details.",)):
        print(f"• {line}")
    return want_details, want_splits, want_artifacts


def build_dev_selection(groups, shortcut_id):
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    if shortcut_id not in DEV_TARGETS:
        return None
    _, package = DEV_TARGETS[shortcut_id]
    for group in groups:
        if getattr(group, "package_name", None) == package:
            return ScopeSelection(scope="app", label=package, groups=(group,))
    return None


def library_scope_selection(groups):
    """Build a ScopeSelection from the APK library selection, if any."""
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    selected_paths = set(static_scope_service.get_selected())
    if not selected_paths:
        return None

    selected_groups = []
    for group in groups:
        if any(str(artifact.path) in selected_paths for artifact in group.artifacts):
            selected_groups.append(group)

    if not selected_groups:
        return None

    scope_label = f"Library selection ({len(selected_groups)} app{'s' if len(selected_groups) != 1 else ''})"
    scope_type = "app" if len(selected_groups) == 1 else "library-selection"
    return ScopeSelection(scope_type, scope_label, tuple(selected_groups))


def choose_scope(groups):
    """Prompt for scope, preferring library selection when available."""
    from ..flows.selection import select_scope

    library_scope = library_scope_selection(groups)
    if library_scope:
        print()
        menu_utils.print_header("Static Analysis Scope")
        print(
            status_messages.status(
                f"APK library selection is active: {len(library_scope.groups)} group(s), {static_scope_service.count()} APKs.",
                level="info",
            )
        )
        choice = prompt_utils.get_choice(
            ["1", "2", "0"],
            default="1",
            prompt="1=Use selection  2=Choose different scope  0=Back ",
        )
        if choice == "0":
            return None
        if choice == "1":
            return library_scope

    return select_scope(groups)


def _latest_group_mtime(group) -> float:
    mtime = 0.0
    for artifact in getattr(group, "artifacts", ()):
        path_obj = getattr(artifact, "path", None)
        try:
            if path_obj is not None:
                mtime = max(mtime, Path(path_obj).stat().st_mtime)
        except OSError:
            continue
    return mtime


def _select_latest_groups(groups):
    if not groups:
        return tuple()
    if len(groups) == 1:
        return (groups[0],)
    best = max(
        groups,
        key=lambda group: (
            1 if group.session_stamp else 0,
            group.session_stamp or "",
            _latest_group_mtime(group),
        ),
    )
    if best.session_stamp:
        same_session = [group for group in groups if group.session_stamp == best.session_stamp]
        if same_session:
            return tuple(same_session)
    return (best,)


def _find_latest_group_for_package(groups, package_name):
    matches = tuple(group for group in groups if group.package_name == package_name)
    if not matches:
        return None
    selected = _select_latest_groups(matches)
    if not selected:
        return None
    return selected[0]


def _find_group_by_sha(groups, sha256):
    if not sha256:
        return None
    for group in groups:
        for artifact in group.artifacts:
            if getattr(artifact, "sha256", None) == sha256:
                return group
    return None


def _get_last_static_package():
    if core_q is None:
        return None
    row = core_q.run_sql(
        """
        SELECT a.package_name
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        ORDER BY COALESCE(sar.ended_at_utc, sar.run_started_utc, sar.id) DESC
        LIMIT 1
        """,
        fetch="one",
    )
    if not row:
        return None
    return row[0]


def _get_last_harvested_package():
    if core_q is None:
        return None
    row = core_q.run_sql(
        """
        SELECT package_name, sha256, version_code, harvested_at
        FROM android_apk_repository
        ORDER BY harvested_at DESC
        LIMIT 1
        """,
        fetch="one",
    )
    if not row:
        return None
    return {
        "package_name": row[0],
        "sha256": row[1],
        "version_code": row[2],
        "harvested_at": row[3],
    }


def resolve_last_selection(groups):
    from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection

    package_name = _get_last_static_package()
    if package_name:
        selection_group = _find_latest_group_for_package(groups, package_name)
        if selection_group:
            return ScopeSelection(scope="app", label=package_name, groups=(selection_group,))
        print(
            status_messages.status(
                f"Latest static run package {package_name} not found in APK library.",
                level="warn",
            )
        )

    harvested = _get_last_harvested_package()
    if harvested:
        print(
            status_messages.status(
                "No previous static run found. Using most recently harvested APK instead.",
                level="warn",
            )
        )
        selection_group = _find_group_by_sha(groups, harvested.get("sha256"))
        if not selection_group:
            selection_group = _find_latest_group_for_package(groups, harvested.get("package_name"))
        if selection_group:
            return ScopeSelection(
                scope="app",
                label=selection_group.package_name,
                groups=(selection_group,),
            )
        print(
            status_messages.status(
                f"Most recent harvested APK {harvested.get('package_name')} not found in library.",
                level="warn",
            )
        )
    print(status_messages.status("No prior static runs or harvested APKs found.", level="warn"))
    return None


def _sort_report_key(stored):
    report = stored.report
    version_code = report.manifest.version_code
    try:
        code_value = int(version_code) if version_code is not None else None
    except (TypeError, ValueError):
        code_value = None
    generated_at = report.generated_at or ""
    try:
        file_mtime = stored.path.stat().st_mtime
    except OSError:
        file_mtime = 0.0
    return (
        code_value if code_value is not None else -1,
        generated_at,
        file_mtime,
    )


def render_version_diff(package_name):
    from scytaledroid.StaticAnalysis.persistence.reports import list_reports
    from scytaledroid.StaticAnalysis.detectors.correlation.diffing import (
        compare_components,
        compare_flags,
        compare_permissions,
    )

    reports = [stored for stored in list_reports() if stored.report.manifest.package_name == package_name]
    if len(reports) < 2:
        print(
            status_messages.status(
                f"Need at least two reports for {package_name} to diff.",
                level="warn",
            )
        )
        return

    reports.sort(key=_sort_report_key)
    previous = reports[-2].report
    current = reports[-1].report

    new_exported = compare_components(current.exported_components, previous.exported_components)
    new_permissions = compare_permissions(current.permissions.dangerous, previous.permissions.dangerous)
    flipped_flags = compare_flags(
        current.manifest_flags.to_dict(),
        previous.manifest_flags.to_dict(),
    )

    menu_utils.print_header("Version diff", f"{package_name} ({previous.manifest.version_code} → {current.manifest.version_code})")
    if new_exported:
        for component_type, names in new_exported.items():
            print(status_messages.status(f"New exported {component_type}: {len(names)}", level="warn"))
            for name in names[:10]:
                print(f"  - {name}")
            if len(names) > 10:
                print(f"  ... ({len(names) - 10} more)")
    else:
        print(status_messages.status("No new exported components detected.", level="info"))

    if new_permissions:
        print(status_messages.status(f"New dangerous permissions: {len(new_permissions)}", level="warn"))
        for name in new_permissions[:10]:
            print(f"  - {name}")
        if len(new_permissions) > 10:
            print(f"  ... ({len(new_permissions) - 10} more)")
    else:
        print(status_messages.status("No new dangerous permissions detected.", level="info"))

    if flipped_flags:
        print(status_messages.status("Manifest flag changes detected:", level="warn"))
        for key, (previous_value, current_value) in flipped_flags.items():
            print(f"  - {key}: {previous_value} → {current_value}")
    else:
        print(status_messages.status("No manifest flag changes detected.", level="info"))
    print()


def inject_dev_session_label(params: "RunParameters", selection) -> "RunParameters":
    if not selection:
        return params
    short = selection.label.split(".")[-1]
    return replace(params, session_stamp=f"static-dev-{short}-{make_session_stamp()}")


__all__ = [
    "DEV_TARGETS",
    "apply_command_overrides",
    "ask_run_controls",
    "build_dev_selection",
    "choose_scope",
    "collect_view_options",
    "confirm_reset",
    "inject_dev_session_label",
    "prompt_session_label",
    "render_reset_outcome",
    "render_version_diff",
    "resolve_last_selection",
]
