"""Helper utilities for the static analysis menu flow."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from scytaledroid.DeviceAnalysis.services.static_scope_service import static_scope_service
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

if TYPE_CHECKING:

    from ..commands.models import Command
    from ..core.models import RunParameters

try:  # optional DB access (offline mode)
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - DB optional
    core_q = None


@lru_cache(maxsize=1)
def _load_menu_actions():  # pragma: no cover - simple cache wrapper
    from . import actions

    return actions


def apply_command_overrides(
    params: RunParameters,
    command: Command,
) -> RunParameters:
    actions = _load_menu_actions()
    return actions.apply_command_overrides(params, command)


def ask_run_controls() -> str:
    actions = _load_menu_actions()
    return actions.ask_run_controls()


def confirm_reset(session_label: str | None = None) -> str | None:
    actions = _load_menu_actions()
    return actions.confirm_reset(session_label)


def prompt_session_label(params: RunParameters) -> RunParameters:
    actions = _load_menu_actions()
    return actions.prompt_session_label(params)


def prompt_run_setup(params: RunParameters, selection, command):
    actions = _load_menu_actions()
    return actions.prompt_run_setup(params, selection, command)


def render_run_preflight(params: RunParameters, selection, command, *, reset_mode: str | None) -> None:
    actions = _load_menu_actions()
    actions.render_run_preflight(params, selection, command, reset_mode=reset_mode)


def render_reset_outcome(outcome: object, *, session_label: str | None = None) -> None:
    actions = _load_menu_actions()
    actions.render_reset_outcome(outcome, session_label=session_label)


def collect_view_options(command: Command) -> tuple[bool, bool, bool, bool]:
    from ..commands.models import SelectionMode

    print("View options")
    print("------------------------")
    print("[1] Summary details")
    print("    High-level findings, static scoring bands, and key signals.")
    print("    Best starting point for review or demo.")
    print()
    print("[2] Split breakdown")
    print("    Per-APK split/module analysis (features, ABI, resources).")
    print("    Useful for large apps with dynamic feature splits.")
    print()
    print("[3] Artifact detail")
    print("    Deep dive into a specific artifact (manifest, strings, native libs).")
    print("    Advanced / forensic view.")
    print()
    print("[0] Return to main menu")
    print("    Exit results view without modifying data.")
    print()
    print("[Enter] Continue with defaults")
    print("    Opens Summary details.")
    choice = prompt_utils.get_choice(
        ["1", "2", "3", "0"],
        default="1",
        prompt="Select option [1]: ",
    )
    if choice == "0":
        return False, False, False, True
    if choice == "1":
        want_details, want_splits, want_artifacts = True, False, False
    elif choice == "2":
        want_details, want_splits, want_artifacts = False, True, False
    else:
        want_details, want_splits, want_artifacts = False, False, True
    if want_details:
        print()
        menu_utils.print_section("Details")
        details_map = {
            "full": [
                "Runs all detectors",
                "Resets caches when prompted",
                "Persists results and verification digest",
            ],
            "lightweight": [
                "Runs the lightweight detector set",
                "Persists results and verification digest",
            ],
            "last": [
                "Uses the most recent static run package",
                "Falls back to latest harvested APK if needed",
            ],
            "diff_last": [
                "Diffs latest two stored reports for the package",
                "Same package only",
            ],
        }
        detail_key = (
            str(command.selection_mode)
            if command.selection_mode is not SelectionMode.SCOPE
            else (command.profile or "")
        )
        for line in details_map.get(detail_key, ("No additional details.",)):
            print(f"• {line}")
    return want_details, want_splits, want_artifacts, False




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


def _find_latest_group_for_package(groups, package_name):
    from ..flows.selection import select_latest_groups

    matches = tuple(group for group in groups if group.package_name == package_name)
    if not matches:
        return None
    selected = select_latest_groups(matches)
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


def _get_last_static_run_info():
    if core_q is None:
        return None
    row = core_q.run_sql(
        """
        SELECT
            a.package_name,
            av.version_name,
            av.version_code,
            COALESCE(sar.base_apk_sha256, sar.sha256) AS base_sha,
            sar.status,
            sar.run_class,
            sar.session_stamp,
            COALESCE(sar.ended_at_utc, sar.run_started_utc) AS completed_or_started_at
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
    return {
        "package_name": row[0],
        "version_name": row[1],
        "version_code": row[2],
        "sha256": row[3],
        "status": row[4],
        "run_class": row[5],
        "session_stamp": row[6],
        "when": row[7],
    }


def _format_version_label(version_name, version_code) -> str:
    name = str(version_name or "").strip()
    code = str(version_code or "").strip()
    if name and code:
        return f"{name} ({code})"
    if name:
        return name
    if code:
        return code
    return ""


def _short_sha(value: object, width: int = 12) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text[:width]


def _group_display_label(group) -> str:
    base = getattr(group, "base_artifact", None) or next(iter(getattr(group, "artifacts", ()) or ()), None)
    metadata = getattr(base, "metadata", None)
    if isinstance(metadata, dict):
        app_label = str(metadata.get("app_label") or metadata.get("display_name") or "").strip()
        if app_label:
            return f"{app_label} | {group.package_name}"
    return str(getattr(group, "package_name", "") or "")


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


def describe_last_selection(groups) -> dict[str, object]:
    try:
        last_static = _get_last_static_run_info()
    except Exception:
        last_static = None
    package_name = str((last_static or {}).get("package_name") or "").strip()
    if package_name:
        selection_group = _find_latest_group_for_package(groups, package_name)
        if selection_group:
            version_label = _format_version_label(
                (last_static or {}).get("version_name"),
                (last_static or {}).get("version_code"),
            ) or getattr(selection_group, "version_display", "")
            status = str((last_static or {}).get("status") or "").strip()
            run_class = str((last_static or {}).get("run_class") or "").strip()
            status_label = " | ".join(part for part in (status, run_class) if part)
            return {
                "available": True,
                "label": _group_display_label(selection_group),
                "source": "static-run",
                "version_label": version_label,
                "sha_short": _short_sha((last_static or {}).get("sha256")),
                "run_status": status_label,
                "run_when": str((last_static or {}).get("when") or "").strip(),
                "session_stamp": str((last_static or {}).get("session_stamp") or "").strip(),
            }
        return {
            "available": False,
            "label": package_name,
            "source": "static-run-missing-library",
        }

    try:
        harvested = _get_last_harvested_package()
    except Exception:
        harvested = None
    if harvested:
        selection_group = _find_group_by_sha(groups, harvested.get("sha256"))
        if not selection_group:
            selection_group = _find_latest_group_for_package(groups, harvested.get("package_name"))
        if selection_group:
            return {
                "available": True,
                "label": _group_display_label(selection_group),
                "source": "latest-harvest",
                "version_label": _format_version_label(
                    None,
                    harvested.get("version_code"),
                ) or getattr(selection_group, "version_display", ""),
                "sha_short": _short_sha(harvested.get("sha256")),
                "run_status": "HARVESTED",
                "run_when": str(harvested.get("harvested_at") or "").strip(),
                "session_stamp": str(getattr(selection_group, "session_stamp", "") or "").strip(),
            }
        return {
            "available": False,
            "label": str(harvested.get("package_name") or ""),
            "source": "harvest-missing-library",
        }

    return {
        "available": False,
        "label": "",
        "source": "none",
    }


def diff_last_available(groups) -> tuple[bool, str]:
    try:
        package_name = _get_last_static_package()
    except Exception:
        package_name = None
    if not package_name:
        return False, ""

    try:
        from scytaledroid.StaticAnalysis.persistence.reports import list_reports

        reports = [stored for stored in list_reports() if stored.report.manifest.package_name == package_name]
    except Exception:
        reports = []

    if len(reports) >= 2:
        return True, package_name

    matches = tuple(group for group in groups if group.package_name == package_name)
    if len(matches) >= 2:
        return True, package_name
    return False, package_name


def _sort_report_key(stored):
    report = stored.report
    version_code = report.manifest.version_code
    try:
        code_value = int(version_code) if version_code is not None else None
    except (TypeError, ValueError):
        code_value = None
    generated_at = report.generated_at or ""
    # Avoid filesystem mtimes for ordering. Prefer deterministic keys.
    file_name = ""
    try:
        file_name = stored.path.name
    except Exception:
        file_name = ""
    return (
        code_value if code_value is not None else -1,
        generated_at,
        file_name,
    )


def _report_distinct_key(stored) -> tuple[str, str, str]:
    report = stored.report
    manifest = report.manifest
    version_code = str(getattr(manifest, "version_code", "") or "").strip()
    version_name = str(getattr(manifest, "version_name", "") or "").strip()
    sha256 = str(report.hashes.get("sha256") or "").strip().lower()
    if version_code:
        # Prefer version-code identity when it is available so repeated reports
        # of the same build do not masquerade as a version diff.
        return (version_code, "", "")
    if version_name:
        return ("", version_name, "")
    return ("", "", sha256)


def _select_distinct_report_pair(reports):
    if len(reports) < 2:
        return None

    reports = sorted(reports, key=_sort_report_key)
    current = reports[-1]
    current_key = _report_distinct_key(current)
    for previous in reversed(reports[:-1]):
        if _report_distinct_key(previous) != current_key:
            return previous.report, current.report
    return None


def render_version_diff(package_name):
    from scytaledroid.StaticAnalysis.detectors.correlation.diffing import (
        compare_components,
        compare_flags,
        compare_permissions,
    )
    from scytaledroid.StaticAnalysis.persistence.reports import list_reports

    reports = [stored for stored in list_reports() if stored.report.manifest.package_name == package_name]
    pair = _select_distinct_report_pair(reports)
    if pair is None:
        print(
            status_messages.status(
                f"Need at least two distinct analyzed versions/builds for {package_name} to diff.",
                level="warn",
            )
        )
        return

    previous, current = pair

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


__all__ = [
    "apply_command_overrides",
    "ask_run_controls",
    "choose_scope",
    "collect_view_options",
    "confirm_reset",
    "describe_last_selection",
    "diff_last_available",
    "prompt_run_setup",
    "prompt_session_label",
    "render_run_preflight",
    "render_reset_outcome",
    "render_version_diff",
    "resolve_last_selection",
    "_select_distinct_report_pair",
]
