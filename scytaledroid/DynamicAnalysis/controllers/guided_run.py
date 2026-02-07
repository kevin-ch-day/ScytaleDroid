"""Guided dataset run controller."""

from __future__ import annotations

import contextlib
import io
from dataclasses import replace
from pathlib import Path

from collections.abc import Callable

from scytaledroid.DynamicAnalysis.controllers.device_select import select_device
from scytaledroid.DynamicAnalysis.plan_selection import (
    ensure_plan_or_error,
    print_plan_selection_banner,
)
from scytaledroid.DynamicAnalysis.profile_loader import load_profile_packages
from scytaledroid.DynamicAnalysis.core.run_specs import build_dynamic_run_spec
from scytaledroid.DynamicAnalysis.run_dynamic_analysis import execute_dynamic_run_spec
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.StaticAnalysis.core.repository import group_artifacts
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def _auto_run_static_for_package(package_name: str) -> bool:
    """Dataset-mode helper: run static analysis quietly to produce a dynamic plan.

    This is non-interactive and intended only to unblock dataset collection.
    """

    from scytaledroid.Config import app_config
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp

    groups = group_artifacts()
    group = next((g for g in groups if (g.package_name or "").lower() == package_name.lower()), None)
    if not group:
        print(status_messages.status("No APK artifacts found locally for this package.", level="error"))
        return False

    session_stamp = normalize_session_stamp(f"{make_session_stamp()}-{group.package_name}")
    selection = ScopeSelection(scope="app", label=group.package_name, groups=(group,))
    params = RunParameters(
        profile="full",
        scope=selection.scope,
        scope_label=selection.label,
        session_stamp=session_stamp,
        show_split_summaries=False,
        # Noninteractive run: never prompt on collisions.
        canonical_action="append",
    )
    base_dir = Path(app_config.DATA_DIR) / "device_apks"

    buffer_out = io.StringIO()
    buffer_err = io.StringIO()
    with contextlib.redirect_stdout(buffer_out), contextlib.redirect_stderr(buffer_err):
        spec = build_static_run_spec(
            selection=selection,
            params=params,
            base_dir=base_dir,
            run_mode="batch",
            quiet=True,
            noninteractive=True,
        )
        execute_run_spec(spec)
    return True


def run_guided_dataset_run(
    *,
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_device_badge: Callable[[str, str], None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
) -> None:
    print()
    menu_utils.print_header("Guided Dataset Run")
    selected = select_device()
    if not selected:
        return
    device_serial, device_label = selected
    print_device_badge(device_serial, device_label)

    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Dataset (guided)"

    groups = group_artifacts()
    dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        return

    available = {group.package_name.lower() for group in groups if group.package_name}
    scoped_groups = tuple(
        group
        for group in groups
        if group.package_name
        and group.package_name.lower() in available.intersection(dataset_pkgs)
    )
    if not scoped_groups:
        print(
            status_messages.status(
                "No APK artifacts available for Research Dataset Alpha. Pull APKs or use Custom package name.",
                level="warn",
            )
        )
        return

    package_name = select_package_from_groups(scoped_groups, title="Research Dataset Alpha apps")
    if not package_name:
        return

    tier = "dataset"

    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids = select_observers(device_serial, mode="guided")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return

    # Dataset mode is deterministic about plan choice, but interactive about gating:
    # if no plan exists yet, offer a single prompt to run static now.
    plan_selection = ensure_plan_or_error(
        package_name,
        prompt_run_static=True,
        deterministic=True,
        run_static_callback=_auto_run_static_for_package,
    )
    if not plan_selection:
        return
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    print_plan_selection_banner(plan_selection)
    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)

    spec = build_dynamic_run_spec(
        package_name=package_name,
        device_serial=device_serial,
        observer_ids=tuple(observer_ids),
        scenario_id=scenario_id,
        tier=tier,
        duration_seconds=duration_seconds,
        plan_path=plan_path,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
        interactive=True,
    )
    result = execute_dynamic_run_spec(spec)
    print_run_summary(result, label)
    if result.dynamic_run_id and print_tier1_qa_result:
        print_tier1_qa_result(result.dynamic_run_id)


__all__ = ["run_guided_dataset_run"]
