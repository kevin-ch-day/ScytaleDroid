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
from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools
from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
    dataset_tracker_counts,
    delete_dynamic_evidence_packs,
    find_dynamic_run_dirs,
    recent_tracker_runs,
    reset_package_dataset_tracker,
)
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
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
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

    # Per-app run menu: operators can run in any order and as many times as needed.
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import peek_next_run_protocol

    next_protocol = peek_next_run_protocol(package_name, tier="dataset") or {}
    suggested_profile = (next_protocol.get("run_profile") or "interactive_use").strip()
    suggested_slot = next_protocol.get("run_sequence")
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

    cfg = DatasetTrackerConfig()
    counts = dataset_tracker_counts(package_name)
    fs_runs = find_dynamic_run_dirs(package_name)

    print()
    print(
        status_messages.status(
            f"Runs recorded: tracker={counts.total_runs} "
            f"(valid={counts.valid_runs}/{cfg.repeats_per_app}, "
            f"baseline={counts.baseline_valid_runs}/{cfg.baseline_required}, "
            f"interactive={counts.interactive_valid_runs}/{cfg.interactive_required}, "
            f"quota_met={int(counts.quota_met)}) "
            f"| local_evidence={len(fs_runs)}",
            level="info",
        )
    )
    if counts.quota_met:
        # Once quota is met, runs are still allowed, but they're "extra" and don't change completion.
        print(
            status_messages.status(
                "Quota met. Additional runs are allowed and will be tracked as extra (do not change completion).",
                level="info",
            )
        )
        suggested_slot = None
    elif suggested_slot:
        print(
            status_messages.status(
                f"Suggested by quota (counts toward completion): {suggested_profile} (dataset slot #{suggested_slot})",
                level="info",
            )
        )

    def _badge_for(key: str) -> str | None:
        if not suggested_slot:
            return None
        return "suggested" if key == ("2" if suggested_profile == "interactive_use" else "1") else None

    protocol_options = [
        menu_utils.MenuOption("1", "Idle / minimal", description="baseline_idle + minimal interaction", badge=_badge_for("1")),
        menu_utils.MenuOption("2", "Normal", description="interactive_use + normal interaction", badge=_badge_for("2")),
        menu_utils.MenuOption("3", "Heavy", description="interactive_use + heavy interaction", badge=None),
        menu_utils.MenuOption("4", "Test app (Dry Run/No Saving)", description="no capture; checks plan + tools", badge=None),
        menu_utils.MenuOption("D", "Delete previous runs", description="delete local evidence packs + reset tracker for this app", badge=None),
    ]

    menu_utils.print_header("Tag Dynamic Analysis Run")
    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=protocol_options,
            default="2" if suggested_profile == "interactive_use" else "1",
            exit_label="Exit",
            show_exit=True,
            show_descriptions=True,
            compact=True,
        )
    )
    selected_protocol = prompt_utils.get_choice(
        ["1", "2", "3", "4", "D", "0"],
        default="2" if suggested_profile == "interactive_use" else "1",
        casefold=True,
        invalid_message="Choose 0-4 or D.",
    )
    selected_protocol = selected_protocol.upper()
    if selected_protocol == "0":
        return
    if selected_protocol == "D":
        local = find_dynamic_run_dirs(package_name)
        print(
            status_messages.status(
                f"Local dynamic runs for {package_name}: {len(local)} evidence pack(s).",
                level="warn",
            )
        )
        if not local and counts.total_runs <= 0:
            print(status_messages.status("Nothing to delete/reset.", level="info"))
            prompt_utils.press_enter_to_continue()
            return
        confirmed = prompt_utils.prompt_yes_no(
            f"Delete local evidence packs AND reset dataset tracker entry for {package_name}?",
            default=False,
        )
        if not confirmed:
            return
        deleted = delete_dynamic_evidence_packs(package_name)
        reset_package_dataset_tracker(package_name)
        remaining = len(find_dynamic_run_dirs(package_name))
        print(
            status_messages.status(
                f"Deleted {deleted} evidence pack(s). Remaining={remaining}. Tracker entry reset.",
                level="info",
            )
        )
        prompt_utils.press_enter_to_continue()
        return
    if selected_protocol == "4":
        # Preflight-only test: do not capture or write evidence packs.
        missing = missing_required_tools(tier="dataset")
        tools = collect_host_tools()
        if missing:
            print(
                status_messages.status(
                    f"Preflight FAIL: missing host tools: {', '.join(missing)}",
                    level="error",
                )
            )
        else:
            print(status_messages.status("Preflight OK: host tools present.", level="success"))
        print(status_messages.status(f"Host tools: {tools}", level="info"))
        # Also ensure a plan exists (offer to run static once, as normal).
        plan_selection = ensure_plan_or_error(
            package_name,
            prompt_run_static=True,
            deterministic=True,
            run_static_callback=_auto_run_static_for_package,
        )
        if plan_selection:
            print(status_messages.status(f"Plan OK: {plan_selection['plan_path']}", level="success"))
        prompt_utils.press_enter_to_continue()
        return

    # Show recent history before starting capture so operator can sanity-check state.
    recent = recent_tracker_runs(package_name, limit=5)
    if recent:
        rows = []
        for r in recent:
            if r.valid is True:
                status = "VALID"
            elif r.valid is False:
                status = f"INVALID:{r.invalid_reason_code or 'UNKNOWN'}"
            else:
                status = "UNKNOWN"
            rows.append(
                [
                    (r.ended_at or "—")[:19],
                    (r.run_profile or "—"),
                    (r.interaction_level or "—"),
                    (getattr(r, "messaging_activity", None) or "—"),
                    status,
                    (r.run_id or "—")[:8],
                ]
            )
        menu_utils.print_section("Recent Runs (from tracker)")
        menu_utils.print_table(
            ["Ended", "Profile", "Interaction", "Msg", "Status", "Run ID"],
            rows,
        )

    # Capture modes.
    tier = "dataset"
    counts_toward_completion = not bool(counts.quota_met)
    if selected_protocol == "1":
        run_profile = "baseline_idle"
        interaction_level = "minimal"
    elif selected_protocol == "2":
        run_profile = "interactive_use"
        interaction_level = "normal"
    else:
        run_profile = "interactive_use"
        interaction_level = "heavy"

    messaging_activity: str | None = None
    messaging_pkgs = {
        # Dataset messaging apps where text vs call activity meaningfully changes network behavior.
        "com.facebook.orca",
        "com.whatsapp",
        "org.telegram.messenger",
        "org.thoughtcrime.securesms",
    }
    if package_name.lower() in messaging_pkgs:
        print()
        menu_utils.print_header("Messaging Activity (Optional Tag)")
        menu_utils.render_menu(
            menu_utils.MenuSpec(
                items=[
                    menu_utils.MenuOption("1", "None / browsing only", description="no explicit messaging activity"),
                    menu_utils.MenuOption("2", "Text only", description="send/receive text messages"),
                    menu_utils.MenuOption("3", "Voice call", description="voice calling only"),
                    menu_utils.MenuOption("4", "Video call", description="video calling only"),
                    menu_utils.MenuOption("5", "Mixed", description="text + voice/video"),
                ],
                default="1",
                exit_label=None,
                show_exit=False,
                show_descriptions=True,
                compact=True,
            )
        )
        choice = prompt_utils.get_choice(["1", "2", "3", "4", "5"], default="1", invalid_message="Choose 1-5.")
        messaging_activity = {
            "1": "none",
            "2": "text_only",
            "3": "voice_call",
            "4": "video_call",
            "5": "mixed",
        }[choice]

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
        # Dataset tier is strict; exploratory runs are allowed to proceed with best-effort
        # schema/persistence while still producing an evidence pack.
        require_dynamic_schema=(tier == "dataset"),
        observer_prompts_enabled=bool(observer_prompts_enabled),
        pcapdroid_api_key=pcapdroid_api_key,
        run_profile=run_profile,
        interaction_level=interaction_level,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    result = execute_dynamic_run_spec(spec)
    print_run_summary(result, label)
    if result.dynamic_run_id and print_tier1_qa_result:
        print_tier1_qa_result(result.dynamic_run_id)


__all__ = ["run_guided_dataset_run"]
