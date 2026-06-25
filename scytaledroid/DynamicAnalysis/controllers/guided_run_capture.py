"""Capture setup and drift rendering helpers for guided dynamic runs."""

from __future__ import annotations

from typing import Any, Callable


def plan_drift_rows(plan_drift: dict[str, Any], *, detailed_installed_build: bool) -> list[list[str]]:
    installed_build = str(plan_drift.get("observed_version_code") or "unknown")
    if detailed_installed_build:
        installed_build = f"{installed_build} ({plan_drift.get('observed_command') or 'unknown'})"
    static_plan_build = (
        f"{plan_drift.get('expected_version_name') or 'unknown'} "
        f"({plan_drift.get('expected_version_code') or 'unknown'})"
    )
    return [
        ["Installed build", installed_build],
        ["Static plan build" if detailed_installed_build else "Static plan", static_plan_build],
        ["Static run", plan_drift.get("static_run_id") or "unknown"],
    ]


def print_plan_drift_warning(plan_drift: dict[str, Any], *, status_messages: Any) -> None:
    if plan_drift.get("observed_pattern") or plan_drift.get("observed_line"):
        print(
            status_messages.status(
                "Observed build identity came from the live package dump and does not match the newest static plan.",
                level="warn",
            )
        )


def print_plan_drift_blocked_message(plan_drift: dict[str, Any], *, status_messages: Any) -> None:
    observed_vc = str(plan_drift.get("observed_version_code") or "").strip() or "unknown"
    expected_vc = str(plan_drift.get("expected_version_code") or "").strip() or "unknown"
    print(
        status_messages.status(
            "Blocked: installed build "
            f"{observed_vc} does not match static-plan build {expected_vc}. "
            "Refresh harvest/static for this app or choose another app.",
            level="error",
        )
    )


def render_static_plan_build_drift_block(
    *,
    display_label: str,
    plan_drift: dict[str, Any],
    menu_utils: Any,
    status_messages: Any,
) -> None:
    menu_utils.print_header("Static Plan / Device Drift")
    rows = [["App", display_label], *plan_drift_rows(plan_drift, detailed_installed_build=True)]
    menu_utils.print_table(["Field", "Value"], rows)
    print_plan_drift_warning(plan_drift, status_messages=status_messages)
    print_plan_drift_blocked_message(plan_drift, status_messages=status_messages)


def render_selected_app_drift_workbench(
    *,
    app: Any,
    plan_drift: dict[str, Any],
    menu_utils: Any,
    status_messages: Any,
    selected_app_active_valid_runs_fn: Callable[[Any], int],
    print_selected_app_evidence_context_fn: Callable[..., None],
    selected_app_lineage_state_fn: Callable[..., str],
    selected_app_state_snapshot_fn: Callable[..., Any],
) -> None:
    active_valid_runs = selected_app_active_valid_runs_fn(app)
    menu_utils.print_header("Dynamic Workbench", app.display_label)
    print_selected_app_evidence_context_fn(
        package_name=app.package_name,
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=app.historical_valid_local,
        historical_build_count=app.historical_build_count,
        db_active_sessions=app.db_active_sessions,
        db_historical_sessions=app.db_historical_sessions,
        include_why=False,
    )
    lineage_state = selected_app_lineage_state_fn(
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=app.historical_valid_local,
        db_active_sessions=app.db_active_sessions,
        db_historical_sessions=app.db_historical_sessions,
    )
    snapshot = selected_app_state_snapshot_fn(
        lineage_state=lineage_state,
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=app.historical_valid_local,
        db_active_sessions=app.db_active_sessions,
        db_historical_sessions=app.db_historical_sessions,
        latest_valid=app.latest_valid,
        queue_action="baseline",
        baseline_valid_runs=int(app.counts.baseline_valid_runs),
        interactive_valid_runs=int(app.counts.interactive_valid_runs),
        baseline_required=int(app.cfg.baseline_required),
        interactive_required=int(app.cfg.interactive_required),
        extra_valid_runs=app.extra_valid_local,
    )
    evidence_short = {
        "local+db": "ldb",
        "local-only": "local",
        "db-only": "db",
        "empty": "empty",
        "none": "—",
    }.get(snapshot.evidence, snapshot.evidence)
    state_parts = ["drift"]
    if evidence_short and evidence_short != "—":
        state_parts.append(evidence_short)
    qa_badge = snapshot.qa
    if qa_badge and qa_badge != "—":
        state_parts.append(qa_badge)
    menu_utils.print_header("App state")
    rows = [
        ["Status", "refresh"],
        ["Need", "refresh"],
        ["Quota", snapshot.quota],
        ["State", "/".join(state_parts)],
        ["Action", "refresh"],
    ]
    menu_utils.print_table(["Field", "Value"], rows)
    print()
    print("Why:")
    print("The installed app build does not match the newest static plan.")
    print("Pause dynamic collection for this app until harvest/static refresh is complete.")
    print()
    rows = plan_drift_rows(plan_drift, detailed_installed_build=False)
    menu_utils.print_table(["Field", "Value"], rows)
    print()
    print("Recommended next step:")
    print("Refresh harvest/static for this app, then return to the dynamic queue.")
    print()
    print_plan_drift_warning(plan_drift, status_messages=status_messages)
    print_plan_drift_blocked_message(plan_drift, status_messages=status_messages)


def print_capture_device_choice(
    *,
    details: dict[str, str],
    detected: bool,
    menu_utils: Any,
    status_messages: Any,
) -> None:
    menu_utils.print_section("Capture device")
    print(
        "  "
        + " · ".join(
            [
                details["name"],
                details["serial"],
                f"Android {details['android']}",
                details["type"],
            ]
        )
    )
    if not detected:
        print(
            status_messages.status(
                "Selected device is not currently detected via adb. Continue only if the device reconnects before validation.",
                level="warn",
            )
        )


def choose_capture_device(
    device_ctx: dict[str, str | None],
    *,
    get_device_selection_details_fn: Callable[[str], dict[str, str]],
    select_device_fn: Callable[..., tuple[str, str] | None],
    menu_utils: Any,
    prompt_utils: Any,
    status_messages: Any,
) -> tuple[str, str] | None:
    current_serial = str(device_ctx.get("serial") or "").strip()
    if not current_serial:
        return select_device_fn()

    details = get_device_selection_details_fn(current_serial)
    detected = str(details.get("detected") or "").strip() == "1"
    print_capture_device_choice(
        details=details,
        detected=detected,
        menu_utils=menu_utils,
        status_messages=status_messages,
    )
    menu_utils.print_menu(
        [
            menu_utils.MenuOption("1", "Use selected device"),
            menu_utils.MenuOption("2", "Change device"),
        ],
        show_exit=False,
        show_descriptions=False,
        compact=True,
    )
    menu_utils.print_menu([], show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
    choice = prompt_utils.get_choice(
        ["1", "2", "0"],
        default="1",
        prompt="› Device action [1]: ",
        invalid_message="Choose 1, 2, or 0.",
    )
    if choice == "0":
        return None
    if choice == "2":
        return select_device_fn(
            header="Change Capture Device",
            prefer_active=False,
            allow_auto_single=False,
        )
    return current_serial, str(details.get("label") or current_serial)


def prepare_selected_app_capture(
    *,
    app: Any,
    device_ctx: dict[str, str | None],
    print_device_badge: Callable[[str, str], None],
    menu_utils: Any,
    prompt_utils: Any,
    status_messages: Any,
    print_paper_mode_constants_fn: Callable[[], None],
    choose_capture_device_fn: Callable[[dict[str, str | None]], tuple[str, str] | None],
    device_preflight_checks_fn: Callable[[str], bool],
    detect_static_plan_build_drift_fn: Callable[..., dict[str, str] | None],
    render_selected_app_drift_workbench_fn: Callable[..., None],
) -> tuple[str, str] | None:
    print()
    menu_utils.print_header("Capture Setup", app.display_label)
    print_paper_mode_constants_fn()
    selected = choose_capture_device_fn(device_ctx)
    if not selected:
        return None
    device_serial, device_label = selected
    device_ctx["serial"] = device_serial
    device_ctx["label"] = device_label
    print_device_badge(device_serial, device_label)
    if not device_preflight_checks_fn(device_serial):
        prompt_utils.press_enter_to_continue()
        return None
    plan_drift = detect_static_plan_build_drift_fn(
        device_serial=device_serial,
        package_name=app.package_name,
    )
    if plan_drift is not None:
        print()
        render_selected_app_drift_workbench_fn(app=app, plan_drift=plan_drift)
        prompt_utils.press_enter_to_continue()
        return None
    return device_serial, device_label


__all__ = [
    "choose_capture_device",
    "plan_drift_rows",
    "prepare_selected_app_capture",
    "print_capture_device_choice",
    "print_plan_drift_blocked_message",
    "print_plan_drift_warning",
    "render_selected_app_drift_workbench",
    "render_static_plan_build_drift_block",
]
