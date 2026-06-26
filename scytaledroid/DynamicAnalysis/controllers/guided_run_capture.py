"""Capture setup and drift rendering helpers for guided dynamic runs."""

from __future__ import annotations

from typing import Any, Callable

from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_evidence_text,
    selected_app_qa_text,
)


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
    prompt_utils: Any,
    status_messages: Any,
    selected_app_active_valid_runs_fn: Callable[[Any], int],
    print_selected_app_evidence_context_fn: Callable[..., None],
    selected_app_lineage_state_fn: Callable[..., str],
    selected_app_state_snapshot_fn: Callable[..., Any],
    render_selected_app_recent_runs_fn: Callable[[Any], None],
    render_selected_app_diagnostics_fn: Callable[..., None],
) -> None:
    while True:
        active_valid_runs = selected_app_active_valid_runs_fn(app)
        menu_utils.print_header(app.display_label)
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
            queue_action="refresh",
            baseline_valid_runs=int(app.counts.baseline_valid_runs),
            interactive_valid_runs=int(app.counts.interactive_valid_runs),
            baseline_required=int(app.cfg.baseline_required),
            interactive_required=int(app.cfg.interactive_required),
            extra_valid_runs=app.extra_valid_local,
        )
        evidence_text = selected_app_evidence_text(snapshot.build, snapshot.evidence)
        qa_text = selected_app_qa_text(snapshot.qa)
        print(f"Build drift detected · {evidence_text} · {qa_text} · quota {snapshot.quota}")
        print()
        menu_utils.print_section("Recommended")
        print("R) Refresh checklist [default]")
        print("Reason: installed build does not match the newest static plan.")
        print()
        print_plan_drift_warning(plan_drift, status_messages=status_messages)
        print_plan_drift_blocked_message(plan_drift, status_messages=status_messages)
        print()
        menu_utils.print_section("Review / inspect")
        print("H) Run history")
        print("G) Diagnostics")
        print()
        print("0) Back")
        choice = prompt_utils.get_choice(
            ["R", "H", "G", "0", "B"],
            default="R",
            casefold=True,
            invalid_message="Choose one of the listed actions.",
        ).upper()
        if choice in {"0", "B"}:
            return
        if choice == "R":
            _render_refresh_checklist(
                app=app,
                plan_drift=plan_drift,
                menu_utils=menu_utils,
            )
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "H":
            render_selected_app_recent_runs_fn(app.state)
            prompt_utils.press_enter_to_continue()
            continue
        if choice == "G":
            render_selected_app_diagnostics_fn(
                package_name=app.package_name,
                display_label=app.display_label,
                state=app.state,
                queue_action="refresh",
                db_active_sessions=app.db_active_sessions,
                db_historical_sessions=app.db_historical_sessions,
            )
            prompt_utils.press_enter_to_continue()
            continue


def _render_refresh_checklist(
    *,
    app: Any,
    plan_drift: dict[str, Any],
    menu_utils: Any,
) -> None:
    menu_utils.print_header("Refresh checklist", app.display_label)
    print("This app is blocked because the installed build does not match the newest static plan.")
    print()
    print("Current state")
    rows = plan_drift_rows(plan_drift, detailed_installed_build=False)
    menu_utils.print_table(["Field", "Value"], rows)
    print()
    print("To clear refresh:")
    print("  1. Back out to Main Menu.")
    print("  2. Open Device Inventory & Harvest.")
    print("  3. Refresh inventory if the snapshot is stale.")
    print("  4. Execute harvest and choose a scope that includes this app.")
    print("  5. Pull the current APK/build.")
    print("  6. Open Static Analysis Pipeline.")
    print("  7. Choose Analyze one app.")
    print("  8. Analyze this app/package.")
    print("  9. Return to Dynamic Analysis → App queue / next action.")
    print(" 10. Confirm this app no longer shows Build=drift / Action=refresh.")
    if bool(getattr(app, "has_identity_mismatch", False)):
        print()
        print("Caution:")
        print("  Identity mismatch context exists. Check diagnostics before reusing older evidence.")
    print()
    print("After refresh clears:")
    print("  Return to the app queue and follow the updated recommended action for this app.")


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
    if detected:
        return current_serial, str(details.get("label") or current_serial)

    menu_utils.print_menu(
        [
            menu_utils.MenuOption("1", "Keep selected device"),
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
