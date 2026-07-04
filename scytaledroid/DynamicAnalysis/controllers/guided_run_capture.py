"""Capture setup, drift rendering, and live-capture wiring helpers."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.capture.state import CaptureState, ObserverStatus
from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_evidence_text,
    selected_app_qa_text,
)
from scytaledroid.Utils.DisplayUtils.summary_cards import print_summary_card, summary_item

_FOREGROUND_READY_TIMEOUT_S = 12.0
_FOREGROUND_READY_POLL_S = 1.0


def _drift_evidence_text(build: str, evidence: str) -> str:
    evidence_key = str(evidence or "").strip()
    if evidence_key == "local+db":
        return "tracked-build evidence (local+db)"
    if evidence_key == "db-only":
        return "tracked-build evidence (db-only)"
    if evidence_key in {"empty", "none"}:
        return "no tracked-build evidence"
    return selected_app_evidence_text(build, evidence)


def _drift_build_summary(plan_drift: dict[str, Any]) -> str:
    observed_vc = str(plan_drift.get("observed_version_code") or "").strip() or "unknown"
    expected_vc = str(plan_drift.get("expected_version_code") or "").strip() or "unknown"
    return f"Installed build {observed_vc} · tracked static-plan build {expected_vc}"


def _latest_harvested_version_code(package_name: str) -> str | None:
    package = str(package_name or "").strip()
    if not package:
        return None
    root = Path(app_config.DATA_DIR) / "device_apks"
    if not root.exists():
        return None
    best_num: int | None = None
    best_text: str | None = None
    for manifest_path in root.glob(f"*/runs/*/{package}/**/harvest_package_manifest.json"):
        match = re.search(r"_v(\d+)(?:_|$)", manifest_path.parent.name)
        if not match:
            continue
        version_text = str(match.group(1) or "").strip()
        if not version_text:
            continue
        try:
            version_num = int(version_text)
        except ValueError:
            continue
        if best_num is None or version_num > best_num:
            best_num = version_num
            best_text = version_text
    return best_text


def _drift_harvest_context(package_name: str, plan_drift: dict[str, Any]) -> list[str]:
    observed_vc = str(plan_drift.get("observed_version_code") or "").strip() or "unknown"
    harvested_vc = _latest_harvested_version_code(package_name)
    if not harvested_vc:
        return ["No harvested APK for this app is present in the workspace yet."]
    if harvested_vc == observed_vc:
        return [f"Workspace harvest already includes installed build {observed_vc}."]
    return [
        f"Newest harvested APK in workspace: {harvested_vc}",
        f"No harvested APK for installed build {observed_vc} is present in this workspace yet.",
    ]


def read_device_foreground_package(device_serial: str | None) -> str | None:
    serial = str(device_serial or "").strip()
    if not serial:
        return None
    try:
        from scytaledroid.DeviceAnalysis.adb import client as adb_client

        if not adb_client.is_available():
            return None
        completed = adb_client.run_shell_command(serial, ["dumpsys", "window"], timeout=10)
        text = str(getattr(completed, "stdout", "") or "")
    except Exception:
        return None
    for line in text.splitlines():
        if "mCurrentFocus" not in line and "mFocusedApp" not in line:
            continue
        match = re.search(r"u0\s+([a-zA-Z0-9_.]+)/", line)
        if match:
            return str(match.group(1))
    return None


def launch_package_to_foreground(device_serial: str | None, package_name: str | None) -> None:
    serial = str(device_serial or "").strip()
    package = str(package_name or "").strip()
    if not serial or not package:
        return
    try:
        from scytaledroid.DeviceAnalysis.adb import shell as adb_shell

        adb_shell.run_shell(
            serial,
            [
                "monkey",
                "-p",
                package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            timeout=10,
        )
    except Exception:
        return


def target_foreground_label(*, package_name: str, static_plan: dict[str, object] | None) -> str:
    plan = static_plan if isinstance(static_plan, dict) else {}
    for key in ("app_label", "display_label", "label"):
        value = str(plan.get(key) or "").strip()
        if value:
            return value
    return str(package_name or "target app").strip() or "target app"


def build_capture_state(
    *,
    app_name: str,
    package_name: str,
    expected_package: str,
    version_code: str | None,
    phase: str,
    target_duration_s: int | None,
    minimum_duration_s: int | None,
    observer_status: ObserverStatus | None = None,
) -> CaptureState:
    return CaptureState(
        app_name=str(app_name or package_name or "target app").strip() or "target app",
        package_name=str(package_name or "").strip(),
        expected_package=str(expected_package or package_name or "").strip(),
        version_code=str(version_code).strip() if version_code is not None else None,
        phase=str(phase or "Manual capture").strip() or "Manual capture",
        target_duration_s=int(target_duration_s) if target_duration_s is not None else None,
        minimum_duration_s=int(minimum_duration_s) if minimum_duration_s is not None else None,
        observer_status=observer_status or ObserverStatus(),
    )


def make_runtime_foreground_provider(device_serial: str | None) -> Callable[[], str | None]:
    return lambda: read_device_foreground_package(device_serial)


def make_runtime_relaunch_callback(
    *,
    device_serial: str | None,
    package_name: str,
    app_name: str,
) -> Callable[[CaptureState], str | None]:
    def _callback(_state: CaptureState) -> str | None:
        launch_package_to_foreground(device_serial, package_name)
        return f"Returning {app_name} to foreground..."

    return _callback


def make_runtime_observer_status_provider(
    *,
    pcapdroid_status: str = "running",
    logcat_status: str = "running",
    pcap_bytes_provider: Callable[[], int | None] | None = None,
) -> Callable[[CaptureState], ObserverStatus]:
    def _provider(_state: CaptureState) -> ObserverStatus:
        pcap_bytes = pcap_bytes_provider() if pcap_bytes_provider is not None else None
        return ObserverStatus(
            pcapdroid=pcapdroid_status,
            logcat=logcat_status,
            pcap_bytes=pcap_bytes,
        )

    return _provider


def ensure_target_foreground_before_capture(
    *,
    device_serial: str | None,
    package_name: str,
    app_name: str,
    static_plan: dict[str, object] | None,
    on_protocol_event: Callable[[str, dict[str, object]], None] | None = None,
    prompt_continue_fn: Callable[[str], None],
    status_printer: Callable[[str, str], None],
    read_foreground_fn: Callable[[str | None], str | None] = read_device_foreground_package,
    launch_callback: Callable[[str | None, str | None], None] = launch_package_to_foreground,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    serial = str(device_serial or "").strip()
    package = str(package_name or "").strip()
    if not serial or not package:
        return
    target_label = target_foreground_label(package_name=package, static_plan=static_plan)
    from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import PCAPDROID_PACKAGE

    while True:
        waited = False
        attempted_return = False
        actual_pkg: str | None = None
        deadline = float(clock()) + _FOREGROUND_READY_TIMEOUT_S
        while float(clock()) < deadline:
            actual_pkg = read_foreground_fn(serial)
            if actual_pkg is None:
                status_printer(
                    "Foreground verification unavailable; continuing without a live foreground gate.",
                    "warn",
                )
                return
            if actual_pkg == package:
                if on_protocol_event:
                    on_protocol_event(
                        "TARGET_FOREGROUND_READY",
                        {
                            "expected_package": package,
                            "actual_package": actual_pkg,
                        },
                    )
                return
            if actual_pkg == PCAPDROID_PACKAGE and not attempted_return:
                status_printer(f"Returning {target_label} to foreground...", "info")
                launch_callback(serial, package)
                attempted_return = True
                if on_protocol_event:
                    on_protocol_event(
                        "TARGET_FOREGROUND_RETURN_ATTEMPT",
                        {
                            "expected_package": package,
                            "actual_package": actual_pkg,
                        },
                    )
            elif not waited:
                status_printer(f"Waiting for {target_label} foreground...", "info")
                waited = True
            sleep(_FOREGROUND_READY_POLL_S)
        actual_display = str(actual_pkg or "unknown").strip() or "unknown"
        status_printer(
            f"Foreground still shows {actual_display}. Return {target_label} to the foreground before capture starts.",
            "warn",
        )
        prompt_continue_fn(f"Return {target_label} to foreground, then press Enter to re-check")


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
    observed_vc = str(plan_drift.get("observed_version_code") or "").strip() or "unknown"
    expected_vc = str(plan_drift.get("expected_version_code") or "").strip() or "unknown"
    print_summary_card(
        display_label,
        [
            summary_item("Status", "installed build drift", value_style="warning"),
            summary_item("Installed", observed_vc, value_style="accent"),
            summary_item("Tracked plan", expected_vc, value_style="muted"),
            summary_item("Static run", str(plan_drift.get("static_run_id") or "unknown"), value_style="muted"),
        ],
        subtitle="Static plan / device drift",
    )
    print()
    print_plan_drift_warning(plan_drift, status_messages=status_messages)
    print_plan_drift_blocked_message(plan_drift, status_messages=status_messages)


def _drift_workbench_summary_items(
    *,
    evidence_text: str,
    qa_text: str,
    quota: str,
    plan_drift: dict[str, Any],
) -> list[Any]:
    observed_vc = str(plan_drift.get("observed_version_code") or "").strip() or "unknown"
    expected_vc = str(plan_drift.get("expected_version_code") or "").strip() or "unknown"
    return [
        summary_item("Status", "installed build drift", value_style="warning"),
        summary_item("Installed", observed_vc, value_style="accent"),
        summary_item("Tracked plan", expected_vc, value_style="muted"),
        summary_item("Evidence", evidence_text, value_style="muted"),
        summary_item("QA", qa_text, value_style="muted"),
        summary_item("Quota", quota, value_style="muted"),
    ]


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
        evidence_text = _drift_evidence_text(snapshot.build, snapshot.evidence)
        qa_text = selected_app_qa_text(snapshot.qa)
        print_summary_card(
            app.display_label,
            _drift_workbench_summary_items(
                evidence_text=evidence_text,
                qa_text=qa_text,
                quota=str(snapshot.quota),
                plan_drift=plan_drift,
            ),
            footer=_drift_build_summary(plan_drift),
        )
        for line in _drift_harvest_context(app.package_name, plan_drift):
            print(status_messages.status(line, level="info"))
        print()
        print_plan_drift_warning(plan_drift, status_messages=status_messages)
        print_plan_drift_blocked_message(plan_drift, status_messages=status_messages)
        print()
        menu_utils.print_section("Recommended")
        menu_utils.print_menu(
            [
                menu_utils.MenuOption(
                    "R",
                    "Refresh checklist",
                    description="installed build does not match the newest static plan",
                    badge="suggested",
                ),
            ],
            default="R",
            show_descriptions=False,
            show_exit=False,
            compact=True,
        )
        print()
        menu_utils.print_section("Review / inspect")
        menu_utils.print_menu(
            [
                menu_utils.MenuOption("H", "Run history", description="recent tracker-scoped runs"),
                menu_utils.MenuOption("G", "Diagnostics", description="study, capture, and quota detail"),
            ],
            show_descriptions=False,
            show_exit=False,
            compact=True,
        )
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
                status_messages=status_messages,
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
                latest_recent=app.latest_recent,
                has_identity_mismatch=bool(getattr(app, "has_identity_mismatch", False)),
                live_build_drift=True,
            )
            prompt_utils.press_enter_to_continue()
            continue


def _render_refresh_checklist(
    *,
    app: Any,
    plan_drift: dict[str, Any],
    menu_utils: Any,
    status_messages: Any,
) -> None:
    menu_utils.print_header("Refresh checklist", app.display_label)
    print(
        status_messages.status(
            "Blocked: installed build does not match the newest static plan. "
            "Counts below belong to the tracked static-plan build, not the newly installed build.",
            level="warn",
        )
    )
    print()
    menu_utils.print_section("Current state")
    rows = plan_drift_rows(plan_drift, detailed_installed_build=False)
    menu_utils.print_table(["Field", "Value"], rows)
    for line in _drift_harvest_context(app.package_name, plan_drift):
        print(status_messages.status(line, level="info"))
    print()
    menu_utils.print_section("To clear refresh")
    steps = [
        "Back out to Main Menu.",
        "Open Device Inventory & Harvest.",
        "Refresh inventory if the snapshot is stale.",
        "Execute harvest and choose a scope that includes this app.",
        "Pull the current APK/build.",
        "Open Static Analysis Pipeline.",
        "Choose Analyze one app.",
        "Analyze this app/package.",
        "Return to Dynamic Analysis → App queue / next action.",
        "Confirm this app no longer shows Status=refresh in the app queue.",
    ]
    for index, step_text in enumerate(steps, start=1):
        print(status_messages.step(step_text, progress=(index, len(steps))))
    if bool(getattr(app, "has_identity_mismatch", False)):
        print()
        print(
            status_messages.status(
                "Caution: identity mismatch context exists. Check diagnostics before reusing older evidence.",
                level="warn",
            )
        )
    print()
    print(
        status_messages.status(
            "After refresh clears: return to the app queue and follow the updated recommended action. "
            "The refreshed app version should be treated as the new current build target for dataset-mode runs.",
            level="info",
        )
    )


def print_capture_device_choice(
    *,
    details: dict[str, str],
    detected: bool,
    menu_utils: Any,
    status_messages: Any,
) -> None:
    print_summary_card(
        "Capture device",
        [
            summary_item("Device", details["name"], value_style="accent"),
            summary_item("Serial", details["serial"], value_style="muted"),
            summary_item("Android", details["android"], value_style="muted"),
            summary_item("Type", details["type"], value_style="muted"),
            summary_item(
                "ADB",
                "connected" if detected else "not detected",
                value_style="success" if detected else "warning",
            ),
        ],
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
            menu_utils.MenuOption("1", "Keep selected device", description="wait for adb reconnect on current serial"),
            menu_utils.MenuOption("2", "Change device", description="pick a different capture device"),
        ],
        default="1",
        show_descriptions=False,
        show_exit=False,
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
    print_summary_card(
        app.display_label,
        [
            summary_item("Package", app.package_name, value_style="muted"),
        ],
        subtitle="Capture setup",
    )
    print()
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
    "build_capture_state",
    "choose_capture_device",
    "ensure_target_foreground_before_capture",
    "launch_package_to_foreground",
    "make_runtime_foreground_provider",
    "make_runtime_observer_status_provider",
    "make_runtime_relaunch_callback",
    "plan_drift_rows",
    "prepare_selected_app_capture",
    "print_capture_device_choice",
    "print_plan_drift_blocked_message",
    "print_plan_drift_warning",
    "read_device_foreground_package",
    "render_selected_app_drift_workbench",
    "render_static_plan_build_drift_block",
    "target_foreground_label",
]
