"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import adb_devices, adb_shell, adb_status
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.DynamicAnalysis.plan_selection import (
    print_plan_selection_banner,
    resolve_plan_selection,
)
from scytaledroid.DynamicAnalysis.profile_loader import load_db_profiles, load_profile_packages
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec
from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import PCAPDROID_PACKAGE
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, list_categories, list_packages, load_profile_map

_DEVICE_STATUS_CACHE: dict[str, dict[str, str]] = {}


def dynamic_analysis_menu() -> None:
    options = [
        MenuOption("1", "Launch sandbox run"),
        MenuOption("2", "View recent dynamic sessions"),
        MenuOption("3", "Configure instrumentation"),
        MenuOption("4", "Run Research Dataset Alpha (guided)"),
    ]

    while True:
        print()
        menu_utils.print_header("Dynamic Analysis")
        spec = MenuSpec(items=options, exit_label="Back", show_exit=True)
        menu_utils.render_menu(spec)
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"])

        if choice == "0":
            break

        if choice == "1":
            print()
            menu_utils.print_header("Dynamic Run Device")
            devices, warnings = adb_devices.scan_devices()
            for warning in warnings:
                print(status_messages.status(warning, level="warn"))
            if not devices:
                print(status_messages.status("No devices detected via adb.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            device_options = [
                MenuOption(str(index + 1), adb_devices.get_device_label(device))
                for index, device in enumerate(devices)
            ]
            device_spec = MenuSpec(items=device_options, exit_label="Cancel", show_exit=True)
            menu_utils.render_menu(device_spec)
            device_choice = prompt_utils.get_choice(
                [option.key for option in device_options] + ["0"],
                default="1",
            )
            if device_choice == "0":
                continue
            device_index = int(device_choice) - 1
            device_serial = devices[device_index].get("serial")
            if not device_serial:
                print(status_messages.status("Selected device missing serial.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            is_rooted = _print_root_status(device_serial)
            _print_network_status(device_serial)
            print()
            scenario_id = "basic_usage"
            duration_seconds = 0
            label = "Manual"
            menu_utils.print_header("Dynamic Run Scenario")
            print(status_messages.status("Tip: Basic usage is recommended for validation runs.", level="info"))
            scenario_options = [
                MenuOption("1", "Cold start"),
                MenuOption("2", "Basic usage"),
                MenuOption("3", "Permission trigger"),
            ]
            scenario_spec = MenuSpec(items=scenario_options, exit_label="Cancel", show_exit=True)
            menu_utils.render_menu(scenario_spec)
            scenario_choice = prompt_utils.get_choice(
                [option.key for option in scenario_options] + ["0"],
                default="2",
            )
            if scenario_choice == "0":
                continue
            scenario_id = {"1": "cold_start", "2": "basic_usage", "3": "permission_trigger"}.get(
                scenario_choice,
                "basic_usage",
            )
            selection = _select_dynamic_target()
            package_name = selection[0] if selection else None
            tier = selection[1] if selection else "exploration"
            if tier == "dataset":
                if prompt_utils.prompt_yes_no("Run as exploration instead of dataset?", default=False):
                    tier = "exploration"
            elif package_name == "com.zhiliaoapp.musically":
                if prompt_utils.prompt_yes_no("Mark this run as calibration?", default=True):
                    tier = "calibration"
            if not package_name:
                continue
            print()
            menu_utils.print_header("Dynamic Run Observers")
            use_pcapdroid = _device_has_pcapdroid(device_serial)
            if use_pcapdroid:
                print(
                    status_messages.status(
                        "PCAPdroid scope: app-only traffic (UID). If traffic is missing, consider full-device "
                        "capture for diagnostics.",
                        level="info",
                    )
                )
            else:
                print(status_messages.status("PCAPdroid not installed; VPN capture unavailable.", level="warn"))
            use_logs = True
            observer_ids = []
            if use_pcapdroid:
                observer_ids.append("pcapdroid_capture")
            if use_logs:
                observer_ids.append("system_log_capture")
            if not observer_ids:
                print(status_messages.status("Select at least one observer.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            plan_selection = resolve_plan_selection(package_name)
            if not plan_selection:
                prompt_utils.press_enter_to_continue()
                continue
            plan_path = plan_selection["plan_path"]
            static_run_id = plan_selection["static_run_id"]
            print_plan_selection_banner(plan_selection)
            clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)
            from .run_dynamic_analysis import run_dynamic_analysis

            result = run_dynamic_analysis(
                package_name,
                duration_seconds=duration_seconds,
                device_serial=device_serial,
                scenario_id=scenario_id,
                observer_ids=tuple(observer_ids),
                interactive=True,
                plan_path=plan_path,
                tier=tier,
                static_run_id=static_run_id,
                clear_logcat=clear_logcat,
            )
            print_run_summary(result, label)
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "4":
            _run_guided_dataset_run()
            prompt_utils.press_enter_to_continue()
            continue

            prompt_utils.press_enter_to_continue()
            continue

        print(status_messages.status("Dynamic analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()


def _select_dynamic_target() -> tuple[str, str] | None:
    print()
    menu_utils.print_header("Dynamic Run Target")
    target_options = [
        MenuOption("1", "App (select from available artifacts)"),
        MenuOption("2", "Profile (select app from profile)"),
        MenuOption("3", "Custom package name"),
    ]
    target_spec = MenuSpec(items=target_options, exit_label="Cancel", show_exit=True)
    menu_utils.render_menu(target_spec)
    choice = prompt_utils.get_choice([option.key for option in target_options] + ["0"], default="1")
    if choice == "0":
        return None

    groups = group_artifacts()
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in load_profile_packages("RESEARCH_DATASET_ALPHA")}
    except Exception:
        dataset_pkgs = set()

    if choice == "1":
        package_name = _select_package_from_groups(groups, title="App selection")
        if package_name:
            if package_name.lower() in dataset_pkgs:
                run_as_dataset = prompt_utils.prompt_yes_no(
                    "This app is in Research Dataset Alpha. Run as dataset tier?",
                    default=True,
                )
                return (package_name, "dataset" if run_as_dataset else "exploration")
            return (package_name, "exploration")
        package_name = _prompt_custom_package()
        if package_name:
            return _resolve_custom_tier(package_name, dataset_pkgs)
        return None

    if choice == "2":
        profile_selection = _select_profile_package(groups)
        if profile_selection:
            package_name, profile_key = profile_selection
            tier = "dataset" if profile_key == "RESEARCH_DATASET_ALPHA" else "exploration"
            return (package_name, tier)
        package_name = _prompt_custom_package()
        if package_name:
            return _resolve_custom_tier(package_name, dataset_pkgs)
        return None

    package_name = _prompt_custom_package()
    if package_name:
        return _resolve_custom_tier(package_name, dataset_pkgs)
    return None


def _run_guided_dataset_run() -> None:
    print()
    menu_utils.print_header("Guided Dataset Run")
    devices, warnings = adb_devices.scan_devices()
    for warning in warnings:
        print(status_messages.status(warning, level="warn"))
    if not devices:
        print(status_messages.status("No devices detected via adb.", level="error"))
        return

    device_options = [
        MenuOption(str(index + 1), adb_devices.get_device_label(device))
        for index, device in enumerate(devices)
    ]
    device_spec = MenuSpec(items=device_options, exit_label="Cancel", show_exit=True)
    menu_utils.render_menu(device_spec)
    device_choice = prompt_utils.get_choice(
        [option.key for option in device_options] + ["0"],
        default="1",
    )
    if device_choice == "0":
        return
    device_index = int(device_choice) - 1
    device_serial = devices[device_index].get("serial")
    if not device_serial:
        print(status_messages.status("Selected device missing serial.", level="error"))
        return

    is_rooted = _print_root_status(device_serial)
    _print_network_status(device_serial)

    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Dataset (guided)"

    groups = group_artifacts()
    dataset_pkgs = load_profile_packages("RESEARCH_DATASET_ALPHA")
    if not dataset_pkgs:
        print(status_messages.status("Research Dataset Alpha profile has no apps.", level="warn"))
        return

    available = {group.package_name.lower() for group in groups if group.package_name}
    scoped_groups = tuple(
        group for group in groups if group.package_name and group.package_name.lower() in available.intersection(dataset_pkgs)
    )
    if not scoped_groups:
        print(
            status_messages.status(
                "No APK artifacts available for Research Dataset Alpha. Pull APKs or use Custom package name.",
                level="warn",
            )
        )
        return

    package_name = _select_package_from_groups(scoped_groups, title="Research Dataset Alpha apps")
    if not package_name:
        return

    tier = "dataset"

    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids: list[str] = []
    use_pcapdroid = _device_has_pcapdroid(device_serial)
    if use_pcapdroid:
        print(
            status_messages.status(
                "PCAPdroid scope: app-only traffic (UID). If traffic is missing, consider full-device "
                "capture for diagnostics.",
                level="info",
            )
        )
    else:
        print(status_messages.status("PCAPdroid not installed; VPN capture unavailable.", level="warn"))
    use_logs = True
    if use_pcapdroid:
        observer_ids.append("pcapdroid_capture")
    if use_logs:
        observer_ids.append("system_log_capture")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return

    plan_selection = resolve_plan_selection(package_name)
    if not plan_selection:
        return
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    print_plan_selection_banner(plan_selection)
    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)

    from .run_dynamic_analysis import run_dynamic_analysis

    result = run_dynamic_analysis(
        package_name,
        duration_seconds=duration_seconds,
        device_serial=device_serial,
        scenario_id=scenario_id,
        observer_ids=tuple(observer_ids),
        interactive=True,
        plan_path=plan_path,
        tier=tier,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
    )
    print_run_summary(result, label)
    if result.dynamic_run_id:
        _print_tier1_qa_result(result.dynamic_run_id)


def _print_tier1_qa_result(dynamic_run_id: str) -> None:
    row = run_sql(
        """
        SELECT
          ds.dynamic_run_id,
          ds.status,
          ds.tier,
          ds.sampling_rate_s,
          ds.expected_samples,
          ds.captured_samples,
          ds.sample_max_gap_s,
          MAX(CASE WHEN i.issue_code = 'telemetry_partial_samples' THEN 1 ELSE 0 END) AS telemetry_partial
        FROM dynamic_sessions ds
        LEFT JOIN dynamic_session_issues i
          ON i.dynamic_run_id = ds.dynamic_run_id
        WHERE ds.dynamic_run_id = %s
        GROUP BY ds.dynamic_run_id, ds.status, ds.tier, ds.sampling_rate_s,
                 ds.expected_samples, ds.captured_samples, ds.sample_max_gap_s
        """,
        (dynamic_run_id,),
        fetch="one",
        dictionary=True,
    )
    if not row:
        print(status_messages.status("Tier-1 QA check unavailable for this run.", level="warn"))
        return

    failures = []
    if row.get("tier") != "dataset":
        failures.append("tier_not_dataset")
    if row.get("status") != "success":
        failures.append("status_not_success")
    ratio = _safe_ratio(row.get("captured_samples"), row.get("expected_samples"))
    if ratio is None:
        failures.append("missing_capture_ratio")
    elif ratio < 0.90:
        failures.append("low_capture_ratio")
    try:
        sampling_rate = float(row.get("sampling_rate_s"))
        max_gap = float(row.get("sample_max_gap_s"))
        if max_gap > (sampling_rate * 2):
            failures.append("max_gap_exceeded")
    except (TypeError, ValueError):
        failures.append("missing_gap_stats")
    if row.get("telemetry_partial"):
        failures.append("telemetry_partial_samples")

    if failures:
        print(
            status_messages.status(
                f"Tier-1 QA: FAIL ({', '.join(failures)})",
                level="warn",
            )
        )
    else:
        print(status_messages.status("Tier-1 QA: PASS", level="success"))


def _safe_ratio(captured: object, expected: object) -> float | None:
    try:
        cap = float(captured)
        exp = float(expected)
    except (TypeError, ValueError):
        return None
    if exp == 0:
        return None
    return cap / exp


def _resolve_custom_tier(package_name: str, dataset_pkgs: set[str]) -> tuple[str, str]:
    if package_name.lower() in dataset_pkgs:
        run_as_dataset = prompt_utils.prompt_yes_no(
            "This app is in Research Dataset Alpha. Run as dataset tier?",
            default=True,
        )
        return (package_name, "dataset" if run_as_dataset else "exploration")
    run_as_dataset = prompt_utils.prompt_yes_no(
        "Run this custom package as dataset tier?",
        default=False,
    )
    return (package_name, "dataset" if run_as_dataset else "exploration")


def _select_profile_package(groups) -> tuple[str, str | None] | None:
    categories = list_categories(groups)
    db_profiles = load_db_profiles()
    if not categories and not db_profiles:
        print(status_messages.status("No profile data available for selection.", level="warn"))
        return None
    print()
    print("Dynamic Run Scope (Profile)")
    print("-" * 86)
    available_counts = {label: count for label, count in categories}
    profile_rows = []
    for profile in db_profiles:
        profile_rows.append(
            {
                "label": profile["display_name"],
                "key": profile["profile_key"],
                "db_count": profile["app_count"],
                "available_count": available_counts.get(profile["display_name"], 0),
            }
        )
    for label, count in categories:
        if any(row["label"] == label for row in profile_rows):
            continue
        profile_rows.append(
            {
                "label": label,
                "key": None,
                "db_count": count,
                "available_count": count,
            }
        )
    profile_rows.sort(
        key=lambda row: (
            0 if row.get("key") == "RESEARCH_DATASET_ALPHA" else 1,
            row["label"].lower(),
        )
    )
    rows = [
        [str(idx), row["label"], str(row["db_count"]), str(row["available_count"])]
        for idx, row in enumerate(profile_rows, start=1)
    ]
    table_utils.render_table(["#", "Profile", "Apps (db)", "Available"], rows, compact=True)
    index = _choose_index("Select profile #", len(profile_rows))
    if index is None:
        return None
    selected = profile_rows[index]
    profile_key = selected.get("key")
    if profile_key:
        if profile_key == "RESEARCH_DATASET_ALPHA":
            try:
                from scytaledroid.Database.db_utils.menu_actions import ensure_dynamic_tier_column

                ensure_dynamic_tier_column(prompt_user=True)
            except Exception:
                print(
                    status_messages.status(
                        "Unable to verify dynamic_sessions.tier column; dataset tagging may be unavailable.",
                        level="warn",
                    )
                )
        packages = load_profile_packages(profile_key)
        if not packages:
            print(status_messages.status("No apps found for that profile.", level="warn"))
            return None
        available = {group.package_name.lower() for group in groups if group.package_name}
        scoped_groups = tuple(group for group in groups if group.package_name.lower() in available.intersection(packages))
        if not scoped_groups:
            print(
                status_messages.status(
                    "No APK artifacts available yet for that profile. Pull APKs or use Custom package name.",
                    level="warn",
                )
            )
            return None
        package_name = _select_package_from_groups(scoped_groups, title=f"{selected['label']} apps")
        if not package_name:
            return None
        return (package_name, profile_key)
    category_name = selected["label"]
    profile_map = load_profile_map(groups)
    scoped_groups = tuple(
        group
        for group in groups
        if (
            profile_map.get(group.package_name.lower())
            or group.category
            or "Uncategorized"
        )
        == category_name
    )
    if not scoped_groups:
        print(status_messages.status("No apps found for that profile.", level="warn"))
        return None
    package_name = _select_package_from_groups(scoped_groups, title=f"{category_name} apps")
    if not package_name:
        return None
    return (package_name, None)


def _select_package_from_groups(groups, *, title: str) -> str | None:
    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No apps available for selection.", level="warn"))
        return None
    print()
    menu_utils.print_header(title, "Select a package to run")
    rows = []
    for idx, (package, _version, count, app_label) in enumerate(packages, start=1):
        display = app_label or package
        rows.append([str(idx), display, package, str(count)])
    _render_package_table(rows)
    index = _choose_index("Select app #", len(packages))
    if index is None:
        return None
    package_name, _, _, _ = packages[index]
    return package_name


def _render_package_table(rows, *, max_preview: int = 15) -> None:
    if len(rows) <= max_preview:
        table_utils.render_table(["#", "App", "Package", "Artifacts"], rows, compact=True)
        return
    preview = rows[:max_preview]
    table_utils.render_table(["#", "App", "Package", "Artifacts"], preview, compact=True)
    response = prompt_utils.prompt_text("Press L to list all, or Enter to continue", required=False)
    if response.strip().lower() == "l":
        table_utils.render_table(["#", "App", "Package", "Artifacts"], rows, compact=True)


def _choose_index(prompt: str, total: int) -> int | None:
    if total <= 0:
        return None
    options = [str(idx) for idx in range(1, total + 1)]
    choice = prompt_utils.get_choice(options + ["0"], default="1", prompt=f"{prompt} ")
    if choice == "0":
        return None
    return int(choice) - 1


def _prompt_custom_package() -> str:
    return prompt_utils.prompt_text(
        "Package name",
        required=True,
        error_message="Please provide a package name.",
    )


def _device_has_pcapdroid(device_serial: str) -> bool:
    try:
        output = adb_shell.run_shell(device_serial, ["pm", "path", PCAPDROID_PACKAGE]).strip()
    except Exception:
        return False
    return output.startswith("package:")


def _print_root_status(device_serial: str, *, force: bool = False) -> bool:
    stats = adb_status.get_device_stats(device_serial)
    root_state = (stats.get("is_rooted") or "Unknown").strip().upper()
    if root_state == "YES":
        message = "Device root: YES (advanced capture available)."
        level = "success"
        is_rooted = True
    elif root_state == "NO":
        message = "Device root: NO (non-root mode)."
        level = "info"
        is_rooted = False
    else:
        message = "Device root: Unknown."
        level = "warn"
        is_rooted = False
    cached = _DEVICE_STATUS_CACHE.get(device_serial, {})
    if force or cached.get("root") != message:
        print(status_messages.status(message, level=level))
        cached["root"] = message
        _DEVICE_STATUS_CACHE[device_serial] = cached
    return is_rooted


def _print_network_status(device_serial: str, *, force: bool = False) -> None:
    details = []
    try:
        status = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
    except Exception:
        print(status_messages.status("Network status: unable to read connectivity state.", level="warn"))
        return
    if "validated" in status:
        details.append("validated")
    if "not_vpn" in status or "not vpn" in status:
        details.append("not_vpn")
    if "not connected" in status:
        print(status_messages.status("Network status: not connected.", level="warn"))
        return
    label = "Network status: " + (", ".join(details) if details else "unknown")
    cached = _DEVICE_STATUS_CACHE.get(device_serial, {})
    if force or cached.get("network") != label:
        print(status_messages.status(label, level="info"))
        cached["network"] = label
        _DEVICE_STATUS_CACHE[device_serial] = cached
