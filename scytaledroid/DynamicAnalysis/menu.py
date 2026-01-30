"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import adb_utils
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.evidence_store import filesystem_safe_slug
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Config import app_config
from pathlib import Path
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec
from scytaledroid.DynamicAnalysis.observers.proxy_capture import resolve_mitmdump_path
import json
import socket
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, list_categories, list_packages, load_profile_map
from scytaledroid.DynamicAnalysis.plans.loader import extract_plan_identity, SUPPORTED_SIGNATURE_VERSIONS


def dynamic_analysis_menu() -> None:
    options = [
        MenuOption("1", "Launch sandbox run"),
        MenuOption("2", "View recent dynamic sessions"),
        MenuOption("3", "Configure instrumentation"),
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
            devices, warnings = adb_utils.scan_devices()
            for warning in warnings:
                print(status_messages.status(warning, level="warn"))
            if not devices:
                print(status_messages.status("No devices detected via adb.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            device_options = [
                MenuOption(str(index + 1), adb_utils.get_device_label(device))
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
            print()
            menu_utils.print_header("Dynamic Run Scenario")
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
            print()
            menu_utils.print_header("Dynamic Run Observers")
            use_proxy = prompt_utils.prompt_yes_no("Enable proxy network capture (recommended)?", default=True)
            use_tcpdump = prompt_utils.prompt_yes_no("Enable device tcpdump capture (optional)?", default=False)
            use_logs = prompt_utils.prompt_yes_no("Enable system log capture?", default=True)
            observer_ids = []
            proxy_port = 8890
            if use_proxy:
                if not _preflight_proxy_capture(proxy_port):
                    proceed_without_proxy = prompt_utils.prompt_yes_no(
                        "Proxy capture unavailable. Continue without proxy capture?",
                        default=True,
                    )
                    if not proceed_without_proxy:
                        continue
                    use_proxy = False
                if use_proxy:
                    observer_ids.append("proxy_capture")
            if use_tcpdump:
                observer_ids.append("network_capture")
            if use_logs:
                observer_ids.append("system_log_capture")
            if not observer_ids:
                print(status_messages.status("Select at least one observer.", level="error"))
                prompt_utils.press_enter_to_continue()
                continue
            print()
            menu_utils.print_header("Dynamic Run Duration")
            duration_options = [
                MenuOption("1", "Short (90s)"),
                MenuOption("2", "Standard (120s)"),
                MenuOption("3", "Extended (180s)"),
            ]
            duration_spec = MenuSpec(items=duration_options, exit_label="Cancel", show_exit=True)
            menu_utils.render_menu(duration_spec)
            selection = prompt_utils.get_choice(["1", "2", "3", "0"], default="2")
            if selection == "0":
                continue
            duration_map = {"1": 90, "2": 120, "3": 180}
            duration_seconds = duration_map.get(selection, 120)
            label = {
                "1": "Short",
                "2": "Standard",
                "3": "Extended",
            }.get(selection, "Standard")
            package_name = _select_dynamic_target()
            if not package_name:
                continue
            static_override = prompt_utils.prompt_text(
                "Static run id (optional)",
                required=False,
                default="",
            )
            static_run_id = None
            if static_override:
                try:
                    static_run_id = int(static_override)
                except ValueError:
                    print(status_messages.status("Invalid static_run_id; leaving unset.", level="warn"))
                    static_run_id = None
            plan_path, selection_note = _resolve_plan_path(package_name, static_run_id)
            if plan_path:
                print(status_messages.status(f"Static plan: {plan_path}", level="info"))
            else:
                if selection_note:
                    print(status_messages.status(selection_note, level="warn"))
                else:
                    print(status_messages.status("No dynamic plan found for package.", level="warn"))
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
                static_run_id=static_run_id,
                clear_logcat=clear_logcat,
                proxy_port=proxy_port,
            )
            message = (
                f"Selected duration: {label} ({duration_seconds}s). "
                f"Session status: {result.status}."
            )
            print(status_messages.status(message, level="warn"))
            prompt_utils.press_enter_to_continue()
            continue

        print(status_messages.status("Dynamic analysis workflow not implemented yet.", level="warn"))
        prompt_utils.press_enter_to_continue()


def _select_dynamic_target() -> str | None:
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
    if choice == "1":
        package_name = _select_package_from_groups(groups, title="App selection")
        if package_name:
            return package_name
        return _prompt_custom_package()

    if choice == "2":
        package_name = _select_profile_package(groups)
        if package_name:
            return package_name
        return _prompt_custom_package()

    return _prompt_custom_package()


def _select_profile_package(groups) -> str | None:
    categories = list_categories(groups)
    if not categories:
        print(status_messages.status("No profile data available for selection.", level="warn"))
        return None
    print()
    print("Dynamic Run Scope (Profile)")
    print("-" * 86)
    rows = [[str(idx), category, str(count)] for idx, (category, count) in enumerate(categories, start=1)]
    table_utils.render_table(["#", "Profile", "Apps"], rows, compact=True)
    print(f"Status: profiles={len(categories)}")
    index = _choose_index("Select profile #", len(categories))
    if index is None:
        return None
    category_name, _ = categories[index]
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
    return _select_package_from_groups(scoped_groups, title=f"{category_name} apps")


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


def _fetch_static_run_row(static_run_id: int | None) -> dict[str, object]:
    if static_run_id is None:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        row = core_q.run_sql(
            """
            SELECT sar.id AS static_run_id,
                   sar.run_signature,
                   sar.run_signature_version,
                   sar.artifact_set_hash,
                   sar.base_apk_sha256,
                   sar.pipeline_version
            FROM static_analysis_runs sar
            WHERE sar.id=%s
            """,
            (static_run_id,),
            fetch="one_dict",
        )
        if isinstance(row, dict):
            return row
    except Exception:
        return {}
    return {}


def _resolve_plan_path(package_name: str, static_run_id: int | None) -> tuple[str | None, str | None]:
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    if not base_dir.exists():
        return None, "No dynamic plan directory found."

    slug = filesystem_safe_slug(package_name)
    candidates = sorted(base_dir.glob(f"{slug}-*.json"))
    if not candidates:
        return None, "No dynamic plans found for package."

    plan_rows: list[dict[str, object]] = []
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        identity = extract_plan_identity(payload)
        if str(identity.get("package") or "") != package_name:
            continue
        plan_rows.append({"path": candidate, "identity": identity})

    if not plan_rows:
        return None, "No dynamic plans match the selected package."

    if static_run_id is None:
        run_ids = sorted({row["identity"].get("static_run_id") for row in plan_rows if row["identity"].get("static_run_id")})
        if not run_ids:
            return None, "No static_run_id found in plans; regenerate plan."
        if len(run_ids) > 1:
            return None, "Multiple static_run_id values found; specify static_run_id."
        static_run_id = int(run_ids[0])

    db_row = _fetch_static_run_row(static_run_id)
    if not db_row:
        return None, "No static_analysis_runs row found for static_run_id; run static analysis first."
    db_signature = db_row.get("run_signature")
    db_sig_version = db_row.get("run_signature_version")
    if not db_signature or not db_sig_version:
        return None, "static_analysis_runs missing run_signature or version; run migrations."
    if db_sig_version not in SUPPORTED_SIGNATURE_VERSIONS:
        return None, f"Unsupported run_signature_version: {db_sig_version}"

    matching = []
    for row in plan_rows:
        ident = row["identity"]
        if str(ident.get("static_run_id")) != str(static_run_id):
            continue
        if str(ident.get("run_signature")) != str(db_signature):
            continue
        if str(ident.get("run_signature_version")) != str(db_sig_version):
            continue
        matching.append(row["path"])

    if not matching:
        note = "No plan matches static_run_id + run_signature; regenerate plan."
        if _prompt_legacy_plan_selection():
            legacy = _resolve_latest_plan_path_legacy(package_name, static_run_id)
            if legacy:
                _emit_legacy_plan_selection(package_name, static_run_id, legacy)
                return legacy, "LEGACY PLAN SELECTION ENABLED — nondeterministic behavior"
        return None, note

    if len(matching) > 1:
        note = "Multiple plans found for static_run_id; specify plan_id or regenerate plan."
        if _prompt_legacy_plan_selection():
            legacy = _resolve_latest_plan_path_legacy(package_name, static_run_id)
            if legacy:
                _emit_legacy_plan_selection(package_name, static_run_id, legacy)
                return legacy, "LEGACY PLAN SELECTION ENABLED — nondeterministic behavior"
        return None, note

    return str(matching[0]), None


def _resolve_latest_plan_path_legacy(package_name: str, static_run_id: int | None) -> str | None:
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    if not base_dir.exists():
        return None
    slug = filesystem_safe_slug(package_name)
    candidates = sorted(base_dir.glob(f"{slug}-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        return None
    if static_run_id is None:
        return str(candidates[0])
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(payload.get("static_run_id")) == str(static_run_id):
            return str(candidate)
    return None


def _prompt_legacy_plan_selection() -> bool:
    message = "Allow legacy plan selection by mtime? (nondeterministic)"
    return prompt_utils.prompt_yes_no(message, default=False)


def _emit_legacy_plan_selection(
    package_name: str,
    static_run_id: int | None,
    plan_path: str,
) -> None:
    print(
        status_messages.status(
            "LEGACY PLAN SELECTION ENABLED — nondeterministic behavior",
            level="warn",
        )
    )
    log.warning(
        "Legacy plan selection enabled",
        category="dynamic",
        extra={
            "event": "plan.selection",
            "mode": "legacy_mtime",
            "package": package_name,
            "static_run_id": static_run_id,
            "plan_path": plan_path,
        },
    )


def _preflight_proxy_capture(port: int) -> bool:
    mitm_bin, hint = resolve_mitmdump_path()
    if mitm_bin is None:
        message = "mitmdump not found."
        if hint:
            message = f"{message} {hint}"
        print(status_messages.status(message, level="warn"))
        return False
    if not _is_port_free(port):
        print(status_messages.status(f"Proxy port {port} is already in use.", level="warn"))
        return False
    return True


def _is_port_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        sock.close()
    return True
