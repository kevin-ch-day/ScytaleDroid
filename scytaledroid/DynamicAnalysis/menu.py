"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis import adb_devices, adb_shell, adb_status
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.evidence_store import filesystem_safe_slug
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Config import app_config
from pathlib import Path
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec
from scytaledroid.DynamicAnalysis.observers.proxy_capture import resolve_mitmdump_path
from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import PCAPDROID_PACKAGE
import json
import socket
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, list_categories, list_packages, load_profile_map
from scytaledroid.Database.db_core import run_sql
from scytaledroid.DynamicAnalysis.plans.loader import extract_plan_identity, SUPPORTED_SIGNATURE_VERSIONS


def dynamic_analysis_menu() -> None:
    options = [
        MenuOption("1", "Launch sandbox run"),
        MenuOption("2", "View recent dynamic sessions"),
        MenuOption("3", "Configure instrumentation"),
        MenuOption("4", "Run Research Dataset Alpha (guided)"),
        MenuOption("9", "Force FAIL (dev/test)"),
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
            use_pcapdroid = False
            if _device_has_pcapdroid(device_serial):
                use_pcapdroid = prompt_utils.prompt_yes_no(
                    "Enable VPN capture via PCAPdroid (recommended for non-root)?",
                    default=not is_rooted,
                )
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

            use_proxy = False
            proxy_notice = None
            if not use_pcapdroid:
                proxy_default, proxy_notice = _proxy_default_for_package(package_name, is_rooted)
                if proxy_notice:
                    print(status_messages.status(proxy_notice, level="warn"))
                use_proxy = prompt_utils.prompt_yes_no(
                    "Enable proxy network capture? (may break pinned apps)",
                    default=proxy_default,
                )
                if use_proxy and proxy_notice:
                    confirm_proxy = prompt_utils.prompt_yes_no(
                        "Proceed with proxy capture anyway?",
                        default=False,
                    )
                    if not confirm_proxy:
                        use_proxy = False
            if _device_has_tcpdump(device_serial):
                use_tcpdump = prompt_utils.prompt_yes_no(
                    "Enable device tcpdump capture (requires root)?",
                    default=False,
                )
            else:
                use_tcpdump = False
                print(
                    status_messages.status(
                        "tcpdump not available on device (non-root). Network capture disabled.",
                        level="warn",
                    )
                )
            use_logs = prompt_utils.prompt_yes_no("Enable system log capture?", default=True)
            observer_ids = []
            proxy_port = 8890
            if use_pcapdroid:
                observer_ids.append("pcapdroid_capture")
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
            plan_selection = _resolve_plan_selection(package_name)
            if not plan_selection:
                prompt_utils.press_enter_to_continue()
                continue
            plan_path = plan_selection["plan_path"]
            static_run_id = plan_selection["static_run_id"]
            _print_plan_selection_banner(plan_selection)
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
                proxy_port=proxy_port,
            )
            _print_run_summary(result, label)
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "4":
            _run_guided_dataset_run()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "9":
            _run_force_fail()
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
        dataset_pkgs = {pkg.lower() for pkg in _load_profile_packages("RESEARCH_DATASET_ALPHA")}
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
    dataset_pkgs = _load_profile_packages("RESEARCH_DATASET_ALPHA")
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
    use_pcapdroid = False
    if _device_has_pcapdroid(device_serial):
        use_pcapdroid = prompt_utils.prompt_yes_no(
            "Enable VPN capture via PCAPdroid?",
            default=not is_rooted,
        )
        if use_pcapdroid:
            print(
                status_messages.status(
                    "PCAPdroid scope: app-only traffic (UID). If traffic is missing, consider full-device capture "
                    "for diagnostics.",
                    level="info",
                )
            )
            observer_ids.append("pcapdroid_capture")
    else:
        print(status_messages.status("PCAPdroid not installed; VPN capture unavailable.", level="warn"))

    use_logs = prompt_utils.prompt_yes_no("Enable system log capture?", default=True)
    if use_logs:
        observer_ids.append("system_log_capture")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return

    plan_selection = _resolve_plan_selection(package_name)
    if not plan_selection:
        return
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    _print_plan_selection_banner(plan_selection)
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
        proxy_port=8890,
    )
    _print_run_summary(result, label)
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


def _run_force_fail() -> None:
    print()
    menu_utils.print_header("Force FAIL (dev/test)")
    print(status_messages.status("DEV/TEST MODE — generates a blocked run for validation proof.", level="warn"))
    confirm = prompt_utils.prompt_yes_no("Continue with forced FAIL?", default=False)
    if not confirm:
        print(status_messages.status("Force FAIL cancelled.", level="info"))
        return
    package_name = prompt_utils.prompt_text(
        "Package name",
        default="com.example.nonexistent.app",
        required=True,
        hint="Use any package name; this run will be blocked by plan validation.",
    )
    plan_path = _write_force_fail_plan(package_name)
    from .run_dynamic_analysis import run_dynamic_analysis

    result = run_dynamic_analysis(
        package_name,
        duration_seconds=30,
        scenario_id="basic_usage",
        observer_ids=tuple(),
        interactive=True,
        plan_path=plan_path,
    )
    _print_run_summary(result, "Forced FAIL")
    print(status_messages.status(f"Dev plan: {plan_path}", level="info"))


def _write_force_fail_plan(package_name: str) -> str:
    run_dir = Path(app_config.OUTPUT_DIR) / "dev_fail"
    run_dir.mkdir(parents=True, exist_ok=True)
    plan_path = run_dir / f"fail-plan-{filesystem_safe_slug(package_name)}.json"
    payload = {
        "package": package_name,
        "static_run_id": 0,
        "run_signature_version": "v0",
        "notes": "Intentionally invalid plan for validation FAIL proof.",
    }
    plan_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return str(plan_path)


def _select_profile_package(groups) -> tuple[str, str | None] | None:
    categories = list_categories(groups)
    db_profiles = _load_db_profiles()
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
        packages = _load_profile_packages(profile_key)
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


def _load_db_profiles() -> list[dict[str, object]]:
    try:
        rows = run_sql(
            (
                "SELECT p.profile_key, p.display_name, COUNT(a.package_name) AS app_count "
                "FROM android_app_profiles p "
                "LEFT JOIN apps a ON a.profile_key = p.profile_key "
                "WHERE p.is_active = 1 "
                "GROUP BY p.profile_key, p.display_name "
                "ORDER BY p.display_name"
            ),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return []
    profiles = []
    for row in rows or []:
        profiles.append(
            {
                "profile_key": str(row.get("profile_key") or "").strip(),
                "display_name": str(row.get("display_name") or "").strip() or "Unnamed profile",
                "app_count": int(row.get("app_count") or 0),
            }
        )
    return [row for row in profiles if row["profile_key"]]


def _load_profile_packages(profile_key: str) -> set[str]:
    try:
        rows = run_sql(
            "SELECT package_name FROM apps WHERE profile_key = %s",
            (profile_key,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return set()
    return {str(row.get("package_name") or "").strip().lower() for row in rows or [] if row.get("package_name")}


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


def _resolve_plan_selection(package_name: str) -> dict[str, object] | None:
    candidates, note = _load_plan_candidates(package_name)
    if not candidates:
        return _prompt_missing_baseline(package_name, note)

    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        key = candidate["identity_key"]
        grouped.setdefault(key, []).append(candidate)

    if len(grouped) == 1:
        only_key = next(iter(grouped))
        selection = _pick_newest_candidate(grouped[only_key])
        return _build_selection(selection)

    return _prompt_baseline_selection(package_name, candidates)


def _load_plan_candidates(package_name: str) -> tuple[list[dict[str, object]], str | None]:
    base_dir = Path(app_config.DATA_DIR) / "static_analysis" / "dynamic_plan"
    if not base_dir.exists():
        return [], "No dynamic plan directory found."

    slug = filesystem_safe_slug(package_name)
    paths = sorted(base_dir.glob(f"{slug}-*.json"))
    if not paths:
        return [], "No dynamic plans found for package."

    candidates: list[dict[str, object]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        identity = extract_plan_identity(payload)
        if str(identity.get("package") or "") != package_name:
            continue
        if identity.get("run_signature_version") not in SUPPORTED_SIGNATURE_VERSIONS:
            continue
        if not identity.get("run_signature") or not identity.get("artifact_set_hash"):
            continue
        generated_at = _parse_generated_at(payload.get("generated_at"))
        identity_key = _identity_key(identity)
        candidates.append(
            {
                "path": path,
                "identity": identity,
                "generated_at": generated_at,
                "identity_key": identity_key,
                "version_name": payload.get("version_name"),
                "version_code": payload.get("version_code"),
                "package_name": payload.get("package_name") or package_name,
                "run_signature_version": identity.get("run_signature_version"),
            }
        )
    if not candidates:
        return [], "No valid dynamic plan candidates found; regenerate plan."
    return candidates, None


def _pick_newest_candidate(candidates: list[dict[str, object]]) -> dict[str, object]:
    return sorted(
        candidates,
        key=lambda row: row.get("generated_at") or "",
        reverse=True,
    )[0]


def _build_selection(candidate: dict[str, object]) -> dict[str, object]:
    identity = candidate["identity"]
    return {
        "plan_path": str(candidate["path"]),
        "static_run_id": identity.get("static_run_id"),
        "package_name": identity.get("package"),
        "version_name": candidate.get("version_name"),
        "version_code": candidate.get("version_code"),
        "base_apk_sha256": identity.get("base_apk_sha256"),
        "artifact_set_hash": identity.get("artifact_set_hash"),
        "run_signature": identity.get("run_signature"),
        "run_signature_version": identity.get("run_signature_version"),
        "generated_at": candidate.get("generated_at"),
    }


def _prompt_baseline_selection(package_name: str, candidates: list[dict[str, object]]) -> dict[str, object] | None:
    print()
    menu_utils.print_header("Baseline selection required")
    print(
        status_messages.status(
            "Multiple baseline artifacts found for this app. Choose a baseline or run static analysis.",
            level="warn",
        )
    )
    rows = []
    sorted_candidates = sorted(candidates, key=lambda row: row.get("generated_at") or "", reverse=True)
    for idx, candidate in enumerate(sorted_candidates, start=1):
        rows.append(_format_candidate_row(idx, candidate))
    table_utils.render_table(
        ["#", "Version", "SHA256", "Bundle", "Generated"],
        rows,
        compact=True,
    )
    print()
    print("Options: [number] Select baseline  |  S Run static analysis  |  L Legacy mtime  |  0 Cancel")
    choice = prompt_utils.prompt_text("Select baseline", required=False).strip().lower()
    if choice == "s":
        from scytaledroid.StaticAnalysis.cli import static_analysis_menu

        static_analysis_menu()
        return None
    if choice == "l":
        legacy = _resolve_latest_plan_path_legacy(package_name, None)
        if legacy:
            _emit_legacy_plan_selection(package_name, None, legacy)
            return {"plan_path": legacy, "static_run_id": None, "package_name": package_name}
        print(status_messages.status("Legacy plan selection failed.", level="warn"))
        return None
    if choice == "0" or not choice:
        print(status_messages.status("Baseline selection cancelled.", level="warn"))
        return None
    try:
        index = int(choice) - 1
    except ValueError:
        print(status_messages.status("Invalid selection.", level="warn"))
        return None
    if index < 0 or index >= len(sorted_candidates):
        print(status_messages.status("Selection out of range.", level="warn"))
        return None
    return _build_selection(sorted_candidates[index])


def _prompt_missing_baseline(package_name: str, note: str | None) -> dict[str, object] | None:
    print(status_messages.status(note or "No dynamic plan found for package.", level="warn"))
    print()
    print("Options: S Run static analysis  |  0 Cancel")
    choice = prompt_utils.prompt_text("Selection", required=False).strip().lower()
    if choice == "s":
        from scytaledroid.StaticAnalysis.cli import static_analysis_menu

        static_analysis_menu()
        return None
    print(status_messages.status("Baseline selection cancelled.", level="warn"))
    return None


def _format_candidate_row(index: int, candidate: dict[str, object]) -> list[str]:
    identity = candidate["identity"]
    version = _format_version(candidate.get("version_name"), candidate.get("version_code"))
    sha_prefix = _prefix(identity.get("base_apk_sha256"))
    bundle_prefix = _prefix(identity.get("artifact_set_hash"))
    generated = candidate.get("generated_at") or "unknown"
    return [str(index), version, sha_prefix, bundle_prefix, str(generated)]


def _format_version(version_name: object, version_code: object) -> str:
    name = str(version_name) if version_name else "unknown"
    code = str(version_code) if version_code else "—"
    return f"{name} ({code})"


def _prefix(value: object, *, length: int = 4) -> str:
    text = str(value or "")
    if len(text) <= length * 2:
        return text or "—"
    return f"{text[:length]}…{text[-length:]}"


def _parse_generated_at(value: object) -> str | None:
    if not value:
        return None
    text = str(value)
    return text.replace("Z", "")


def _identity_key(identity: dict[str, object]) -> str:
    artifact_set = identity.get("artifact_set_hash")
    if artifact_set:
        return f"set:{artifact_set}"
    base_hash = identity.get("base_apk_sha256")
    return f"base:{base_hash}" if base_hash else "unknown"


def _print_plan_selection_banner(selection: dict[str, object]) -> None:
    print()
    menu_utils.print_header("Baseline selected")
    artifact = (
        f"SHA256 {_prefix(selection.get('base_apk_sha256'))} | "
        f"Bundle {_prefix(selection.get('artifact_set_hash'))}"
    )
    signature = f"{selection.get('run_signature_version') or '—'} / {_prefix(selection.get('run_signature'))}"
    generated = selection.get("generated_at") or "unknown"
    lines = [
        ("App", selection.get("package_name") or "unknown"),
        ("Version", _format_version(selection.get("version_name"), selection.get("version_code"))),
        ("Artifact", artifact),
        ("Signature", signature),
        ("Generated", str(generated)),
        ("Static run", str(selection.get("static_run_id") or "—")),
    ]
    status_messages.print_strip("Baseline", lines, width=70)
    print(
        status_messages.status(
            "Baseline resolved by artifact identity. If the app was updated, run static analysis.",
            level="info",
        )
    )


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


def _print_run_summary(result, duration_label: str) -> None:
    status = result.status or "unknown"
    duration_seconds = result.elapsed_seconds or result.duration_seconds
    print()
    menu_utils.print_header("Dynamic run summary")
    lines = [
        ("Package", result.package_name or "unknown"),
        ("Run ID", result.dynamic_run_id or "unknown"),
        ("Duration", f"{duration_label} ({duration_seconds}s)"),
        ("Status", status),
    ]
    if result.evidence_path:
        lines.append(("Evidence", result.evidence_path))
    status_messages.print_strip("Session", lines, width=70)

    run_dir = Path(result.evidence_path) if result.evidence_path else None
    manifest = _load_manifest(run_dir) if run_dir else None
    summary_payload = _load_summary(run_dir) if run_dir else None
    if manifest:
        operator = manifest.get("operator") or {}
        telemetry_stats = operator.get("telemetry_stats") or {}
        sampling_rate = operator.get("sampling_rate_s")
        if telemetry_stats:
            expected = telemetry_stats.get("expected_samples")
            captured = telemetry_stats.get("captured_samples")
            max_gap = telemetry_stats.get("sample_max_gap_s")
            avg_delta = telemetry_stats.get("sample_avg_delta_s")
            sampling_duration = telemetry_stats.get("sampling_duration_seconds")
            ratio = None
            if expected and captured is not None:
                try:
                    ratio = float(captured) / float(expected)
                except Exception:
                    ratio = None
            telemetry_lines = []
            if sampling_rate:
                telemetry_lines.append(f"Sampling rate: {sampling_rate}s")
            if sampling_duration is not None:
                try:
                    telemetry_lines.append(f"Sampling window: {float(sampling_duration):.0f}s")
                except Exception:
                    telemetry_lines.append(f"Sampling window: {sampling_duration}s")
            if expected is not None and captured is not None:
                telemetry_lines.append(f"Samples: {captured}/{expected}")
            if ratio is not None:
                telemetry_lines.append(f"Capture ratio: {ratio:.3f}")
            if max_gap is not None:
                telemetry_lines.append(f"Max gap: {max_gap:.2f}s")
            if avg_delta is not None:
                telemetry_lines.append(f"Avg delta: {avg_delta:.2f}s")
            if sampling_duration is not None and duration_seconds:
                try:
                    delta = abs(float(duration_seconds) - float(sampling_duration))
                    telemetry_lines.append(f"Clock delta: {delta:.0f}s")
                except Exception:
                    pass
            if telemetry_lines:
                _print_simple_list("Telemetry", telemetry_lines)
            if summary_payload:
                net_quality = (
                    summary_payload.get("telemetry", {})
                    .get("network_signal_quality")
                )
                if net_quality:
                    _print_simple_list("Network signal", [f"Quality: {net_quality}"])

        observers = manifest.get("observers") or []
        if observers:
            observer_lines = []
            failure_lines = []
            for observer in observers:
                observer_id = observer.get("observer_id", "unknown")
                obs_status = observer.get("status", "unknown")
                err = observer.get("error")
                label = f"{observer_id}: {obs_status}"
                if err:
                    label += f" ({err})"
                    if obs_status == "failed":
                        failure_lines.append(f"{observer_id}: {err}")
                observer_lines.append(label)
            _print_simple_list("Observers", observer_lines)
            if failure_lines:
                _print_simple_list("Observer errors", failure_lines)

        artifacts = manifest.get("artifacts") or []
        outputs = manifest.get("outputs") or []
        if artifacts or outputs:
            artifact_types = sorted({a.get("type", "unknown") for a in artifacts if isinstance(a, dict)})
            output_types = sorted({o.get("type", "unknown") for o in outputs if isinstance(o, dict)})
            artifact_summary = [
                f"Artifacts: {len(artifacts)} ({', '.join(artifact_types) if artifact_types else 'none'})",
                f"Outputs: {len(outputs)} ({', '.join(output_types) if output_types else 'none'})",
            ]
            _print_simple_list("Artifacts", artifact_summary)

        capture_lines = _summarize_capture(manifest)
        if capture_lines:
            _print_simple_list("Capture", capture_lines)
        if summary_payload:
            capture_info = summary_payload.get("capture") or {}
            pcap_valid = capture_info.get("pcap_valid")
            pcap_size = capture_info.get("pcap_size_bytes")
            min_bytes = capture_info.get("min_pcap_bytes")
            capture_mode = capture_info.get("capture_mode")
            details = []
            if pcap_valid is not None:
                details.append(f"pcap_valid: {pcap_valid}")
            if pcap_size is not None:
                details.append(f"pcap_size: {pcap_size}B")
            if min_bytes is not None:
                details.append(f"min_bytes: {min_bytes}B")
            if capture_mode:
                details.append(f"mode: {capture_mode}")
            if details:
                _print_simple_list("PCAP", details)
            if pcap_valid is False:
                size_label = f"{pcap_size}B" if pcap_size is not None else "unknown size"
                threshold_label = f"{min_bytes}B" if min_bytes is not None else "unknown threshold"
                print(
                    status_messages.status(
                        f"PCAP invalid ({size_label} < {threshold_label}); treated as unavailable for Tier-1.",
                        level="warn",
                    )
                )

        summary_paths = _summary_paths(manifest)
        if summary_paths:
            _print_simple_list("Summary", summary_paths)

        if run_dir:
            events_path = run_dir / "notes" / "run_events.jsonl"
            if events_path.exists():
                _print_simple_list("Logs", [f"Events: {events_path}"])

    if status == "blocked":
        print(status_messages.status("Session blocked by plan validation.", level="warn"))
    elif status != "success":
        print(status_messages.status("Session marked as degraded. Check observer errors above.", level="warn"))


def _load_manifest(run_dir: Path | None) -> dict[str, object] | None:
    if not run_dir:
        return None
    manifest_path = run_dir / "run_manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_summary(run_dir: Path | None) -> dict[str, object] | None:
    if not run_dir:
        return None
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return None
    try:
        return json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _summarize_capture(manifest: dict[str, object]) -> list[str]:
    artifacts = manifest.get("artifacts") or []
    types = {a.get("type") for a in artifacts if isinstance(a, dict)}
    captured = []
    if "system_log_capture" in types:
        captured.append("logcat")
    network_label = _network_capture_label(artifacts)
    if network_label:
        captured.append(network_label)
    if not captured:
        return ["No observer artifacts captured."]
    return [f"Captured: {', '.join(captured)}."]


def _network_capture_label(artifacts: list[object]) -> str | None:
    size_bytes = 0
    sources = []
    min_bytes = 30 * 1024
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        a_type = artifact.get("type")
        if a_type not in {"proxy_capture", "network_capture", "pcapdroid_capture"}:
            continue
        sources.append(a_type.replace("_capture", ""))
        try:
            size_bytes += int(artifact.get("size_bytes") or 0)
        except Exception:
            continue
    if not sources:
        return None
    if size_bytes < min_bytes:
        return None
    size_label = _format_bytes(size_bytes) if size_bytes else "size unknown"
    return f"network({'+'.join(sorted(set(sources)))}, {size_label})"


def _format_bytes(size: int) -> str:
    if size <= 0:
        return "0B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def _summary_paths(manifest: dict[str, object]) -> list[str]:
    outputs = manifest.get("outputs") or []
    summary = {}
    for item in outputs:
        if not isinstance(item, dict):
            continue
        artifact_type = item.get("type")
        path = item.get("relative_path")
        if artifact_type and path:
            summary[artifact_type] = path
    lines = []
    if "analysis_summary_json" in summary:
        lines.append(f"summary.json: {summary['analysis_summary_json']}")
    if "analysis_summary_md" in summary:
        lines.append(f"summary.md: {summary['analysis_summary_md']}")
    return lines


def _print_simple_list(title: str, items: list[str]) -> None:
    if not items:
        return
    lines = [(str(index + 1), value) for index, value in enumerate(items)]
    status_messages.print_strip(title, lines, width=70)


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


def _device_has_tcpdump(device_serial: str) -> bool:
    try:
        path = adb_shell.run_shell(device_serial, ["which", "tcpdump"]).strip()
    except Exception:
        return False
    return bool(path)


def _device_has_pcapdroid(device_serial: str) -> bool:
    try:
        output = adb_shell.run_shell(device_serial, ["pm", "path", PCAPDROID_PACKAGE]).strip()
    except Exception:
        return False
    return output.startswith("package:")


def _is_port_free(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def _print_root_status(device_serial: str) -> bool:
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
    print(status_messages.status(message, level=level))
    return is_rooted


def _print_network_status(device_serial: str) -> None:
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
    print(status_messages.status(label, level="info"))


def _proxy_default_for_package(package_name: str, is_rooted: bool) -> tuple[bool, str | None]:
    if not package_name:
        return (False, None)
    pinned_prefixes = ("com.google.", "com.android.")
    pinned_exact = {
        "com.zhiliaoapp.musically",
        "com.whatsapp",
        "org.telegram.messenger",
        "com.instagram.android",
        "com.facebook.katana",
        "com.facebook.orca",
        "com.snapchat.android",
        "com.twitter.android",
    }
    pinned = package_name in pinned_exact or package_name.startswith(pinned_prefixes)
    if pinned:
        notice = (
            "This app likely enforces certificate pinning; proxy capture can break loading."
        )
        return (False, notice)
    if not is_rooted:
        return (False, None)
    return (True, None)
