"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

from scytaledroid.Config import app_config  # noqa: F401 - re-exported for tests
from scytaledroid.Database.db_core import run_sql
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell, status as adb_status
from scytaledroid.DynamicAnalysis import plan_selection as _plan_selection
from scytaledroid.DynamicAnalysis.controllers.guided_run import run_guided_dataset_run
from scytaledroid.DynamicAnalysis.profile_loader import load_db_profiles, load_profile_packages
from scytaledroid.DynamicAnalysis.services.observer_service import (
    select_observers as _service_select_observers,
)
from scytaledroid.StaticAnalysis.core.repository import (
    group_artifacts,
    list_categories,
    list_packages,
    load_profile_map,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec

_DEVICE_STATUS_CACHE: dict[str, dict[str, str]] = {}


def dynamic_analysis_menu() -> None:
    from scytaledroid.Database.db_utils import schema_gate
    ok, message, detail = schema_gate.dynamic_schema_gate()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Database Tools → Apply Tier-1 schema migrations (or import canonical DB export), then retry.",
            level="error",
        )
        return

    options = [
        MenuOption("1", "Run Research Dataset Alpha (guided)"),
        MenuOption("2", "Dataset run status"),
        MenuOption("3", "Export run summary CSV"),
        MenuOption("4", "Export PCAP features CSV"),
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
            _run_guided_dataset_run()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "2":
            _render_dataset_status()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "3":
            _export_dynamic_run_summary_csv()
            prompt_utils.press_enter_to_continue()
            continue

        if choice == "4":
            _export_pcap_features_csv()
            prompt_utils.press_enter_to_continue()
            continue


    return


def _render_dataset_status() -> None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    print()
    menu_utils.print_header("Dataset Run Status")
    payload = load_dataset_tracker()
    apps = payload.get("apps", {})
    rows = []
    for package, entry in sorted(apps.items()):
        runs = int(entry.get("run_count") or 0)
        valid = int(entry.get("valid_runs") or 0)
        target = int(entry.get("target_runs") or 0)
        status = "complete" if entry.get("app_complete") else "in_progress"
        rows.append(
            {
                "Package": package,
                "Valid": valid,
                "Runs": runs,
                "Target": target,
                "Status": status,
            }
        )
    if not rows:
        print(status_messages.status("No dataset runs recorded yet.", level="info"))
        return
    table_utils.print_table(rows, headers=["Package", "Valid", "Runs", "Target", "Status"])


def _export_pcap_features_csv() -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_pcap_features_csv

    print()
    menu_utils.print_header("PCAP Features Export")
    output_path = export_pcap_features_csv()
    if output_path is None:
        print(status_messages.status("No pcap_features.json files found.", level="warn"))
        return
    print(status_messages.status(f"Exported CSV: {output_path}", level="success"))


def _export_dynamic_run_summary_csv() -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_dynamic_run_summary_csv

    print()
    menu_utils.print_header("Run Summary Export")
    output_path = export_dynamic_run_summary_csv()
    if output_path is None:
        print(status_messages.status("No dynamic run summaries found.", level="warn"))
        return
    print(status_messages.status(f"Exported CSV: {output_path}", level="success"))


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


def _resolve_plan_selection(package_name: str) -> dict[str, object] | None:
    candidates, note = _plan_selection._load_plan_candidates(package_name)
    if not candidates:
        return _prompt_missing_baseline(package_name, note)

    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        key = candidate["identity_key"]
        grouped.setdefault(key, []).append(candidate)

    if len(grouped) == 1:
        only_key = next(iter(grouped))
        selection = _plan_selection._pick_newest_candidate(grouped[only_key])
        return _plan_selection._build_selection(selection)

    return _prompt_baseline_selection(package_name, candidates)


def _run_guided_dataset_run() -> None:
    run_guided_dataset_run(
        select_package_from_groups=_select_package_from_groups,
        select_observers=_select_observers,
        print_device_badge=_print_device_badge,
        print_tier1_qa_result=_print_tier1_qa_result,
    )


def _print_tier1_qa_result(dynamic_run_id: str) -> None:
    try:
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
    except Exception as exc:  # noqa: BLE001
        print(
            status_messages.status(
                f"Tier-1 QA unavailable (DB error: {exc}).",
                level="warn",
            )
        )
        return
    if not row:
        print(status_messages.status("Tier-1 QA gate: NOT ENFORCED (dynamic).", level="info"))
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


def _prompt_baseline_selection(
    package_name: str,
    candidates: list[dict[str, object]],
) -> dict[str, object] | None:
    return _plan_selection._prompt_baseline_selection(package_name, candidates)


def _prompt_missing_baseline(package_name: str, note: str | None) -> dict[str, object] | None:
    return _plan_selection._prompt_missing_baseline(package_name, note)


def _select_observers(device_serial: str, *, mode: str) -> list[str]:
    return _service_select_observers(device_serial, mode=mode)


def _print_device_badge(device_serial: str, device_label: str) -> None:
    stats = adb_status.get_device_stats(device_serial)
    root_state = (stats.get("is_rooted") or "Unknown").strip().upper()
    if root_state == "YES":
        root_label = "yes"
    elif root_state == "NO":
        root_label = "no"
    else:
        root_label = "unknown"

    net_label = "unknown"
    try:
        status = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
        if "not connected" in status:
            net_label = "not_connected"
        elif "not_vpn" in status or "not vpn" in status:
            net_label = "not_vpn"
        elif "validated" in status:
            net_label = "validated"
    except Exception:
        net_label = "unknown"

    badge = f"Device: {device_label} | root: {root_label} | net: {net_label}"
    cached = _DEVICE_STATUS_CACHE.get(device_serial, {})
    if cached.get("badge") != badge:
        print(status_messages.status(badge, level="info"))
        cached["badge"] = badge
        _DEVICE_STATUS_CACHE[device_serial] = cached


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
