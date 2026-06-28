"""Focused-run target and plan selection helpers."""

from __future__ import annotations

from collections.abc import Callable

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, MenuSpec


def choose_index(
    prompt: str,
    total: int,
    *,
    get_choice_fn: Callable[..., str] = prompt_utils.get_choice,
) -> int | None:
    if total <= 0:
        return None
    options = [str(idx) for idx in range(1, total + 1)]
    choice = get_choice_fn(options + ["0"], default="1", prompt=f"{prompt} ")
    if choice == "0":
        return None
    return int(choice) - 1


def prompt_custom_package() -> str:
    return prompt_utils.prompt_text(
        "Package name",
        required=True,
        error_message="Please provide a package name.",
    )


def resolve_custom_tier(
    package_name: str,
    dataset_pkgs: set[str],
    *,
    active_research_cohort_label_fn: Callable[[], str],
) -> tuple[str, str]:
    if package_name.lower() in dataset_pkgs:
        cohort_label = active_research_cohort_label_fn()
        run_as_dataset = prompt_utils.prompt_yes_no(
            f"This app is in {cohort_label}. Run as dataset tier?",
            default=True,
        )
        return (package_name, "dataset" if run_as_dataset else "exploration")
    run_as_dataset = prompt_utils.prompt_yes_no(
        "Run this custom package as dataset tier?",
        default=False,
    )
    return (package_name, "dataset" if run_as_dataset else "exploration")


def select_package_from_groups(
    groups,
    *,
    title: str,
    subtitle: str | None = None,
    device_serial: str | None = None,
    prepare_package_selection_view_fn,
    run_package_selection_menu_fn,
) -> str | None:
    prepared = prepare_package_selection_view_fn(groups, device_serial=device_serial)
    if prepared is None:
        print(status_messages.status("No apps available for selection.", level="warn"))
        return None
    print()
    menu_utils.print_header(title, subtitle)
    return run_package_selection_menu_fn(prepared)


def select_profile_package(
    groups,
    *,
    list_categories_fn,
    load_operational_profiles_fn,
    load_profile_packages_fn,
    choose_index_fn,
    select_package_from_groups_fn,
) -> tuple[str, str | None] | None:
    categories = list_categories_fn(groups)
    db_profiles = load_operational_profiles_fn()
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
    profile_rows.sort(key=lambda row: row["label"].lower())
    rows = [
        [str(idx), row["label"], str(row["db_count"]), str(row["available_count"])]
        for idx, row in enumerate(profile_rows, start=1)
    ]
    table_utils.render_table(["#", "Profile", "Apps (db)", "Available"], rows, compact=True)
    index = choose_index_fn("Select profile #", len(profile_rows))
    if index is None:
        return None
    selected = profile_rows[index]
    profile_key = selected.get("key")
    if profile_key:
        packages = load_profile_packages_fn(profile_key)
        if not packages:
            print(status_messages.status("No apps found for that profile.", level="warn"))
            return None
        available = {group.package_name.lower() for group in groups if group.package_name}
        scoped_groups = tuple(group for group in groups if group.package_name.lower() in available.intersection(packages))
        if not scoped_groups:
            print(
                status_messages.status(
                    "No APK artifacts available yet for that profile. Execute Harvest or use Custom package name.",
                    level="warn",
                )
            )
            return None
        package_name = select_package_from_groups_fn(
            scoped_groups,
            title="App Queue",
            subtitle=f"{selected['label']} · dynamic run queue",
        )
        if not package_name:
            return None
        return (package_name, profile_key)
    category_name = selected["label"]
    scoped_groups = tuple(
        group
        for group in groups
        if (
            (getattr(group, "category", None) or "Uncategorized")
            == category_name
        )
    )
    if not scoped_groups:
        print(status_messages.status("No apps found for that profile.", level="warn"))
        return None
    package_name = select_package_from_groups_fn(scoped_groups, title=f"{category_name} apps")
    if not package_name:
        return None
    return (package_name, None)


def resolve_plan_selection(
    package_name: str,
    *,
    load_plan_candidates_fn,
    prompt_missing_baseline_fn,
    pick_newest_candidate_fn,
    build_selection_fn,
    prompt_baseline_selection_fn,
) -> dict[str, object] | None:
    candidates, note = load_plan_candidates_fn(package_name)
    if not candidates:
        return prompt_missing_baseline_fn(package_name, note)

    grouped: dict[str, list[dict[str, object]]] = {}
    for candidate in candidates:
        key = candidate["identity_key"]
        grouped.setdefault(key, []).append(candidate)

    if len(grouped) == 1:
        only_key = next(iter(grouped))
        selection = pick_newest_candidate_fn(grouped[only_key])
        return build_selection_fn(selection)

    return prompt_baseline_selection_fn(package_name, candidates)


def select_dynamic_target(
    *,
    group_artifacts_fn,
    active_research_cohort_packages_fn,
    active_research_cohort_label_fn,
    select_package_from_groups_fn,
    prompt_custom_package_fn,
    resolve_custom_tier_fn,
    select_profile_package_fn,
) -> tuple[str, str] | None:
    print()
    menu_utils.print_header("Dynamic Run Target")
    target_options = [
        MenuOption("1", "App (select from available artifacts)"),
        MenuOption("2", "Profile (select app from profile)"),
        MenuOption("3", "Custom package name"),
    ]
    target_spec = MenuSpec(items=target_options, exit_label="Cancel", show_exit=True)
    menu_utils.render_menu(target_spec)
    choice = prompt_utils.get_choice(
        menu_utils.selectable_keys(target_options, include_exit=True),
        default="1",
        disabled=[option.key for option in target_options if option.disabled],
    )
    if choice == "0":
        return None

    groups = group_artifacts_fn()
    try:
        dataset_pkgs = {pkg.lower() for pkg in active_research_cohort_packages_fn()}
    except Exception:
        dataset_pkgs = set()

    if choice == "1":
        package_name = select_package_from_groups_fn(groups, title="App selection")
        if package_name:
            if package_name.lower() in dataset_pkgs:
                cohort_label = active_research_cohort_label_fn()
                run_as_dataset = prompt_utils.prompt_yes_no(
                    f"This app is in {cohort_label}. Run as dataset tier?",
                    default=True,
                )
                return (package_name, "dataset" if run_as_dataset else "exploration")
            return (package_name, "exploration")
        package_name = prompt_custom_package_fn()
        if package_name:
            return resolve_custom_tier_fn(package_name, dataset_pkgs)
        return None

    if choice == "2":
        profile_selection = select_profile_package_fn(groups)
        if profile_selection:
            package_name, profile_key = profile_selection
            tier = "dataset" if str(profile_key or "").strip().upper().startswith("RESEARCH_DATASET_") else "exploration"
            return (package_name, tier)
        package_name = prompt_custom_package_fn()
        if package_name:
            return resolve_custom_tier_fn(package_name, dataset_pkgs)
        return None

    package_name = prompt_custom_package_fn()
    if package_name:
        return resolve_custom_tier_fn(package_name, dataset_pkgs)
    return None
