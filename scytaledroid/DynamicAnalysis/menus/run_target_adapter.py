"""Adapters for focused-run target selection and runtime helpers."""

from __future__ import annotations

from typing import Any


def select_dynamic_target(
    *,
    select_dynamic_target_fn,
    group_artifacts_fn,
    active_research_cohort_packages_fn,
    active_research_cohort_label_fn,
    select_package_from_groups_fn,
    prompt_custom_package_fn,
    resolve_custom_tier_fn,
    select_profile_package_fn,
) -> tuple[str, str] | None:
    return select_dynamic_target_fn(
        group_artifacts_fn=group_artifacts_fn,
        active_research_cohort_packages_fn=active_research_cohort_packages_fn,
        active_research_cohort_label_fn=active_research_cohort_label_fn,
        select_package_from_groups_fn=select_package_from_groups_fn,
        prompt_custom_package_fn=prompt_custom_package_fn,
        resolve_custom_tier_fn=resolve_custom_tier_fn,
        select_profile_package_fn=select_profile_package_fn,
    )


def resolve_plan_selection(
    package_name: str,
    *,
    resolve_plan_selection_fn,
    load_plan_candidates_fn,
    prompt_missing_baseline_fn,
    pick_newest_candidate_fn,
    build_selection_fn,
    prompt_baseline_selection_fn,
) -> dict[str, object] | None:
    return resolve_plan_selection_fn(
        package_name,
        load_plan_candidates_fn=load_plan_candidates_fn,
        prompt_missing_baseline_fn=prompt_missing_baseline_fn,
        pick_newest_candidate_fn=pick_newest_candidate_fn,
        build_selection_fn=build_selection_fn,
        prompt_baseline_selection_fn=prompt_baseline_selection_fn,
    )


def run_guided_dataset_run(
    ui_defaults: Any,
    *,
    run_guided_dataset_run_fn,
    select_package_from_groups_fn,
    select_observers_fn,
    print_device_badge_fn,
    print_tier1_qa_result_fn,
) -> None:
    run_guided_dataset_run_fn(
        select_package_from_groups=select_package_from_groups_fn,
        select_observers=select_observers_fn,
        print_device_badge=print_device_badge_fn,
        print_tier1_qa_result=print_tier1_qa_result_fn,
        observer_prompts_enabled=bool(getattr(ui_defaults, "observer_prompts_enabled", False)),
        pcapdroid_api_key=getattr(ui_defaults, "pcapdroid_api_key", None),
    )


def resolve_active_cohort_for_run(
    *,
    active_research_cohort_key_fn,
    chooseable_active_research_cohorts_fn,
    choose_active_research_cohort_fn,
    status_messages_mod,
) -> dict[str, object] | None:
    active_key = str(active_research_cohort_key_fn() or "").strip().lower()
    rows = chooseable_active_research_cohorts_fn()
    if not rows:
        print(status_messages_mod.status("No active app cohorts are defined in the DB.", level="warn"))
        return None
    if active_key:
        for row in rows:
            cohort_key = str(row.get("cohort_key") or "").strip().lower()
            if cohort_key == active_key:
                return dict(row)
    selected = choose_active_research_cohort_fn()
    return dict(selected) if isinstance(selected, dict) else None


def run_focused_app_run(
    ui_defaults: Any,
    *,
    run_sandbox_dynamic_run_fn,
    select_dynamic_target_fn,
    select_observers_fn,
    print_root_status_fn,
    print_network_status_fn,
) -> None:
    run_sandbox_dynamic_run_fn(
        select_dynamic_target=select_dynamic_target_fn,
        select_observers=select_observers_fn,
        print_root_status=print_root_status_fn,
        print_network_status=print_network_status_fn,
        observer_prompts_enabled=bool(getattr(ui_defaults, "observer_prompts_enabled", False)),
        pcapdroid_api_key=getattr(ui_defaults, "pcapdroid_api_key", None),
    )


def resolve_custom_tier(
    package_name: str,
    dataset_pkgs: set[str],
    *,
    resolve_custom_tier_fn,
    active_research_cohort_label_fn,
) -> tuple[str, str]:
    return resolve_custom_tier_fn(
        package_name,
        dataset_pkgs,
        active_research_cohort_label_fn=active_research_cohort_label_fn,
    )


def select_profile_package(
    groups,
    *,
    select_profile_package_fn,
    list_categories_fn,
    load_operational_profiles_fn,
    load_profile_packages_fn,
    choose_index_fn,
    select_package_from_groups_fn,
) -> tuple[str, str | None] | None:
    return select_profile_package_fn(
        groups,
        list_categories_fn=list_categories_fn,
        load_operational_profiles_fn=load_operational_profiles_fn,
        load_profile_packages_fn=load_profile_packages_fn,
        choose_index_fn=choose_index_fn,
        select_package_from_groups_fn=select_package_from_groups_fn,
    )


def select_observers(
    device_serial: str,
    *,
    mode: str,
    select_observers_fn,
) -> list[str]:
    return select_observers_fn(device_serial, mode=mode)


def print_tier1_qa_result(dynamic_run_id: str, *, print_tier1_qa_result_fn) -> None:
    print_tier1_qa_result_fn(dynamic_run_id)


def print_device_badge(
    device_serial: str,
    device_label: str,
    *,
    print_device_badge_fn,
    device_status_cache: dict[str, dict[str, str]],
) -> None:
    print_device_badge_fn(
        device_serial,
        device_label,
        device_status_cache=device_status_cache,
    )


def print_root_status(
    device_serial: str,
    *,
    print_root_status_fn,
    force: bool = False,
    device_status_cache: dict[str, dict[str, str]],
) -> bool:
    return print_root_status_fn(
        device_serial,
        force=force,
        device_status_cache=device_status_cache,
    )


def print_network_status(
    device_serial: str,
    *,
    print_network_status_fn,
    force: bool = False,
    device_status_cache: dict[str, dict[str, str]],
) -> None:
    print_network_status_fn(
        device_serial,
        force=force,
        device_status_cache=device_status_cache,
    )


__all__ = [
    "print_device_badge",
    "print_network_status",
    "print_root_status",
    "print_tier1_qa_result",
    "resolve_active_cohort_for_run",
    "resolve_custom_tier",
    "resolve_plan_selection",
    "run_focused_app_run",
    "run_guided_dataset_run",
    "select_dynamic_target",
    "select_observers",
    "select_profile_package",
]
