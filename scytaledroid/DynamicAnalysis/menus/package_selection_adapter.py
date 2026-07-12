"""Adapters for dynamic-menu package selection and queue preparation."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    PreparedPackageSelectionRow,
    PreparedPackageSelectionView,
)


def prepare_package_selection_view(
    groups,
    *,
    prepare_package_selection_view_fn,
    load_dataset_packages,
    list_packages_fn,
    summarize_evidence_quota_fn,
    build_package_selection_row_fn,
    device_serial: str | None = None,
) -> PreparedPackageSelectionView | None:
    return prepare_package_selection_view_fn(
        groups,
        load_dataset_packages=load_dataset_packages,
        list_packages_fn=list_packages_fn,
        summarize_evidence_quota_fn=summarize_evidence_quota_fn,
        build_package_selection_row_fn=build_package_selection_row_fn,
        device_serial=device_serial,
    )


def build_package_selection_row(
    *,
    build_package_selection_row_fn,
    idx: int,
    package: str,
    app_label: str | None,
    collisions: set[str],
    dataset_pkgs: set[str],
    tracker_apps,
    cfg,
    recent_tracker_runs,
    live_build_drift=None,
    db_lineage_context=None,
    truncate_visible_fn,
    bucket_progress_label_fn,
    quota_progress_label_fn,
    static_build_label_fn,
    next_action_from_need_fn,
    build_scoped_dataset_counts_fn,
    resolve_tracker_run_identity_fn,
) -> PreparedPackageSelectionRow:
    return build_package_selection_row_fn(
        idx=idx,
        package=package,
        app_label=app_label,
        collisions=collisions,
        dataset_pkgs=dataset_pkgs,
        tracker_apps=tracker_apps,
        cfg=cfg,
        recent_tracker_runs=recent_tracker_runs,
        live_build_drift=live_build_drift,
        db_lineage_context=db_lineage_context,
        truncate_visible_fn=truncate_visible_fn,
        bucket_progress_label_fn=bucket_progress_label_fn,
        quota_progress_label_fn=quota_progress_label_fn,
        static_build_label_fn=static_build_label_fn,
        next_action_from_need_fn=next_action_from_need_fn,
        build_scoped_dataset_counts_fn=build_scoped_dataset_counts_fn,
        resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
    )


def run_package_selection_menu(
    prepared: PreparedPackageSelectionView,
    *,
    run_package_selection_menu_fn,
    summarize_evidence_quota_fn,
) -> str | None:
    return run_package_selection_menu_fn(
        prepared,
        summarize_evidence_quota_fn=summarize_evidence_quota_fn,
    )


def build_scoped_dataset_counts(
    package_name: str,
    runs: list[dict],
    *,
    build_scoped_dataset_counts_fn,
    cfg: object | None = None,
    resolve_tracker_run_identity_fn,
) -> dict[str, int | str]:
    return build_scoped_dataset_counts_fn(
        package_name,
        runs,
        cfg=cfg,
        resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
    )


def resolve_tracker_run_identity(
    package_name: str,
    run: dict,
    *,
    resolve_tracker_run_identity_fn,
    run_identity_cache: dict[str, tuple[str | None, str | None]],
    output_dir: str,
) -> tuple[str | None, str | None]:
    return resolve_tracker_run_identity_fn(
        package_name,
        run,
        run_identity_cache=run_identity_cache,
        output_dir=output_dir,
    )


def select_package_from_groups(
    groups,
    *,
    select_package_from_groups_fn,
    prepare_package_selection_view_fn,
    run_package_selection_menu_fn,
    title: str,
    subtitle: str | None = None,
    device_serial: str | None = None,
) -> str | None:
    return select_package_from_groups_fn(
        groups,
        title=title,
        subtitle=subtitle,
        device_serial=device_serial,
        prepare_package_selection_view_fn=prepare_package_selection_view_fn,
        run_package_selection_menu_fn=run_package_selection_menu_fn,
    )


__all__ = [
    "PreparedPackageSelectionRow",
    "PreparedPackageSelectionView",
    "build_package_selection_row",
    "build_scoped_dataset_counts",
    "prepare_package_selection_view",
    "resolve_tracker_run_identity",
    "run_package_selection_menu",
    "select_package_from_groups",
]
