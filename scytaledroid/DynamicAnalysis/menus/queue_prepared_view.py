"""Prepared queue view models and aggregation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PreparedPackageSelectionView:
    packages: list[tuple[str, str | None, int | None, str | None]]
    dataset_pkgs: set[str]
    cfg: object
    rows: list[list[str]]
    op_rows: list[list[str]]
    build_rows: list[list[str]]
    dataset_apps_total: int
    dataset_apps_complete: int
    dataset_valid_runs_total: int
    current_build_ready_count: int = 0
    current_build_in_progress_count: int = 0
    current_build_review_count: int = 0
    stale_app_count: int = 0
    current_build_db_only_count: int = 0
    historical_valid_runs_total: int = 0
    historical_build_count_total: int = 0
    mixed_identity_app_count: int = 0
    legacy_only_app_count: int = 0
    historical_local_only_app_count: int = 0
    historical_db_only_app_count: int = 0
    no_evidence_anywhere_count: int = 0
    expected_runs: int = 0
    evidence_summary: dict[str, int | bool] | None = None
    row_models: list["PreparedPackageSelectionRow"] | None = None
    capture_device_selected: bool = True


@dataclass(frozen=True)
class PreparedPackageSelectionRow:
    full_row: list[str]
    op_row: list[str]
    build_row: list[str] | None
    dataset_app_count: int
    dataset_complete_count: int
    dataset_valid_runs_count: int
    historical_valid_runs_count: int = 0
    historical_build_count: int = 0
    build_state: str = "—"
    package_name: str = ""
    display_name: str = ""
    baseline_countable: int = 0
    baseline_extra: int = 0
    baseline_not_idle_supplemental: int = 0
    baseline_low_signal_supplemental: int = 0
    interactive_countable: int = 0
    interactive_extra: int = 0
    interactive_low_signal_supplemental: int = 0
    need_baseline: int = 0
    need_interactive: int = 0
    prep_label: str = "—"
    qa_label: str = "—"
    next_label: str = "—"
    technical_valid_active: int = 0
    live_build_drift: bool = False
    live_expected_version_code: str = ""
    live_expected_version_name: str = ""
    live_observed_version_code: str = ""
    live_static_run_id: str = ""
    lineage_state: str = ""
    db_active_sessions: int = 0
    db_historical_sessions: int = 0
    db_total_sessions: int = 0


def prepare_package_selection_view(
    groups,
    *,
    load_dataset_packages,
    list_packages_fn,
    summarize_evidence_quota_fn,
    build_package_selection_row_fn,
    resolve_live_build_drift_map_fn,
    resolve_db_dynamic_lineage_context_map_fn,
    device_serial: str | None = None,
) -> PreparedPackageSelectionView | None:
    packages = list_packages_fn(groups)
    if not packages:
        return None
    dataset_pkgs: set[str] = set()
    try:
        dataset_pkgs = {pkg.lower() for pkg in load_dataset_packages()}
    except Exception:
        dataset_pkgs = set()
    live_build_drift_map = resolve_live_build_drift_map_fn(
        [package for package, _v, _c, _label in packages],
        device_serial=device_serial,
    )
    db_lineage_map = resolve_db_dynamic_lineage_context_map_fn(
        [package for package, _v, _c, _label in packages]
    )

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )
    from scytaledroid.DynamicAnalysis.utils.run_cleanup import recent_tracker_runs

    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    tracker_apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    labels = [((app_label or package).strip() or package) for package, _v, _c, app_label in packages]
    collisions = {label for label in labels if labels.count(label) > 1}

    rows: list[list[str]] = []
    op_rows: list[list[str]] = []
    build_rows: list[list[str]] = []
    row_models: list[PreparedPackageSelectionRow] = []
    dataset_apps_total = 0
    dataset_apps_complete = 0
    dataset_valid_runs_total = 0
    current_build_ready_count = 0
    current_build_in_progress_count = 0
    current_build_review_count = 0
    stale_app_count = 0
    current_build_db_only_count = 0
    historical_valid_runs_total = 0
    historical_build_count_total = 0
    mixed_identity_app_count = 0
    legacy_only_app_count = 0
    historical_local_only_app_count = 0
    historical_db_only_app_count = 0
    no_evidence_anywhere_count = 0
    evidence_summary: dict[str, int | bool] | None = None

    for idx, (package, _version, _count, app_label) in enumerate(packages, start=1):
        prepared_row = build_package_selection_row_fn(
            idx=idx,
            package=package,
            app_label=app_label,
            collisions=collisions,
            dataset_pkgs=dataset_pkgs,
            tracker_apps=tracker_apps,
            cfg=cfg,
            recent_tracker_runs=recent_tracker_runs,
            live_build_drift=live_build_drift_map.get(str(package or "").strip().lower()),
            db_lineage_context=db_lineage_map.get(str(package or "").strip().lower()),
        )
        dataset_apps_total += prepared_row.dataset_app_count
        dataset_apps_complete += prepared_row.dataset_complete_count
        dataset_valid_runs_total += prepared_row.dataset_valid_runs_count
        if prepared_row.live_build_drift:
            stale_app_count += 1
        elif prepared_row.lineage_state == "current_build_db_only":
            current_build_db_only_count += 1
        elif prepared_row.lineage_state == "current_build_observed":
            if str(prepared_row.qa_label or "").startswith("invalid"):
                current_build_review_count += 1
            elif prepared_row.dataset_complete_count > 0:
                current_build_ready_count += 1
            else:
                current_build_in_progress_count += 1
        historical_valid_runs_total += prepared_row.historical_valid_runs_count
        historical_build_count_total += prepared_row.historical_build_count
        if prepared_row.build_state == "mixed":
            mixed_identity_app_count += 1
        elif prepared_row.build_state == "legacy":
            legacy_only_app_count += 1
        if prepared_row.lineage_state == "historical_local_only":
            historical_local_only_app_count += 1
        elif prepared_row.lineage_state == "historical_db_only":
            historical_db_only_app_count += 1
        elif prepared_row.lineage_state == "no_evidence_anywhere":
            no_evidence_anywhere_count += 1
        rows.append(prepared_row.full_row)
        op_rows.append(prepared_row.op_row)
        row_models.append(prepared_row)
        if prepared_row.build_row is not None:
            build_rows.append(prepared_row.build_row)

    expected_runs = 0
    if dataset_apps_total > 0:
        evidence_summary = summarize_evidence_quota_fn(dataset_pkgs, cfg)
        expected_runs = dataset_apps_total * (int(cfg.baseline_required) + int(cfg.interactive_required))

    return PreparedPackageSelectionView(
        packages=packages,
        dataset_pkgs=dataset_pkgs,
        cfg=cfg,
        rows=rows,
        op_rows=op_rows,
        build_rows=build_rows,
        dataset_apps_total=dataset_apps_total,
        dataset_apps_complete=dataset_apps_complete,
        dataset_valid_runs_total=dataset_valid_runs_total,
        current_build_ready_count=current_build_ready_count,
        current_build_in_progress_count=current_build_in_progress_count,
        current_build_review_count=current_build_review_count,
        stale_app_count=stale_app_count,
        current_build_db_only_count=current_build_db_only_count,
        historical_valid_runs_total=historical_valid_runs_total,
        historical_build_count_total=historical_build_count_total,
        mixed_identity_app_count=mixed_identity_app_count,
        legacy_only_app_count=legacy_only_app_count,
        historical_local_only_app_count=historical_local_only_app_count,
        historical_db_only_app_count=historical_db_only_app_count,
        no_evidence_anywhere_count=no_evidence_anywhere_count,
        expected_runs=expected_runs,
        evidence_summary=evidence_summary,
        row_models=row_models,
        capture_device_selected=bool(str(device_serial or "").strip()),
    )


__all__ = [
    "PreparedPackageSelectionRow",
    "PreparedPackageSelectionView",
    "prepare_package_selection_view",
]
