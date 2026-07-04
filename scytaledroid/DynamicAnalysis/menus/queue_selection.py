"""Package selection helpers for the dynamic analysis menu."""

from __future__ import annotations

from scytaledroid.DynamicAnalysis import app_queue_rendering as _app_queue_rendering
from scytaledroid.DynamicAnalysis import app_queue_state as _app_queue_state
from scytaledroid.DynamicAnalysis.menus import status_reports as _status_reports
from scytaledroid.DynamicAnalysis.menus.queue_data_sources import (
    resolve_db_dynamic_lineage_context_map as _resolve_db_dynamic_lineage_context_map_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_data_sources import (
    resolve_live_build_drift_map as _resolve_live_build_drift_map_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_prepared_view import (
    PreparedPackageSelectionRow,
    PreparedPackageSelectionView,
)
from scytaledroid.DynamicAnalysis.menus.queue_prepared_view import (
    prepare_package_selection_view as _prepare_package_selection_view_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_row_builder import (
    build_package_selection_row as _build_package_selection_row_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_row_builder import (
    prep_label_for_lineage_state as _prep_label_for_lineage_state_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_row_builder import (
    row_lineage_state as _row_lineage_state_impl,
)
from scytaledroid.DynamicAnalysis.tracker_scope import (
    build_scoped_dataset_counts as _build_scoped_dataset_counts_shared,
)
from scytaledroid.DynamicAnalysis.tracker_scope import (
    resolve_tracker_run_identity as _resolve_tracker_run_identity_shared,
)
from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    terminal,
    text_blocks,
)


def prepare_package_selection_view(
    groups,
    *,
    load_dataset_packages,
    list_packages_fn,
    summarize_evidence_quota_fn,
    build_package_selection_row_fn,
    device_serial: str | None = None,
) -> PreparedPackageSelectionView | None:
    return _prepare_package_selection_view_impl(
        groups,
        load_dataset_packages=load_dataset_packages,
        list_packages_fn=list_packages_fn,
        summarize_evidence_quota_fn=summarize_evidence_quota_fn,
        build_package_selection_row_fn=build_package_selection_row_fn,
        resolve_live_build_drift_map_fn=_resolve_live_build_drift_map,
        resolve_db_dynamic_lineage_context_map_fn=_resolve_db_dynamic_lineage_context_map,
        device_serial=device_serial,
    )


def build_package_selection_row(
    *,
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
    return _build_package_selection_row_impl(
        prepared_row_cls=PreparedPackageSelectionRow,
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
        build_scoped_dataset_counts_fn=build_scoped_dataset_counts_fn,
        resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
    )


def run_package_selection_menu(
    prepared: PreparedPackageSelectionView, *, summarize_evidence_quota_fn
) -> str | None:
    evidence_summary = prepared.evidence_summary

    while True:
        if prepared.dataset_apps_total > 0:
            evidence_summary = evidence_summary or summarize_evidence_quota_fn(
                prepared.dataset_pkgs, prepared.cfg
            )
            quota = int(evidence_summary.get("quota_runs_counted", 0)) if evidence_summary else 0
            apps_ok = int(evidence_summary.get("apps_satisfied", 0)) if evidence_summary else 0
            freeze_ok = (
                (
                    bool(evidence_summary.get("evidence_root_exists"))
                    and quota >= int(prepared.expected_runs)
                    and apps_ok >= int(prepared.dataset_apps_total)
                )
                if evidence_summary
                else False
            )
            remaining = max(0, int(prepared.expected_runs) - int(quota))
            row_models = list(prepared.row_models or [])
            extra_runs = (
                int(evidence_summary.get("extra_eligible_runs", 0)) if evidence_summary else 0
            )
            next_row = _next_recommended_row(row_models)
            _render_queue_summary_block(
                prepared=prepared,
                quota=quota,
                apps_ok=apps_ok,
                remaining=remaining,
                extra_runs=extra_runs,
                freeze_ok=freeze_ok,
                next_row=next_row,
                capture_device_selected=bool(getattr(prepared, "capture_device_selected", True)),
            )

            _render_compact_queue_table(
                row_models,
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 4)),
                next_row=next_row,
            )
            warnings_line = _compact_warning_line(row_models)
            notes_line = _compact_note_line(row_models)
            _render_queue_footer_block(
                warnings_line=warnings_line,
                notes_line=notes_line,
            )
        choice = prompt_utils.prompt_text("Choose app # / name", required=False).strip()

        if not choice:
            index = choose_package_selection(prepared)
            if index is None:
                return None
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        choice_lc = choice.lower()
        if choice_lc in {"s", "summary"}:
            _status_reports.render_cohort_status_details(
                dataset_apps_total=prepared.dataset_apps_total,
                dataset_apps_complete=prepared.dataset_apps_complete,
                dataset_valid_runs_total=prepared.dataset_valid_runs_total,
                current_build_ready_count=prepared.current_build_ready_count,
                current_build_in_progress_count=prepared.current_build_in_progress_count,
                current_build_review_count=prepared.current_build_review_count,
                stale_app_count=prepared.stale_app_count,
                current_build_db_only_count=prepared.current_build_db_only_count,
                historical_valid_runs_total=prepared.historical_valid_runs_total,
                historical_build_count_total=prepared.historical_build_count_total,
                mixed_identity_app_count=prepared.mixed_identity_app_count,
                legacy_only_app_count=prepared.legacy_only_app_count,
                historical_local_only_app_count=prepared.historical_local_only_app_count,
                historical_db_only_app_count=prepared.historical_db_only_app_count,
                no_evidence_anywhere_count=prepared.no_evidence_anywhere_count,
                expected_runs=prepared.expected_runs,
                evidence_summary=evidence_summary,
                row_models=list(prepared.row_models or []),
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 4)),
            )
            continue
        if choice_lc in {"y", "history"}:
            _status_reports.render_cohort_build_history(
                list(prepared.row_models or []),
                prepared.build_rows,
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 4)),
            )
            continue
        if choice_lc in {"v", "grouped", "view"}:
            _app_queue_rendering.render_queue_grouped_sections(
                row_models,
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 4)),
                table_utils_mod=table_utils,
                menu_utils_mod=menu_utils,
                next_row=next_row,
            )
            prompt_utils.press_enter_to_continue()
            continue
        if choice_lc in {"h", "help"}:
            _status_reports.render_cohort_status_help()
            continue
        if choice_lc in {"d", "debug", "diagnostics"}:
            _status_reports.render_cohort_status_debug(
                list(prepared.row_models or []),
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 4)),
            )
            continue
        if choice_lc in {"0", "b", "back", "cancel"}:
            return None
        index = resolve_package_selection(choice, prepared)
        if index is not None:
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        print(
            status_messages.status(
                "Invalid choice. Enter an app number/name or use S, V, Y, H, D, or B.", level="warn"
            )
        )


def _compact_warning_line(row_models: list[PreparedPackageSelectionRow]) -> str:
    return _app_queue_state.compact_warning_line(row_models)


def _compact_note_line(row_models: list[PreparedPackageSelectionRow]) -> str:
    return _app_queue_state.compact_note_line(row_models)


def _render_compact_queue_table(
    rows: list[PreparedPackageSelectionRow],
    *,
    baseline_required: int,
    interactive_required: int,
    next_row: PreparedPackageSelectionRow | None = None,
) -> None:
    _app_queue_rendering.render_compact_queue_table(
        rows,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        terminal_mod=terminal,
        table_utils_mod=table_utils,
        text_blocks_mod=text_blocks,
        next_row=next_row,
    )


def _render_queue_summary_block(
    *,
    prepared: PreparedPackageSelectionView,
    quota: int,
    apps_ok: int,
    remaining: int,
    extra_runs: int,
    freeze_ok: bool,
    next_row: PreparedPackageSelectionRow | None,
    capture_device_selected: bool = True,
) -> None:
    _app_queue_rendering.render_queue_summary_block(
        prepared=prepared,
        quota=quota,
        apps_ok=apps_ok,
        remaining=remaining,
        extra_runs=extra_runs,
        freeze_ok=freeze_ok,
        next_row=next_row,
        capture_device_selected=capture_device_selected,
    )


def _render_queue_footer_block(
    *,
    warnings_line: str = "",
    notes_line: str = "",
) -> None:
    _app_queue_rendering.render_queue_footer_block(
        warnings_line=warnings_line,
        notes_line=notes_line,
    )


def _archive_blocker_summary(row_models: list[PreparedPackageSelectionRow]) -> str:
    return _app_queue_state.archive_blocker_summary(row_models)


def _display_action_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.display_action_label(row)


def _display_next_line_action_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.display_next_line_action_label(row)


def _next_recommended_row(
    rows: list[PreparedPackageSelectionRow],
) -> PreparedPackageSelectionRow | None:
    return _app_queue_state.next_recommended_row(rows)


def _render_queue_section_table(
    rows: list[PreparedPackageSelectionRow],
    *,
    baseline_required: int,
    interactive_required: int,
    show_all: bool = False,
) -> None:
    _app_queue_rendering.render_queue_section_table(
        rows,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        table_utils_mod=table_utils,
        show_all=show_all,
    )


def _main_progress_label(
    countable: int,
    extra: int,
    *,
    required: int,
    missing: int | None = None,
) -> str:
    return _app_queue_state.main_progress_label(
        countable,
        extra,
        required=required,
        missing=missing,
    )


def _manual_progress_label(row: PreparedPackageSelectionRow, *, interactive_required: int) -> str:
    return _app_queue_state.manual_progress_label(row, interactive_required=interactive_required)


def _main_action_label(value: str) -> str:
    return _app_queue_state.main_action_label(value)


def render_package_table(
    rows,
    *,
    headers: list[str] | None = None,
    max_preview: int = 15,
    show_all: bool = False,
) -> bool:
    return _app_queue_rendering.render_package_table(
        rows,
        table_utils_mod=table_utils,
        headers=headers,
        max_preview=max_preview,
        show_all=show_all,
    )


def _compact_selection_rows(rows: list[list[str]]) -> list[list[str]]:
    return _app_queue_rendering.compact_selection_rows(rows)


def _compact_progress_label(value: str) -> str:
    return _app_queue_state.compact_progress_label(value)


def _compact_next_action(value: str) -> str:
    return _app_queue_state.compact_next_action(value)


def _compact_prep_label(value: str) -> str:
    return _app_queue_state.compact_prep_label(value)


def _compact_qa_label(value: str) -> str:
    return _app_queue_state.compact_qa_label(value)


def _resolve_live_build_drift_map(
    packages: list[str],
    *,
    device_serial: str | None,
) -> dict[str, dict[str, str]]:
    return _resolve_live_build_drift_map_impl(packages, device_serial=device_serial)


def _resolve_db_dynamic_lineage_context_map(
    packages: list[str],
) -> dict[str, dict[str, int]]:
    return _resolve_db_dynamic_lineage_context_map_impl(packages)


def _row_lineage_state(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    live_build_drift: bool,
) -> str:
    return _row_lineage_state_impl(
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=legacy_valid_runs,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        live_build_drift=live_build_drift,
    )


def _prep_label_for_lineage_state(lineage_state: str, default_build_label: str) -> str:
    return _prep_label_for_lineage_state_impl(lineage_state, default_build_label)


def build_scoped_dataset_counts(
    package_name: str,
    runs: list[dict],
    *,
    cfg: object | None = None,
    resolve_tracker_run_identity_fn,
) -> dict[str, int | str]:
    return _build_scoped_dataset_counts_shared(
        package_name,
        runs,
        cfg=cfg,
        resolve_tracker_run_identity_fn=resolve_tracker_run_identity_fn,
    )


def resolve_tracker_run_identity(
    package_name: str,
    run: dict,
    *,
    run_identity_cache: dict[str, tuple[str | None, str | None]],
    output_dir: str,
) -> tuple[str | None, str | None]:
    return _resolve_tracker_run_identity_shared(
        package_name,
        run,
        run_identity_cache=run_identity_cache,
        output_dir=output_dir,
    )


def choose_package_selection(prepared: PreparedPackageSelectionView) -> int | None:
    total = len(prepared.packages)
    if total <= 0:
        return None
    while True:
        raw = prompt_utils.prompt_text(
            "Select app number or app name",
            required=False,
        ).strip()
        if not raw:
            return 0
        if raw.lower() in {"0", "b", "back", "cancel"}:
            return None
        resolved = resolve_package_selection(raw, prepared)
        if resolved is not None:
            return resolved
        print(
            status_messages.status(
                f"No matching app found. Enter a number from 1-{total} or an app name like Facebook.",
                level="warn",
            )
        )


def resolve_package_selection(raw: str, prepared: PreparedPackageSelectionView) -> int | None:
    total = len(prepared.packages)
    if total <= 0:
        return None
    lookup: dict[str, int] = {}
    for idx, (package_name, app_label, _static_run_id, _plan_path) in enumerate(prepared.packages):
        lookup[str(idx + 1)] = idx
        pkg_lc = str(package_name or "").strip().lower()
        if pkg_lc:
            lookup[pkg_lc] = idx
        label_lc = str(app_label or "").strip().lower()
        if label_lc:
            lookup[label_lc] = idx
        if idx < len(prepared.op_rows) and len(prepared.op_rows[idx]) > 1:
            display_lc = str(prepared.op_rows[idx][1] or "").strip().lower()
            if display_lc:
                lookup[display_lc] = idx

    choice = raw.strip().lower()
    if choice in lookup:
        return lookup[choice]
    matches = [idx for key, idx in lookup.items() if choice and choice in key and not key.isdigit()]
    matches = sorted(set(matches))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(
            status_messages.status(
                f'Multiple apps matched "{raw}". Please enter the app number.', level="warn"
            )
        )
    return None
