"""Package selection helpers for the dynamic analysis menu."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis import app_queue_rendering as _app_queue_rendering
from scytaledroid.DynamicAnalysis import app_queue_state as _app_queue_state
from scytaledroid.DynamicAnalysis.menus.queue_data_sources import (
    resolve_db_dynamic_lineage_context_map as _resolve_db_dynamic_lineage_context_map_impl,
    resolve_live_build_drift_map as _resolve_live_build_drift_map_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_row_builder import (
    build_package_selection_row as _build_package_selection_row_impl,
    prep_label_for_lineage_state as _prep_label_for_lineage_state_impl,
    row_lineage_state as _row_lineage_state_impl,
)
from scytaledroid.DynamicAnalysis.tracker_scope import (
    build_scoped_dataset_counts as _build_scoped_dataset_counts_shared,
    resolve_tracker_run_identity as _resolve_tracker_run_identity_shared,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils, terminal, text_blocks


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
    interactive_countable: int = 0
    interactive_extra: int = 0
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
    live_build_drift_map = _resolve_live_build_drift_map(
        [package for package, _v, _c, _label in packages],
        device_serial=device_serial,
    )
    db_lineage_map = _resolve_db_dynamic_lineage_context_map(
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

    rows = []
    op_rows = []
    build_rows = []
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


def run_package_selection_menu(prepared: PreparedPackageSelectionView, *, summarize_evidence_quota_fn) -> str | None:
    evidence_summary = prepared.evidence_summary

    while True:
        if prepared.dataset_apps_total > 0:
            evidence_summary = evidence_summary or summarize_evidence_quota_fn(prepared.dataset_pkgs, prepared.cfg)
            quota = int(evidence_summary.get("quota_runs_counted", 0)) if evidence_summary else 0
            apps_ok = int(evidence_summary.get("apps_satisfied", 0)) if evidence_summary else 0
            freeze_ok = (
                bool(evidence_summary.get("evidence_root_exists"))
                and quota >= int(prepared.expected_runs)
                and apps_ok >= int(prepared.dataset_apps_total)
            ) if evidence_summary else False
            remaining = max(0, int(prepared.expected_runs) - int(quota))
            row_models = list(prepared.row_models or [])
            extra_runs = int(evidence_summary.get("extra_eligible_runs", 0)) if evidence_summary else 0
            next_row = _next_recommended_row(row_models)
            _render_queue_summary_block(
                prepared=prepared,
                quota=quota,
                apps_ok=apps_ok,
                remaining=remaining,
                extra_runs=extra_runs,
                freeze_ok=freeze_ok,
                next_row=next_row,
            )

            if next_row:
                print()

            _render_compact_queue_table(
                row_models,
                baseline_required=int(getattr(prepared.cfg, "baseline_required", 3)),
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 2)),
            )
            warnings_line = _compact_warning_line(row_models)
            if warnings_line:
                print()
                print(f"Warnings: {warnings_line}")
            notes_line = _compact_note_line(row_models)
            if notes_line:
                print()
                print(f"Notes   : {notes_line}")
            print()
        print()
        print("Select an app by number or name.")
        shortcuts = ["S summary", "Y history", "H help", "D diagnostics", "B back"]
        print(f"Shortcuts         : {' | '.join(shortcuts)}")
        choice = prompt_utils.prompt_text("Choose app # / name", required=False).strip()

        if not choice:
            index = choose_package_selection(prepared)
            if index is None:
                return None
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        choice_lc = choice.lower()
        if choice_lc in {"s", "summary"}:
            from scytaledroid.DynamicAnalysis.menus.status_reports import render_cohort_status_details

            render_cohort_status_details(
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
                interactive_required=int(getattr(prepared.cfg, "interactive_required", 2)),
            )
            continue
        if choice_lc in {"y", "history"}:
            from scytaledroid.DynamicAnalysis.menus.status_reports import render_cohort_build_history

            render_cohort_build_history(list(prepared.row_models or []), prepared.build_rows)
            continue
        if choice_lc in {"h", "help"}:
            from scytaledroid.DynamicAnalysis.menus.status_reports import render_cohort_status_help

            render_cohort_status_help()
            continue
        if choice_lc in {"d", "debug", "diagnostics"}:
            from scytaledroid.DynamicAnalysis.menus.status_reports import render_cohort_status_debug

            render_cohort_status_debug(prepared.rows, list(prepared.row_models or []))
            continue
        if choice_lc in {"0", "b", "back", "cancel"}:
            return None
        index = resolve_package_selection(choice, prepared)
        if index is not None:
            package_name, _, _, _ = prepared.packages[index]
            return package_name
        print(status_messages.status("Invalid choice. Enter an app number/name or use S, Y, H, D, or B.", level="warn"))


def _recommended_reason(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.recommended_reason(row)


def _compact_warning_line(row_models: list[PreparedPackageSelectionRow]) -> str:
    return _app_queue_state.compact_warning_line(row_models)


def _compact_note_line(row_models: list[PreparedPackageSelectionRow]) -> str:
    return _app_queue_state.compact_note_line(row_models)


def _attention_items(row_models: list[PreparedPackageSelectionRow]) -> list[str]:
    return _app_queue_state.attention_items(row_models)


def _render_compact_queue_table(
    rows: list[PreparedPackageSelectionRow],
    *,
    baseline_required: int,
    interactive_required: int,
) -> None:
    _app_queue_rendering.render_compact_queue_table(
        rows,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        terminal_mod=terminal,
        table_utils_mod=table_utils,
        text_blocks_mod=text_blocks,
    )


def _queue_app_width() -> int:
    return _app_queue_rendering.queue_app_width(terminal_mod=terminal)


def _queue_compact_layout_mode() -> str:
    return _app_queue_rendering.queue_compact_layout_mode(terminal_mod=terminal)


def _render_queue_summary_block(
    *,
    prepared: PreparedPackageSelectionView,
    quota: int,
    apps_ok: int,
    remaining: int,
    extra_runs: int,
    freeze_ok: bool,
    next_row: PreparedPackageSelectionRow | None,
) -> None:
    _app_queue_rendering.render_queue_summary_block(
        prepared=prepared,
        quota=quota,
        apps_ok=apps_ok,
        remaining=remaining,
        extra_runs=extra_runs,
        freeze_ok=freeze_ok,
        next_row=next_row,
    )


def _archive_blocker_summary(row_models: list[PreparedPackageSelectionRow]) -> str:
    return _app_queue_state.archive_blocker_summary(row_models)


def _queue_state_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_state_label(row)


def _queue_need_label(
    row: PreparedPackageSelectionRow,
    *,
    baseline_required: int,
    interactive_required: int,
) -> str:
    return _app_queue_state.queue_need_label(
        row,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
    )


def _queue_runs_label(row: PreparedPackageSelectionRow, *, total_required: int) -> str:
    return _app_queue_state.queue_runs_label(row, total_required=total_required)


def _queue_build_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_build_label(row)


def _queue_evidence_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_evidence_label(row)


def _queue_qa_badge(value: str) -> str:
    return _app_queue_state.queue_qa_badge(value)


def _queue_template_label(package_name: str) -> str:
    return _app_queue_state.queue_template_label(package_name)


def _queue_action_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_action_label(row)


def _queue_state_summary_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_state_summary_label(row)


def _queue_status_narrow_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_status_narrow_label(row)


def _queue_need_narrow_label(
    row: PreparedPackageSelectionRow,
    *,
    baseline_required: int,
    interactive_required: int,
) -> str:
    return _app_queue_state.queue_need_narrow_label(
        row,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
    )


def _queue_runs_narrow_label(row: PreparedPackageSelectionRow, *, total_required: int) -> str:
    return _app_queue_state.queue_runs_narrow_label(row, total_required=total_required)


def _queue_action_narrow_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.queue_action_narrow_label(row)


def _display_action_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.display_action_label(row)


def _display_next_line_action_label(row: PreparedPackageSelectionRow) -> str:
    return _app_queue_state.display_next_line_action_label(row)


def _next_recommendation_priority(row: PreparedPackageSelectionRow) -> tuple[int, str]:
    return _app_queue_state.next_recommendation_priority(row)


def _next_recommended_row(
    rows: list[PreparedPackageSelectionRow],
) -> PreparedPackageSelectionRow | None:
    return _app_queue_state.next_recommended_row(rows)


def _group_queue_sections(
    row_models: list[PreparedPackageSelectionRow],
) -> list[tuple[str, list[PreparedPackageSelectionRow]]]:
    return _app_queue_state.group_queue_sections(row_models)


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
        print(status_messages.status(f"Multiple apps matched \"{raw}\". Please enter the app number.", level="warn"))
    return None
