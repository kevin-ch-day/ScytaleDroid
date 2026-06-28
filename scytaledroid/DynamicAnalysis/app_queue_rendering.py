"""Rendering helpers for the dynamic app queue."""

from __future__ import annotations

from typing import Any

from scytaledroid.DynamicAnalysis import app_queue_state


def queue_app_width(*, terminal_mod: Any) -> int:
    width = terminal_mod.get_terminal_width(force_refresh=True)
    if width < 100:
        return 18
    if width < 110:
        return 20
    return 24


def queue_compact_layout_mode(*, terminal_mod: Any) -> str:
    width = terminal_mod.get_terminal_width(force_refresh=True)
    return "narrow" if width < 110 else "wide"


def render_compact_queue_table(
    rows: list[Any],
    *,
    baseline_required: int,
    interactive_required: int,
    terminal_mod: Any,
    table_utils_mod: Any,
    text_blocks_mod: Any,
) -> None:
    app_width = queue_app_width(terminal_mod=terminal_mod)
    if queue_compact_layout_mode(terminal_mod=terminal_mod) == "narrow":
        headers = ["#", "App", "State", "Need", "Baseline", "Interactive", "Build", "QA", "Next"]
        table_rows = [
            [
                row.full_row[0],
                text_blocks_mod.truncate_visible(row.display_name, app_width),
                app_queue_state.queue_status_narrow_label(row),
                app_queue_state.queue_need_narrow_label(
                    row,
                    baseline_required=baseline_required,
                    interactive_required=interactive_required,
                ),
                app_queue_state.queue_baseline_runs_label(
                    row,
                    baseline_required=baseline_required,
                ),
                app_queue_state.queue_interactive_runs_label(
                    row,
                    interactive_required=interactive_required,
                ),
                app_queue_state.queue_build_label(row),
                app_queue_state.queue_qa_badge(row.qa_label),
                app_queue_state.queue_action_narrow_label(row),
            ]
            for row in rows
        ]
    else:
        headers = ["#", "App", "State", "Need", "Baseline", "Interactive", "Build", "QA", "Next"]
        table_rows = [
            [
                row.full_row[0],
                text_blocks_mod.truncate_visible(row.display_name, app_width),
                app_queue_state.queue_state_label(row),
                app_queue_state.queue_need_label(
                    row,
                    baseline_required=baseline_required,
                    interactive_required=interactive_required,
                ),
                app_queue_state.queue_baseline_runs_label(
                    row,
                    baseline_required=baseline_required,
                ),
                app_queue_state.queue_interactive_runs_label(
                    row,
                    interactive_required=interactive_required,
                ),
                app_queue_state.queue_build_label(row),
                app_queue_state.queue_qa_badge(row.qa_label),
                app_queue_state.queue_action_label(row),
            ]
            for row in rows
        ]
    table_utils_mod.render_table(headers, table_rows, compact=False, padding=2)


def render_queue_summary_block(
    *,
    prepared: Any,
    quota: int,
    apps_ok: int,
    remaining: int,
    extra_runs: int,
    freeze_ok: bool,
    next_row: Any | None,
) -> None:
    evidence_parts = [f"{apps_ok}/{prepared.dataset_apps_total} quota-satisfied"]
    print(f"Corpus      : {' | '.join(evidence_parts)}")

    quota_parts = [f"{quota}/{prepared.expected_runs} valid", f"{remaining} remaining"]
    if extra_runs > 0:
        quota_parts.append(f"{extra_runs} supplemental")
    print(f"Quota       : {' | '.join(quota_parts)}")

    current_parts = [f"{prepared.current_build_ready_count}/{prepared.dataset_apps_total} complete"]
    if prepared.current_build_in_progress_count > 0:
        current_parts.append(f"{prepared.current_build_in_progress_count} in progress")
    if prepared.current_build_review_count > 0:
        current_parts.append(f"{prepared.current_build_review_count} review")
    if prepared.stale_app_count > 0:
        current_parts.append(f"{prepared.stale_app_count} drift")
    if prepared.current_build_db_only_count > 0:
        current_parts.append(f"{prepared.current_build_db_only_count} db-only")
    print(f"Current     : {' | '.join(current_parts)}")

    history_parts = []
    if prepared.historical_local_only_app_count > 0:
        history_parts.append(f"{prepared.historical_local_only_app_count} local-only")
    if prepared.historical_db_only_app_count > 0:
        history_parts.append(f"{prepared.historical_db_only_app_count} db-only")
    if prepared.no_evidence_anywhere_count > 0:
        history_parts.append(f"{prepared.no_evidence_anywhere_count} empty")
    print(f"History     : {' | '.join(history_parts) if history_parts else '—'}")
    print(f"Archive     : {'ready' if freeze_ok else 'blocked'}")
    if not freeze_ok:
        blocker_text = app_queue_state.archive_blocker_summary(list(prepared.row_models or []))
        if blocker_text:
            print(f"Blocked by  : {blocker_text}")
    if next_row:
        print(f"Next        : {next_row.display_name} — {app_queue_state.display_next_line_action_label(next_row)}")


def render_queue_section_table(
    rows: list[Any],
    *,
    baseline_required: int,
    interactive_required: int,
    table_utils_mod: Any,
    show_all: bool = False,
) -> None:
    headers = ["#", "App", "Baseline", "Manual", "Quota", "Prep", "QA", "Action"]
    total_required = int(baseline_required) + int(interactive_required)
    table_rows = [
        [
            row.full_row[0],
            row.display_name,
            app_queue_state.main_progress_label(row.baseline_countable, row.baseline_extra, required=baseline_required),
            app_queue_state.manual_progress_label(row, interactive_required=interactive_required),
            app_queue_state.main_progress_label(
                row.baseline_countable + row.interactive_countable,
                row.baseline_extra + row.interactive_extra,
                required=total_required,
                missing=row.need_baseline + row.need_interactive,
            ),
            row.prep_label or "—",
            app_queue_state.compact_qa_label(row.qa_label),
            app_queue_state.main_action_label(row.next_label),
        ]
        for row in rows
    ]
    max_rows = None if show_all else 15
    table_utils_mod.render_table(headers, table_rows, compact=False, max_rows=max_rows, padding=3)


def render_package_table(
    rows: list[list[str]],
    *,
    table_utils_mod: Any,
    headers: list[str] | None = None,
    max_preview: int = 15,
    show_all: bool = False,
) -> bool:
    headers = list(headers) if headers else ["#", "App"]
    selection_headers = ["#", "App", "Baseline", "Manual", "Quota", "Static prep", "Last QA", "Next action"]
    effective_preview = max_preview + 1 if len(rows) == (max_preview + 1) else max_preview
    truncated = len(rows) > effective_preview and not show_all
    rendered_rows = rows if show_all or len(rows) <= effective_preview else rows[:effective_preview]
    if headers == selection_headers:
        compact_headers = ["#", "App", "Base", "Manual", "Quota", "Prep", "QA", "Next"]
        table_utils_mod.render_table(compact_headers, compact_selection_rows(rendered_rows), compact=False)
    else:
        table_utils_mod.render_table(headers, rendered_rows, compact=False)
    if truncated:
        print(f"Showing first {effective_preview} of {len(rows)} apps.")
    return truncated


def compact_selection_rows(rows: list[list[str]]) -> list[list[str]]:
    return [
        [
            row[0],
            row[1],
            app_queue_state.compact_progress_label(row[2]),
            app_queue_state.compact_progress_label(row[3]),
            app_queue_state.compact_progress_label(row[4]),
            app_queue_state.compact_prep_label(row[5]),
            app_queue_state.compact_qa_label(row[6]),
            app_queue_state.compact_next_action(row[7]),
        ]
        for row in rows
    ]


__all__ = [
    "compact_selection_rows",
    "queue_app_width",
    "queue_compact_layout_mode",
    "render_compact_queue_table",
    "render_package_table",
    "render_queue_section_table",
    "render_queue_summary_block",
]
