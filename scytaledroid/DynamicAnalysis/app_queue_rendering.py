"""Rendering helpers for the dynamic app queue."""

from __future__ import annotations

import re
from typing import Any

from scytaledroid.DynamicAnalysis import app_queue_state
from scytaledroid.DynamicAnalysis.queue_operator_ui import (
    operator_next_action_label,
    queue_compact_legend_lines,
    queue_selection_shortcut_hint,
    queue_selection_shortcuts_hint,
    queue_table_ml_pool_label,
)
from scytaledroid.DynamicAnalysis.run_qualification import cohort_baseline_ml_pool_total
from scytaledroid.Utils.DisplayUtils import colors
from scytaledroid.Utils.DisplayUtils import text_blocks as _text_blocks
from scytaledroid.Utils.DisplayUtils.summary_cards import print_summary_card, summary_item

_QUEUE_LAYOUT_WIDE_MIN = 120
_QUEUE_LAYOUT_STANDARD_MIN = 88
_PROGRESS_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d+)")


def _apply_style(text: str, role: str, *, bold: bool = False) -> str:
    if not text:
        return text
    return colors.apply(text, colors.style(role), bold=bold)


def _style_status_label(value: str) -> str:
    key = str(value or "").strip().lower()
    if key == "complete":
        return _apply_style(value, "success", bold=True)
    if key in {"interactive", "restore"}:
        return _apply_style(value, "accent", bold=True)
    if key == "baseline":
        return _apply_style(value, "warning", bold=True)
    if key == "refresh":
        return _apply_style(value, "error", bold=True)
    if key in {"review", "blocked"}:
        return _apply_style(value, "blocked", bold=True)
    return _apply_style(value, "muted")


def _style_qa_label(value: str) -> str:
    key = str(value or "").strip().lower()
    if key.startswith("invalid"):
        return _apply_style(value, "error", bold=True)
    if "id" in key:
        return _apply_style(value, "warning", bold=True)
    if key.startswith("valid+l"):
        return _apply_style(value, "accent", bold=True)
    if key.startswith("valid"):
        return _apply_style(value, "success", bold=True)
    return _apply_style(value, "muted")


def _style_build_label(value: str) -> str:
    key = str(value or "").strip().lower()
    if key == "current":
        return _apply_style(value, "success", bold=True)
    if key == "mixed":
        return _apply_style(value, "warning", bold=True)
    if key == "drift":
        return _apply_style(value, "error", bold=True)
    if key in {"legacy", "db-hist"}:
        return _apply_style(value, "muted")
    return _apply_style(value, "accent")


def _style_progress_label(value: str) -> str:
    text = str(value or "").strip()
    if not text or text == "—":
        return _apply_style(text or "—", "muted")
    if "held" in text.lower():
        return _apply_style(text, "warning", bold=True)
    match = _PROGRESS_RE.match(text)
    if not match:
        return _apply_style(text, "accent")
    numerator = int(match.group(1))
    denominator = max(1, int(match.group(2)))
    if numerator >= denominator:
        return _apply_style(text, "success", bold=True)
    if numerator <= 0:
        return _apply_style(text, "muted")
    ratio = numerator / denominator
    if ratio >= 0.5:
        return _apply_style(text, "accent", bold=True)
    return _apply_style(text, "warning", bold=True)


def _style_non_idle_label(value: str) -> str:
    text = str(value or "").strip()
    if not text or text == "0":
        return _apply_style(text or "0", "muted")
    return _apply_style(text, "warning", bold=True)


def _style_ml_label(value: str) -> str:
    text = str(value or "").strip()
    if not text or text == "—":
        return _apply_style(text or "—", "muted")
    if text == "0":
        return _apply_style(text, "muted")
    return _apply_style(text, "accent", bold=True)


def _style_app_label(value: str, *, next_row: bool) -> str:
    if next_row:
        return _apply_style(value, "accent", bold=True)
    return value


def queue_app_width(*, terminal_mod: Any, layout: str | None = None) -> int:
    width = terminal_mod.get_terminal_width(force_refresh=True)
    layout = layout or queue_layout_mode(terminal_mod=terminal_mod)
    if layout == "narrow":
        return max(12, min(18, width // 7))
    if layout == "wide":
        return max(14, min(20, width // 9))
    return max(14, min(22, width // 6))


def queue_layout_mode(*, terminal_mod: Any) -> str:
    width = terminal_mod.get_terminal_width(force_refresh=True)
    if width >= _QUEUE_LAYOUT_WIDE_MIN:
        return "wide"
    if width >= _QUEUE_LAYOUT_STANDARD_MIN:
        return "standard"
    return "narrow"


def queue_compact_layout_mode(*, terminal_mod: Any) -> str:
    return queue_layout_mode(terminal_mod=terminal_mod)


def queue_compact_table_headers(*, layout: str | None = None, narrow: bool = False) -> list[str]:
    if narrow or layout == "narrow":
        return ["#", "App", "St", "QA", "Bld", "IB", "NB", "Int"]
    if layout == "wide":
        return [
            "#",
            "App",
            "Status",
            "QA",
            "Build",
            "Idle Base",
            "Non-idle",
            "Interactive",
            "ML",
        ]
    return ["#", "App", "Status", "QA", "Build", "Idle Base", "Non-idle", "Interactive"]


def _queue_table_row_cells(
    row: Any,
    *,
    baseline_required: int,
    interactive_required: int,
    app_width: int,
    status_label_fn: Any,
    text_blocks_mod: Any,
    layout: str,
    next_row: Any | None = None,
) -> list[str]:
    is_next = app_queue_state.queue_row_is_next_recommended(row, next_row)
    app_label = text_blocks_mod.truncate_visible(
        app_queue_state.queue_table_app_label(row.display_name),
        app_width,
    )
    status_label = status_label_fn(row)
    qa_label = app_queue_state.queue_table_qa_label(row)
    build_label = app_queue_state.queue_table_build_label(row)
    idle_label = app_queue_state.queue_idle_baseline_label(
        row,
        baseline_required=baseline_required,
    )
    non_idle_label = app_queue_state.queue_non_idle_baseline_label(row)
    interactive_label = app_queue_state.queue_interactive_total_label(
        row,
        interactive_required=interactive_required,
    )
    cells = [
        app_queue_state.queue_table_index_label(row, next_row=next_row),
        _style_app_label(app_label, next_row=is_next),
        _style_status_label(status_label),
        _style_qa_label(qa_label),
    ]
    if layout == "wide":
        cells.extend(
            [
                _style_build_label(build_label),
                _style_progress_label(idle_label),
                _style_non_idle_label(non_idle_label),
                _style_progress_label(interactive_label),
                _style_ml_label(queue_table_ml_pool_label(row)),
            ]
        )
        return cells
    cells.append(_style_build_label(build_label))
    cells.extend(
        [
            _style_progress_label(idle_label),
            _style_non_idle_label(non_idle_label),
            _style_progress_label(interactive_label),
        ]
    )
    return cells


def _queue_table_min_widths(*, layout: str) -> list[int]:
    if layout == "wide":
        return [2, 10, 8, 6, 7, 9, 8, 11, 3]
    if layout == "standard":
        return [2, 12, 10, 5, 7, 9, 8, 11]
    return [2, 10, 4, 5, 5, 4, 4, 7]


def _queue_table_column_styles(*, layout: str) -> list[str]:
    if layout == "wide":
        return ["", "", "status", "qa", "", "", "", "", "muted"]
    if layout == "standard":
        return ["", "", "status", "qa", "", "", "", ""]
    return ["", "", "status", "qa", "", "", "", ""]


def render_compact_queue_table(
    rows: list[Any],
    *,
    baseline_required: int,
    interactive_required: int,
    terminal_mod: Any,
    table_utils_mod: Any,
    text_blocks_mod: Any,
    next_row: Any | None = None,
) -> None:
    layout = queue_layout_mode(terminal_mod=terminal_mod)
    app_width = queue_app_width(terminal_mod=terminal_mod, layout=layout)
    headers = queue_compact_table_headers(layout=layout)
    status_label_fn = (
        app_queue_state.queue_status_narrow_label
        if layout == "narrow"
        else app_queue_state.queue_status_label
    )
    table_rows = [
        _queue_table_row_cells(
            row,
            baseline_required=baseline_required,
            interactive_required=interactive_required,
            app_width=app_width,
            status_label_fn=status_label_fn,
            text_blocks_mod=text_blocks_mod,
            layout=layout,
            next_row=next_row,
        )
        for row in rows
    ]
    table_utils_mod.render_table(
        headers,
        table_rows,
        compact=False,
        padding=2,
        min_widths=_queue_table_min_widths(layout=layout),
        column_styles=_queue_table_column_styles(layout=layout),
        zebra=True,
    )
    print()
    legend_lines = queue_compact_legend_lines(has_next_marker=next_row is not None)
    legend_items = [
        summary_item(
            "QA",
            legend_lines[1 if next_row is not None else 0].split(": ", 1)[1],
            value_style="muted",
        ),
        summary_item(
            "Build",
            legend_lines[2 if next_row is not None else 1].split(": ", 1)[1],
            value_style="muted",
        ),
        summary_item("Idle Base", "quota-counted idle baselines (3 target)", value_style="success"),
        summary_item(
            "Non-idle",
            "valid retained baselines outside quota; often app-driven feed/media refresh",
            value_style="warning",
        ),
        summary_item(
            "Interactive",
            "valid runs shown against target; held = baseline incomplete",
            value_style="accent",
        ),
        summary_item(
            "ML", "supplemental baseline count available for training", value_style="muted"
        ),
    ]
    footer = legend_lines[0] if next_row is not None else None
    print_summary_card("Queue key", legend_items, footer=footer)


def _clean_footer_line(text: str) -> str:
    line = str(text or "").strip()
    if line.endswith(". Press D."):
        return line[: -len(". Press D.")].rstrip()
    return line


def render_queue_footer_block(
    *,
    warnings_line: str = "",
    notes_line: str = "",
) -> None:
    items = [
        summary_item("Select", queue_selection_shortcut_hint(), value_style="accent"),
        summary_item("Shortcuts", queue_selection_shortcuts_hint(), value_style="muted"),
    ]
    footer_parts: list[str] = []
    if warnings_line:
        items.insert(
            0,
            summary_item("Attention", _clean_footer_line(warnings_line), value_style="warning"),
        )
        footer_parts.append("Press D for deeper diagnostics.")
    if notes_line:
        items.append(summary_item("Notes", _clean_footer_line(notes_line), value_style="muted"))
        if not footer_parts:
            footer_parts.append("Press D for evidence lineage detail.")
    print()
    print_summary_card(
        "Queue actions",
        items,
        footer=" ".join(footer_parts) if footer_parts else None,
    )


def render_queue_summary_block(
    *,
    prepared: Any,
    quota: int,
    apps_ok: int,
    remaining: int,
    extra_runs: int,
    freeze_ok: bool,
    next_row: Any | None,
    capture_device_selected: bool = True,
) -> None:
    ml_pool_total = cohort_baseline_ml_pool_total(list(getattr(prepared, "row_models", None) or []))
    row_models = list(prepared.row_models or [])

    current_parts = [f"{prepared.current_build_ready_count}/{prepared.dataset_apps_total} complete"]
    if prepared.current_build_in_progress_count > 0:
        current_parts.append(f"{prepared.current_build_in_progress_count} in progress")
    if prepared.current_build_review_count > 0:
        current_parts.append(f"{prepared.current_build_review_count} review")
    if prepared.stale_app_count > 0:
        current_parts.append(f"{prepared.stale_app_count} drift")
    if prepared.current_build_db_only_count > 0:
        current_parts.append(f"{prepared.current_build_db_only_count} db-only")

    history_parts = []
    if prepared.historical_local_only_app_count > 0:
        history_parts.append(f"{prepared.historical_local_only_app_count} local-only")
    if prepared.historical_db_only_app_count > 0:
        history_parts.append(f"{prepared.historical_db_only_app_count} db-only")
    if prepared.no_evidence_anywhere_count > 0:
        history_parts.append(f"{prepared.no_evidence_anywhere_count} empty")

    quota_value = f"{quota}/{prepared.expected_runs} valid"
    if remaining > 0:
        quota_value += f" ({remaining} remaining)"
    if extra_runs > 0:
        quota_value += f" · {extra_runs} retained extra"

    items = [
        summary_item(
            "Apps",
            f"{apps_ok}/{prepared.dataset_apps_total} quota-satisfied",
            value_style="accent",
        ),
        summary_item(
            "Quota" if capture_device_selected else "Tracked-build queue",
            quota_value,
            value_style="warning" if remaining > 0 else "success",
        ),
        summary_item(
            "Current build" if capture_device_selected else "Tracked build",
            " · ".join(current_parts),
            value_style="warning" if prepared.stale_app_count > 0 else "accent",
        ),
        summary_item(
            "History",
            " · ".join(history_parts) if history_parts else "—",
            value_style="muted",
        ),
        summary_item(
            "Archive",
            "ready" if freeze_ok else "blocked",
            value_style="success" if freeze_ok else "warning",
        ),
    ]
    if ml_pool_total > 0:
        items.append(
            summary_item(
                "ML pool",
                f"{ml_pool_total} supplemental baseline(s)",
                value_style="emphasis",
            )
        )
    elif remaining <= 0:
        items.append(
            summary_item(
                "ML pool",
                "run supplemental baselines for training",
                value_style="muted",
            )
        )

    if not freeze_ok:
        blocker_text = app_queue_state.queue_remaining_summary(row_models)
        if blocker_text:
            items.append(
                summary_item(
                    "Remaining",
                    blocker_text,
                    value_style="warning",
                )
            )
    if next_row:
        items.append(
            summary_item(
                "Next",
                f"{next_row.display_name} — {operator_next_action_label(next_row)}",
                value_style="accent",
            )
        )
    footer_lines: list[str] = []
    if not capture_device_selected:
        footer_lines.append(
            "Select a device to verify live build drift and enable capture guidance."
        )
    elif remaining > 0:
        capture_plan = app_queue_state.format_capture_plan_line(row_models, limit=3)
        if capture_plan:
            items.append(
                summary_item(
                    "Capture plan",
                    capture_plan,
                    value_style="muted",
                )
            )

    print_summary_card(
        "Cohort status",
        items,
        footer="\n".join(footer_lines) if footer_lines else None,
    )
    print()


def render_queue_grouped_sections(
    row_models: list[Any],
    *,
    baseline_required: int,
    interactive_required: int,
    table_utils_mod: Any,
    menu_utils_mod: Any,
    next_row: Any | None = None,
) -> None:
    sections = app_queue_state.group_queue_sections(row_models)
    menu_utils_mod.print_section("Grouped view")
    for title, section_rows in sections:
        if not section_rows:
            continue
        print()
        menu_utils_mod.print_section(f"{title} ({len(section_rows)})")
        render_queue_section_table(
            section_rows,
            baseline_required=baseline_required,
            interactive_required=interactive_required,
            table_utils_mod=table_utils_mod,
            show_all=len(section_rows) <= 8,
            next_row=next_row,
        )


def render_queue_section_table(
    rows: list[Any],
    *,
    baseline_required: int,
    interactive_required: int,
    table_utils_mod: Any,
    show_all: bool = False,
    next_row: Any | None = None,
) -> None:
    headers = queue_compact_table_headers(layout="wide")
    table_rows = [
        _queue_table_row_cells(
            row,
            baseline_required=baseline_required,
            interactive_required=interactive_required,
            app_width=18,
            status_label_fn=app_queue_state.queue_status_label,
            text_blocks_mod=_text_blocks,
            layout="wide",
            next_row=next_row,
        )
        for row in rows
    ]
    max_rows = None if show_all else 15
    table_utils_mod.render_table(
        headers,
        table_rows,
        compact=False,
        max_rows=max_rows,
        padding=3,
        min_widths=_queue_table_min_widths(layout="wide"),
        column_styles=_queue_table_column_styles(layout="wide"),
        zebra=True,
    )


def render_package_table(
    rows: list[list[str]],
    *,
    table_utils_mod: Any,
    headers: list[str] | None = None,
    max_preview: int = 15,
    show_all: bool = False,
) -> bool:
    headers = list(headers) if headers else ["#", "App"]
    legacy_selection_headers = [
        "#",
        "App",
        "Baseline",
        "Manual",
        "Quota",
        "Static prep",
        "Last QA",
        "Next action",
    ]
    selection_headers = [
        "#",
        "App",
        "Baseline",
        "Interactive",
        "Quota",
        "Static prep",
        "Last QA",
        "Next action",
    ]
    effective_preview = max_preview + 1 if len(rows) == (max_preview + 1) else max_preview
    truncated = len(rows) > effective_preview and not show_all
    rendered_rows = rows if show_all or len(rows) <= effective_preview else rows[:effective_preview]
    if headers == selection_headers or headers == legacy_selection_headers:
        compact_headers = ["#", "App", "Base", "Int", "Quota", "Prep", "QA", "Next"]
        table_utils_mod.render_table(
            compact_headers, compact_selection_rows(rendered_rows), compact=False
        )
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
    "queue_compact_table_headers",
    "queue_layout_mode",
    "render_compact_queue_table",
    "render_queue_footer_block",
    "render_package_table",
    "render_queue_grouped_sections",
    "render_queue_section_table",
    "render_queue_summary_block",
]
