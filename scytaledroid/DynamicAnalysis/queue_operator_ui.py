"""Shared operator-facing labels for dynamic queue and workbench UI."""

from __future__ import annotations

from typing import Any

from scytaledroid.DynamicAnalysis.run_qualification import (
    baseline_ml_training_pool_count,
    row_baseline_ml_pool_size,
    supplemental_baseline_queue_action,
)


def operator_next_action_label(row: Any) -> str:
    """Canonical next-action phrase for summary lines and footers."""
    from scytaledroid.DynamicAnalysis import app_queue_state

    return app_queue_state.display_next_line_action_label(row)


def queue_table_ml_pool_label(row: Any) -> str:
    """Per-app ML training pool depth for queue tables."""
    pool = row_baseline_ml_pool_size(row)
    if pool > 0:
        return str(pool)
    need = int(getattr(row, "need_baseline", 0) or 0) + int(getattr(row, "need_interactive", 0) or 0)
    if need <= 0 and supplemental_baseline_queue_action(getattr(row, "next_label", None)):
        return "0"
    return "—"


def workbench_ml_pool_phrase(*, extra_valid: int, low_signal_retained: int) -> str:
    total = baseline_ml_training_pool_count(
        extra_valid=extra_valid,
        low_signal_retained=low_signal_retained,
    )
    if total <= 0:
        return "ML training pool: empty — supplemental baselines improve pattern averages"
    return f"ML training pool: {total} supplemental baseline(s) on file"


def queue_compact_legend_lines(*, has_next_marker: bool) -> list[str]:
    lines = [
        "QA: valid / invalid / valid+id (identity mismatch) / valid+L (legacy also exists)",
        "Build: current / mixed / legacy / drift / db-hist",
        "Idle Base: quota-counted idle baselines (3 target) · Non-idle: valid retained baselines outside quota, often from app-driven feed/media refresh",
        "Interactive: valid interactive runs shown against target; 'held' means baseline is not complete yet, and retained extras still stay visible in the total · ML: supplemental baseline count for training",
    ]
    if has_next_marker:
        lines.insert(0, "> marks recommended next app")
    return lines


def queue_compact_legend(*, has_next_marker: bool) -> str:
    return " · ".join(queue_compact_legend_lines(has_next_marker=has_next_marker))


def queue_selection_shortcut_hint() -> str:
    return "Select an app by number or name"


def queue_selection_shortcuts_hint() -> str:
    return "S summary · V grouped · Y history · H help · D diagnostics · B back"


__all__ = [
    "operator_next_action_label",
    "queue_compact_legend",
    "queue_compact_legend_lines",
    "queue_selection_shortcut_hint",
    "queue_selection_shortcuts_hint",
    "queue_table_ml_pool_label",
    "workbench_ml_pool_phrase",
]
