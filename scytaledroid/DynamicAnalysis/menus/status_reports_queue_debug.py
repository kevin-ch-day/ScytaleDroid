"""Queue help and debug rendering extracted from status_reports."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def render_cohort_status_help(
    *,
    menu_utils: Any,
    prompt_utils: Any,
    queue_compact_legend_fn: Callable[..., str],
    status_messages: Any,
) -> None:
    print()
    menu_utils.print_header("Help", "Queue legend")
    menu_utils.print_hint(queue_compact_legend_fn(has_next_marker=True))
    print()
    menu_utils.print_section("Columns")
    for line in (
        "Status = workflow state: complete, review, interactive, baseline, restore, refresh, or blocked.",
        "Strict Idle = quota-counted no-touch foreground baselines over the minimum (e.g. 3/3).",
        "Quiescent FG = app-generated foreground activity tag on a no-touch baseline; it is retained for analysis and is not proof of operator interaction.",
        "Interactive = valid interactive runs against the target; retained extras stay visible in the total and the baseline minimum must be complete first.",
        "QA = latest current-build run QA badge (invalid, valid+id, valid+L); explains Status=review.",
        "Build = current target state (current, drift, prior-only, db-only, none yet); wide terminals only.",
        "ML pool = quota-complete app with optional supplemental low-signal baselines for training/pattern averages.",
        "Quiescent FG baseline = valid no-touch foreground evidence with app-driven feed/media refresh activity.",
    ):
        print(status_messages.status(line, level="info", show_prefix=False))
    print()
    menu_utils.print_section("States and gaps")
    for line in (
        "held/locked = interactive quota is not open until the baseline minimum is met; the queue may still show retained interactive evidence as 0/4 held, 1/4 held, and so on.",
        "Quiescent FG is an analysis tag; low-signal baselines remain the supplemental baseline case.",
        "mixed = current-build and legacy-build evidence both exist.",
        "refresh = installed app build differs from the newest static plan (Status=refresh). Harvest/static refresh is required before dynamic continuation.",
        "identity mismatch = latest valid run does not match the active build identity; review historical vs current evidence carefully.",
        "baseline gap = baseline minimum is not met yet for quota/publication use.",
        "interactive gap = baseline is complete, but interactive quota is still missing.",
        "db-only = evidence exists in stored history/DB context but no local pack is present in this workspace.",
        "Status=restore + DB-only evidence = current-build run context is stored locally in DB, but the evidence pack is missing here.",
        "+L = latest QA valid, historical evidence also exists.",
    ):
        print(status_messages.status(line, level="info", show_prefix=False))
    print()
    menu_utils.print_section("Workflow")
    for line in (
        "refresh steps: harvest current APK(s), rerun static for that build, regenerate the newest plan, then return to the queue.",
        "Detailed local/db/history evidence lineage and QA badges moved to diagnostics (D) and run history (Y).",
        "Evidence-authoritative quota = archive/freeze truth.",
        "Tracker-scoped latest-run state = queue-operating view of the active build.",
        "Paper-target freeze readiness = best build-backed paper candidate; it may merge repeated static runs for the same APK hash.",
    ):
        print(status_messages.status(line, level="info", show_prefix=False))
    prompt_utils.press_enter_to_continue()


def render_cohort_status_debug(
    row_models: list[object],
    *,
    baseline_required: int,
    interactive_required: int,
    summary_cards: Any,
    status_messages: Any,
    menu_utils: Any,
    table_utils: Any,
    app_queue_rendering: Any,
    app_queue_state: Any,
    text_blocks: Any,
    prompt_utils: Any,
    diagnostic_db_lineage_label_fn: Callable[[object], str],
    history_reason_and_notes_fn: Callable[[object], tuple[str, list[str]]],
) -> None:
    print()
    drift_rows = [row for row in row_models if bool(getattr(row, "live_build_drift", False))]
    summary_cards.print_summary_card(
        "Queue diagnostics",
        [
            summary_cards.summary_item("Apps", str(len(row_models))),
            summary_cards.summary_item(
                "Build refresh needed",
                str(len(drift_rows)),
                value_style="warning" if drift_rows else "muted",
            ),
        ],
        subtitle="Dense raw/debug view; lower-level tracker and queue fields",
    )
    print()
    print(status_messages.status(
        "This view preserves lower-level queue fields for debugging and the tracker-scoped latest-run state.",
        level="info",
    ))
    if row_models:
        debug_rows = [
            app_queue_rendering._queue_table_row_cells(
                row,
                baseline_required=baseline_required,
                interactive_required=interactive_required,
                app_width=18,
                status_label_fn=app_queue_state.queue_status_label,
                text_blocks_mod=text_blocks,
                layout="wide",
            )
            for row in row_models
        ]
        table_utils.render_table(
            app_queue_rendering.queue_compact_table_headers(layout="wide"),
            debug_rows,
            compact=False,
        )
        if drift_rows:
            print()
            menu_utils.print_section(f"Build refresh required ({len(drift_rows)})")
            print(status_messages.status(
                "Refresh harvest/static before continuing dataset-mode dynamic capture.",
                level="warn",
            ))
            for row in drift_rows:
                expected_vc = str(getattr(row, "live_expected_version_code", "") or "").strip() or "unknown"
                expected_vn = str(getattr(row, "live_expected_version_name", "") or "").strip()
                static_plan = f"{expected_vn} ({expected_vc})" if expected_vn else expected_vc
                observed_vc = str(getattr(row, "live_observed_version_code", "") or "").strip() or "unknown"
                static_run_id = str(getattr(row, "live_static_run_id", "") or "").strip() or "unknown"
                print()
                print(str(getattr(row, "display_name", "—") or "—"))
                print(f"  Package     : {str(getattr(row, 'package_name', '—') or '—')}")
                print(f"  Installed   : {observed_vc}")
                print(f"  Static plan : {static_plan}")
                print(f"  Static run  : {static_run_id}")
                print("  Status      : refresh harvest/static, then return to dynamic queue")
        print()
        menu_utils.print_section("Operator summary")
        summary_rows = [
            [
                getattr(row, "display_name", "—"),
                app_queue_state.queue_status_label(row),
                history_reason_and_notes_fn(row)[0],
                diagnostic_db_lineage_label_fn(row),
                str(getattr(row, "qa_label", "—") or "—"),
            ]
            for row in row_models
        ]
        table_utils.render_table(
            ["App", "Status", "Reason", "DB lineage", "Latest QA"],
            summary_rows,
            compact=False,
        )
        print()
        menu_utils.print_section("Raw state extract")
        raw_rows = [
            [
                getattr(row, "display_name", "—"),
                str(getattr(row, "baseline_countable", 0)),
                str(getattr(row, "baseline_extra", 0)),
                str(getattr(row, "baseline_low_signal_supplemental", 0)),
                str(getattr(row, "baseline_not_idle_supplemental", 0)),
                str(getattr(row, "interactive_countable", 0)),
                str(getattr(row, "interactive_extra", 0)),
                str(getattr(row, "interactive_low_signal_supplemental", 0)),
                str(getattr(row, "historical_valid_runs_count", 0)),
                str(getattr(row, "historical_build_count", 0)),
                str(getattr(row, "need_baseline", 0)),
                str(getattr(row, "need_interactive", 0)),
                str(getattr(row, "lineage_state", "")),
                str(getattr(row, "db_active_sessions", 0)),
                str(getattr(row, "db_historical_sessions", 0)),
            ]
            for row in row_models
        ]
        table_utils.render_table(
            [
                "App",
                "Base ct",
                "Base ex",
                "Base low",
                "Base qfg",
                "Inter ct",
                "Inter ex",
                "Inter low",
                "Legacy",
                "L builds",
                "Need B",
                "Need I",
                "Lineage",
                "DB active",
                "DB hist",
            ],
            raw_rows,
            compact=True,
        )
    prompt_utils.press_enter_to_continue()


__all__ = [
    "render_cohort_status_debug",
    "render_cohort_status_help",
]
