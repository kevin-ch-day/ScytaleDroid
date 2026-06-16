"""UI helpers for Dynamic Analysis menu rendering."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_static_handoff_plan_summary
from scytaledroid.Utils.DisplayUtils import status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption


@dataclass(frozen=True)
class DynamicMenuSections:
    primary_actions: list[MenuOption]
    validation: list[MenuOption]
    maintenance: list[MenuOption]
    archive_export: list[MenuOption]

    @property
    def all_options(self) -> list[MenuOption]:
        return [
            *self.primary_actions,
            *self.validation,
            *self.maintenance,
            *self.archive_export,
        ]


def _quota_reason_text(summary) -> str:
    reason = _humanize_code(summary.first_failing_reason)
    expected = int(getattr(summary, "expected_valid_runs", 0) or 0)
    quota_valid = int(getattr(summary, "quota_runs_counted", 0) or 0)
    if str(getattr(summary, "first_failing_reason", "") or "").strip().upper() == "QUOTA_NOT_SATISFIED" and expected > 0:
        remaining = max(0, expected - quota_valid)
        return f"{reason} — {remaining} quota-valid runs remaining"
    return reason


def build_dynamic_menu_sections() -> DynamicMenuSections:
    return DynamicMenuSections(
        primary_actions=[
            MenuOption("1", "Focused app run"),
            MenuOption("2", "Cohort run"),
        ],
        validation=[
            MenuOption("3", "State summary"),
            MenuOption("4", "Archive readiness"),
        ],
        maintenance=[
            MenuOption("5", "Verify capture environment"),
            MenuOption("6", "Maintenance tools"),
        ],
        archive_export=[],
    )


def _humanize_code(value: str | None, *, hyphenate_go: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        return "none"
    normalized = text.replace("_", "-") if hyphenate_go else text.replace("_", " ")
    lowered = normalized.lower()
    if hyphenate_go:
        return lowered.upper() if lowered in {"go", "no-go"} else normalized
    return lowered


def render_dynamic_menu_overview() -> None:
    try:
        summary = run_freeze_readiness_audit()
    except Exception:
        print(status_messages.status("Dynamic state overview unavailable.", level="warn"))
        return

    try:
        handoff = build_static_handoff_plan_summary()
    except Exception:
        handoff = {}
    handoff_ready = 0
    handoff_total = 0
    handoff_status = "unknown"
    if handoff:
        handoff_ready = int(handoff.get("dataset_packages_with_plan") or 0)
        handoff_total = int(handoff.get("dataset_packages_total") or 0)
        if handoff_total and handoff_ready == handoff_total:
            handoff_status = f"ready ({handoff_ready}/{handoff_total} plans)"
        elif handoff_total:
            handoff_status = f"partial ({handoff_ready}/{handoff_total} plans)"
    evidence_text = (
        "none yet"
        if int(summary.total_runs) == 0
        else f"{summary.total_runs} packs ({summary.valid_runs} valid)"
    )
    quota_valid = int(getattr(summary, "quota_runs_counted", 0) or 0)
    expected_valid = int(getattr(summary, "expected_valid_runs", 0) or 0)
    supplemental_valid = max(0, int(getattr(summary, "valid_runs", 0) or 0) - quota_valid)
    freeze_text = "ready" if summary.can_freeze else "blocked"
    reason_text = _quota_reason_text(summary)
    state_items = [
        summary_cards.summary_item("Evidence", evidence_text, value_style="accent"),
        summary_cards.summary_item("Quota-valid runs", f"{quota_valid} / {expected_valid}", value_style="muted"),
        *(
            [summary_cards.summary_item("Supplemental valid", f"{supplemental_valid} outside quota", value_style="muted")]
            if supplemental_valid > 0
            else []
        ),
        summary_cards.summary_item(
            "Freeze/export",
            freeze_text,
            value_style="success" if summary.can_freeze else "warning",
        ),
        summary_cards.summary_item("Reason", reason_text, value_style="muted"),
        summary_cards.summary_item(
            "Static prep",
            handoff_status,
            value_style="success" if handoff_status == "ready" else "warning",
        ),
    ]
    footer = None
    if int(summary.total_runs) == 0:
        footer = "No dynamic evidence packs are present. This is expected after cleanup or before the first run."
    print(
        summary_cards.format_summary_card(
            "Status",
            state_items,
            footer=footer,
        )
    )
