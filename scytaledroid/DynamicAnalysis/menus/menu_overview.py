"""UI helpers for Dynamic Analysis menu rendering."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_static_handoff_plan_summary
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_label
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
            MenuOption("2", "App queue / next action"),
        ],
        validation=[
            MenuOption("3", "State summary"),
            MenuOption("4", "Archive readiness"),
        ],
        maintenance=[
            MenuOption("5", "Verify capture environment"),
            MenuOption("6", "Change cohort"),
            MenuOption("7", "Reindex tracker"),
            MenuOption("8", "Prune incomplete evidence"),
            MenuOption("9", "Legacy structural tools"),
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
    cohort_label = active_research_cohort_label()
    try:
        selected_device = device_manager.describe_active_device()
    except Exception:
        selected_device = "None"
    device_text = selected_device if selected_device and selected_device != "None" else "none selected"
    subtitle = f"{cohort_label} · {device_text}"
    quota_text = f"{quota_valid} / {expected_valid} valid"
    if expected_valid > 0 and not summary.can_freeze:
        remaining = max(0, expected_valid - quota_valid)
        quota_text += f" ({remaining} remaining)"
    next_step = _next_step_text(
        summary=summary,
        handoff_ready=handoff_ready,
        handoff_total=handoff_total,
        selected_device_text=device_text,
    )
    state_items = [
        summary_cards.summary_item("Evidence", evidence_text, value_style="accent"),
        summary_cards.summary_item("Quota", quota_text, value_style="muted"),
        *(
            [summary_cards.summary_item("Supplemental", f"{supplemental_valid} outside quota", value_style="muted")]
            if supplemental_valid > 0
            else []
        ),
        summary_cards.summary_item(
            "Archive",
            freeze_text,
            value_style="success" if summary.can_freeze else "warning",
        ),
        summary_cards.summary_item("Why blocked", reason_text, value_style="muted"),
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
            subtitle=subtitle,
            footer=footer or next_step,
        )
    )


def _next_step_text(
    *,
    summary,
    handoff_ready: int,
    handoff_total: int,
    selected_device_text: str,
) -> str:
    if str(selected_device_text or "").strip().lower() == "none selected":
        return "Next: select a capture device, then open App queue / next action."
    if int(getattr(summary, "total_runs", 0) or 0) == 0:
        return "Next: use Focused app run or App queue / next action to create evidence."
    if handoff_total > 0 and handoff_ready < handoff_total:
        return "Next: static prep is incomplete; review State summary before collecting more runs."
    reason_code = str(getattr(summary, "first_failing_reason", "") or "").strip().upper()
    if reason_code == "QUOTA_NOT_SATISFIED":
        return "Next: open App queue / next action to continue collection."
    if not bool(getattr(summary, "can_freeze", False)):
        return "Next: review Archive readiness for the current blocker."
    return "Next: archive readiness checks are satisfied."
