"""UI helpers for Dynamic Analysis menu rendering."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DynamicAnalysis.menus.queue_metrics import (
    resolve_active_cohort_evidence_quota_summary,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_label
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import (
    build_static_handoff_plan_summary,
)
from scytaledroid.Utils.DisplayUtils import status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption


@dataclass(frozen=True)
class DynamicMenuSections:
    primary_actions: list[MenuOption]
    validation: list[MenuOption]
    maintenance: list[MenuOption]
    archive_export: list[MenuOption]

    @property
    def ordered_actions(self) -> list[MenuOption]:
        return [
            *self.primary_actions,
            *self.validation,
            *self.maintenance,
            *self.archive_export,
        ]

    @property
    def all_options(self) -> list[MenuOption]:
        return self.ordered_actions


def _quota_reason_text(summary, *, quota_valid: int) -> str:
    reason = _humanize_code(summary.first_failing_reason)
    expected = int(getattr(summary, "expected_valid_runs", 0) or 0)
    if (
        str(getattr(summary, "first_failing_reason", "") or "").strip().upper()
        == "QUOTA_NOT_SATISFIED"
        and expected > 0
    ):
        remaining = max(0, expected - int(quota_valid))
        return f"{reason} — {remaining} quota-valid runs remaining"
    return reason


def build_dynamic_menu_sections() -> DynamicMenuSections:
    return DynamicMenuSections(
        primary_actions=[
            MenuOption(
                "1",
                "Current-build collection queue",
                description="open the live cohort queue for current-build collection",
                badge="primary",
            ),
            MenuOption(
                "2",
                "Paper-freeze readiness",
                description="review build-selected paper target readiness and latest freeze export",
            ),
            MenuOption(
                "3",
                "Focused app workbench",
                description="open one app for run options, QA, history, and diagnostics",
            ),
        ],
        validation=[
            MenuOption(
                "4", "Verify capture environment", description="host PCAP tools and prerequisites"
            ),
            MenuOption("5", "State summary", description="cohort health and collection progress"),
            MenuOption(
                "6", "Archive readiness", description="freeze gate and publication blockers"
            ),
            MenuOption("7", "Change cohort", description="switch active research dataset scope"),
        ],
        maintenance=[
            MenuOption(
                "8",
                "Maintenance / Advanced",
                description="reindex, cleanup, legacy tools, and operator exports",
            ),
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
        else f"{summary.total_runs} packs / {summary.valid_runs} valid"
    )
    try:
        quota_summary = resolve_active_cohort_evidence_quota_summary()
    except Exception:
        quota_summary = {}
    quota_valid = int(quota_summary.get("quota_runs_counted", 0) or 0)
    if quota_valid <= 0:
        quota_valid = int(getattr(summary, "quota_runs_counted", 0) or 0)
    expected_valid = int(getattr(summary, "expected_valid_runs", 0) or 0)
    freeze_text = "ready" if summary.can_freeze else "blocked"
    cohort_label = active_research_cohort_label()
    try:
        selected_device = device_manager.describe_active_device()
    except Exception:
        selected_device = "None"
    device_text = (
        selected_device if selected_device and selected_device != "None" else "none selected"
    )
    state_items = [
        summary_cards.summary_item("Device", device_text, value_style="muted"),
        summary_cards.summary_item("Cohort", cohort_label, value_style="muted"),
        summary_cards.summary_item("Evidence", evidence_text, value_style="accent"),
        summary_cards.summary_item(
            "Static prep",
            handoff_status,
            value_style="success" if handoff_status == "ready" else "warning",
        ),
        summary_cards.summary_item(
            "Archive",
            freeze_text,
            value_style="success" if summary.can_freeze else "warning",
        ),
    ]
    footer = None
    if int(summary.total_runs) == 0:
        footer = "No dynamic evidence packs are present. This is expected after cleanup or before the first run."
    elif not summary.can_freeze and expected_valid > 0:
        remaining = max(0, expected_valid - quota_valid)
        state_items.append(
            summary_cards.summary_item(
                "Remaining quota-valid runs",
                str(remaining),
                value_style="warning",
            )
        )
    print(
        summary_cards.format_summary_card(
            "Current Session",
            state_items,
            footer=footer,
        )
    )
