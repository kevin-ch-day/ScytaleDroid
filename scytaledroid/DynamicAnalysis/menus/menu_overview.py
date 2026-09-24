"""UI helpers for Dynamic Analysis menu rendering."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

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

_OVERVIEW_CACHE_TTL_SECONDS = 5.0
_OVERVIEW_CACHE: dict[
    tuple[str, object, object, object],
    tuple[float, Any, dict[str, object], dict[str, object]],
] = {}


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
            MenuOption("1", "Run an app", badge="primary"),
            MenuOption("2", "Continue collection (guided research)"),
            MenuOption("9", "Recent runs"),
        ],
        validation=[
            MenuOption("7", "Research cohorts"),
            MenuOption("3", "Research readiness / qualification"),
            MenuOption("5", "Collection summary"),
            MenuOption("6", "Archive readiness"),
        ],
        maintenance=[
            MenuOption("4", "Environment diagnostics"),
            MenuOption("8", "Maintenance"),
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


def _cached_overview_state(cohort_label: str) -> tuple[Any, dict[str, object], dict[str, object]]:
    now = time.monotonic()
    cache_key = (
        str(cohort_label),
        run_freeze_readiness_audit,
        build_static_handoff_plan_summary,
        resolve_active_cohort_evidence_quota_summary,
    )
    cached = _OVERVIEW_CACHE.get(cache_key)
    if cached is not None:
        cached_at, summary, handoff, quota_summary = cached
        if now - cached_at <= _OVERVIEW_CACHE_TTL_SECONDS:
            return summary, dict(handoff), dict(quota_summary)

    summary = run_freeze_readiness_audit()
    try:
        handoff = build_static_handoff_plan_summary()
    except Exception:
        handoff = {}
    try:
        quota_summary = resolve_active_cohort_evidence_quota_summary()
    except Exception:
        quota_summary = {}
    _OVERVIEW_CACHE[cache_key] = (now, summary, dict(handoff or {}), dict(quota_summary or {}))
    return summary, dict(handoff or {}), dict(quota_summary or {})


def render_dynamic_menu_overview() -> None:
    try:
        device = device_manager.describe_active_device() or "none selected"
    except Exception:
        device = "unavailable"
    print(f"Device: {device}")
    print("Capture environment: checked when starting a capture; diagnostics available below.")


def render_research_menu_overview() -> None:
    cohort_label = active_research_cohort_label()
    try:
        summary, handoff, quota_summary = _cached_overview_state(cohort_label)
    except Exception:
        print(status_messages.status("Dynamic state overview unavailable.", level="warn"))
        return

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
    quota_valid = int(quota_summary.get("quota_runs_counted", 0) or 0)
    if quota_valid <= 0:
        quota_valid = int(getattr(summary, "quota_runs_counted", 0) or 0)
    expected_valid = int(getattr(summary, "expected_valid_runs", 0) or 0)
    freeze_text = "ready" if summary.can_freeze else "blocked"
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
            value_style="success" if handoff_status.startswith("ready") else "warning",
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
