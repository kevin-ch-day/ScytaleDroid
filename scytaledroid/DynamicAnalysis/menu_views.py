"""UI helpers for Dynamic Analysis menu rendering."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption


@dataclass(frozen=True)
class DynamicMenuSections:
    primary_actions: list[MenuOption]
    evidence_integrity: list[MenuOption]
    exports: list[MenuOption]
    system: list[MenuOption]
    legacy_archive: list[MenuOption]

    @property
    def all_options(self) -> list[MenuOption]:
        return [
            *self.primary_actions,
            *self.legacy_archive,
            *self.evidence_integrity,
            *self.exports,
            *self.system,
        ]


def build_dynamic_menu_sections() -> DynamicMenuSections:
    return DynamicMenuSections(
        primary_actions=[
            MenuOption("1", "Guided cohort run (Research Dataset Alpha)"),
            MenuOption("2", "Cohort status overview"),
        ],
        legacy_archive=[
            MenuOption("3", "Archived structural cohort tools"),
        ],
        evidence_integrity=[
            MenuOption("4", "Freeze readiness audit (evidence packs)"),
            MenuOption("5", "Reindex/repair tracker from evidence packs"),
            MenuOption("6", "Prune incomplete dynamic evidence dirs"),
        ],
        exports=[
            MenuOption("7", "Export frozen archive CSVs (Reporting)"),
        ],
        system=[
            MenuOption("8", "Verify host PCAP tools (tshark + capinfos)"),
            MenuOption("9", "State summary (freeze/evidence/tracker deltas)"),
        ],
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


def _short_path(path_value: str | Path) -> str:
    path = Path(path_value)
    try:
        return str(path.relative_to(Path.cwd()))
    except Exception:
        return str(path)


def render_dynamic_menu_overview() -> None:
    try:
        summary = run_freeze_readiness_audit()
    except Exception:
        print(status_messages.status("Dynamic state overview unavailable.", level="warn"))
        return

    capability = status_messages.status(
        "ENABLED" if summary.can_freeze else "BLOCKED",
        level="success" if summary.can_freeze else "blocked",
        show_icon=False,
        show_prefix=False,
    )
    latest_freeze = (
        f"dataset_freeze.json ({summary.canonical_freeze_role})"
        if str(summary.canonical_freeze_role or "").strip().lower() not in {"", "none"}
        else "none"
    )
    freeze_manifest = Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"
    tracker_state = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    print(
        summary_cards.format_summary_card(
            "Dynamic State",
            [
                summary_cards.summary_item("Freeze capability", "ENABLED" if summary.can_freeze else "BLOCKED", value_style="success" if summary.can_freeze else "warning"),
                summary_cards.summary_item("Freeze audit", _humanize_code(summary.result, hyphenate_go=True), value_style="success" if str(summary.result).upper() == "GO" else "warning"),
                summary_cards.summary_item("Reason", _humanize_code(summary.first_failing_reason), value_style="muted"),
                summary_cards.summary_item(
                    "Evidence packs",
                    f"{summary.total_runs} (valid {summary.valid_runs}, invalid {max(int(summary.total_runs) - int(summary.valid_runs), 0)})",
                    value_style="accent",
                ),
                summary_cards.summary_item("Latest freeze", latest_freeze, value_style="text"),
            ],
            subtitle="Freeze readiness, evidence health, and tracker alignment.",
        )
    )
    print()
    print(
        summary_cards.format_summary_card(
            "Evidence Roots",
            [
                summary_cards.summary_item("Root", _short_path(summary.evidence_root), value_style="muted"),
                summary_cards.summary_item("Freeze", _short_path(freeze_manifest), value_style="muted"),
                summary_cards.summary_item("Tracker", _short_path(tracker_state), value_style="muted"),
            ],
            footer="Use State summary for per-app tracker vs evidence deltas.",
        )
    )
