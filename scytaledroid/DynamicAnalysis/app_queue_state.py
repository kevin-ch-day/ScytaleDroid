"""State and label helpers for the dynamic app queue."""

from __future__ import annotations

import re
from typing import Any

from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_build_compact_label,
    selected_app_build_label,
    selected_app_evidence_compact_label,
    selected_app_evidence_label,
    selected_app_qa_badge_from_label,
)
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package


def recommended_reason(row: Any) -> str:
    if row.live_build_drift:
        return "installed build differs from newest static plan"
    if row.lineage_state == "current_build_db_only":
        return "database knows current-build sessions, but local evidence pack is missing"
    if row.lineage_state == "historical_local_only":
        return "only legacy local evidence exists for older builds"
    if row.lineage_state == "historical_db_only":
        return "only database-known historical evidence exists for older builds"
    if row.lineage_state == "no_evidence_anywhere":
        return "no local or database-backed dynamic evidence exists yet"
    if row.need_baseline > 0:
        return f"baseline runs needed: {row.need_baseline}"
    if row.need_interactive > 0:
        return f"baseline complete, interactive runs needed: {row.need_interactive}"
    if row.baseline_extra > 0 or row.interactive_extra > 0:
        extra_total = int(row.baseline_extra) + int(row.interactive_extra)
        return f"quota complete, {extra_total} extra run(s) retained"
    return "quota state up to date"


def compact_warning_line(row_models: list[Any]) -> str:
    def _format_issue(
        names: list[str],
        *,
        singular_suffix: str,
        plural_label: str,
    ) -> str:
        if not names:
            return ""
        if len(names) == 1:
            return f"{names[0]} {singular_suffix}"
        if len(names) == 2:
            return f"{', '.join(names)} {singular_suffix}"
        return f"{len(names)} {plural_label}"

    issues: list[str] = []
    mixed_rows = [row.display_name for row in row_models if row.prep_label == "mixed"]
    mismatch_rows = [row.display_name for row in row_models if "id_mismatch" in str(row.qa_label)]
    historical_rows = [
        row.display_name
        for row in row_models
        if row.lineage_state in {"historical_local_only", "historical_db_only"}
    ]
    db_only_current_rows = [
        row.display_name
        for row in row_models
        if row.lineage_state == "current_build_db_only"
    ]

    if mixed_rows:
        issues.append(
            _format_issue(
                mixed_rows,
                singular_suffix="mixed current/legacy evidence",
                plural_label="mixed current/legacy evidence states",
            )
        )
    if mismatch_rows:
        issues.append(
            _format_issue(
                mismatch_rows,
                singular_suffix="identity mismatch",
                plural_label="identity mismatches",
            )
        )
    if historical_rows:
        issues.append(
            _format_issue(
                historical_rows,
                singular_suffix="history-only app",
                plural_label="history-only apps",
            )
        )
    if db_only_current_rows:
        issues.append(
            _format_issue(
                db_only_current_rows,
                singular_suffix="DB-only current-build app",
                plural_label="DB-only current-build apps",
            )
        )
    if not issues:
        return ""
    top = issues[:4]
    return " | ".join(top) + ". Press D."


def attention_items(row_models: list[Any]) -> list[str]:
    items: list[str] = []
    baseline_needed = sum(1 for row in row_models if row.need_baseline > 0)
    drift_rows = [row for row in row_models if row.live_build_drift]
    invalid_rows = [row for row in row_models if str(row.qa_label).startswith("invalid")]
    mixed_rows = [row for row in row_models if row.prep_label == "mixed"]
    historical_db_rows = [row for row in row_models if row.lineage_state == "historical_db_only"]
    mismatch_rows = [row for row in row_models if "id_mismatch" in str(row.qa_label)]
    for row in drift_rows[:3]:
        items.append(
            f"{row.display_name}: installed build {row.live_observed_version_code or 'unknown'} "
            f"drifted from static plan {row.live_expected_version_code or 'unknown'} — rerun harvest/static"
        )
    for row in invalid_rows[:3]:
        items.append(f"{row.display_name}: QA invalid — review latest run before trusting quota credit")
    for row in mixed_rows[:3]:
        active_runs = int(getattr(row, "technical_valid_active", 0) or 0)
        legacy_runs = int(getattr(row, "historical_valid_runs_count", 0) or 0)
        legacy_builds = int(getattr(row, "historical_build_count", 0) or 0)
        items.append(
            f"{row.display_name}: prep mixed — {active_runs} current-build valid run(s) and "
            f"{legacy_runs} legacy valid run(s) across {legacy_builds} older build(s)"
        )
    for row in historical_db_rows[:3]:
        items.append(
            f"{row.display_name}: only database-known historical evidence exists — recollect current-build dynamic evidence"
        )
    for row in mismatch_rows[:3]:
        items.append(f"{row.display_name}: QA identity mismatch — latest valid run does not match active build identity")
    if baseline_needed > 0:
        verb = "needs" if baseline_needed == 1 else "need"
        items.append(f"{baseline_needed} app{'s' if baseline_needed != 1 else ''} still {verb} baseline capture")
    return items


def archive_blocker_summary(row_models: list[Any]) -> str:
    if not row_models:
        return ""
    review_count = sum(1 for row in row_models if queue_state_label(row) == "review")
    refresh_count = sum(1 for row in row_models if row.live_build_drift)
    baseline_count = sum(1 for row in row_models if row.need_baseline > 0)
    manual_count = sum(1 for row in row_models if row.need_baseline <= 0 and row.need_interactive > 0)
    parts: list[str] = []
    if review_count > 0:
        parts.append(f"{review_count} review")
    if refresh_count > 0:
        parts.append(f"{refresh_count} refresh")
    if baseline_count > 0:
        parts.append(f"{baseline_count} baseline gap{'s' if baseline_count != 1 else ''}")
    if manual_count > 0:
        parts.append(f"{manual_count} manual")
    return " | ".join(parts)


def queue_state_label(row: Any) -> str:
    if row.live_build_drift:
        return "refresh"
    if row.lineage_state == "current_build_db_only":
        return "restore"
    if row.lineage_state in {"historical_local_only", "historical_db_only"}:
        if row.need_baseline > 0:
            return "baseline"
        return "legacy"
    if str(row.qa_label).startswith("invalid"):
        return "review"
    if row.need_baseline > 0:
        return "baseline"
    if row.need_interactive > 0:
        return "manual"
    if row.next_label == "—":
        return "complete"
    if row.prep_label == "mixed":
        return "review"
    return "blocked"


def queue_need_label(
    row: Any,
    *,
    baseline_required: int,
    interactive_required: int,
) -> str:
    state = queue_state_label(row)
    if row.live_build_drift:
        return "refresh"
    if row.lineage_state == "current_build_db_only":
        return "local pack"
    if row.lineage_state == "historical_local_only":
        return "current"
    if row.lineage_state == "historical_db_only":
        return "local+curr"
    if state == "review":
        return "review"
    if state == "baseline":
        return f"base {row.baseline_countable}/{int(baseline_required)}"
    if state == "manual":
        return f"manual {row.interactive_countable}/{int(interactive_required)}"
    return "—"


def queue_runs_label(row: Any, *, total_required: int) -> str:
    countable = int(row.baseline_countable) + int(row.interactive_countable)
    extra = int(row.baseline_extra) + int(row.interactive_extra)
    missing = int(row.need_baseline) + int(row.need_interactive)
    if missing <= 0:
        if extra > 0:
            return f"{countable}/{int(total_required)} +{extra}"
        return f"{countable}/{int(total_required)}"
    return f"{countable}/{int(total_required)} need {missing}"


def queue_build_label(row: Any) -> str:
    return selected_app_build_label(
        active_valid_runs=int(getattr(row, "technical_valid_active", 0) or 0),
        legacy_valid_runs=int(getattr(row, "historical_valid_runs_count", 0) or 0),
        db_active_sessions=int(getattr(row, "db_active_sessions", 0) or 0),
        db_historical_sessions=int(getattr(row, "db_historical_sessions", 0) or 0),
        lineage_state=str(getattr(row, "lineage_state", "") or ""),
        live_build_drift=bool(getattr(row, "live_build_drift", False)),
    )


def queue_evidence_label(row: Any) -> str:
    return selected_app_evidence_label(
        str(getattr(row, "lineage_state", "") or ""),
        technical_valid_active=int(getattr(row, "technical_valid_active", 0) or 0),
        db_active_sessions=int(getattr(row, "db_active_sessions", 0) or 0),
        historical_valid_runs_count=int(getattr(row, "historical_valid_runs_count", 0) or 0),
        db_historical_sessions=int(getattr(row, "db_historical_sessions", 0) or 0),
    )


def queue_qa_badge(value: str) -> str:
    return selected_app_qa_badge_from_label(value)


def queue_template_label(package_name: str) -> str:
    template_id = str(resolved_template_for_package(package_name) or "").strip()
    if not template_id:
        return "none"
    if template_id == "news_reader_basic_v1":
        return "news"
    if template_id in {
        "social_feed_basic_v2",
        "facebook_basic_v2",
        "snapchat_basic_v1",
        "x_twitter_full_session_v1",
        "social_messaging_basic_v1",
        "messaging_idle_v1",
        "messaging_text_v1",
        "messaging_voice_v1",
        "messaging_video_v1",
        "messaging_call_basic_v1",
        "whatsapp_idle_v1",
        "whatsapp_text_v1",
        "whatsapp_voice_v1",
        "whatsapp_video_v1",
        "tiktok_basic_v1",
        "tiktok_basic_v2",
    }:
        return "acct"
    return "gen"


def queue_action_label(row: Any) -> str:
    action = display_action_label(row)
    if action == "baseline":
        return "base"
    if action == "scripted":
        return "script"
    return action


def queue_state_summary_label(row: Any) -> str:
    build = queue_build_label(row)
    evidence = queue_evidence_label(row)
    qa = queue_qa_badge(row.qa_label)
    evidence_short = selected_app_evidence_compact_label(evidence)
    build_short = selected_app_build_compact_label(build)
    parts = [build_short]
    if evidence_short and evidence_short != "—":
        parts.append(evidence_short)
    if qa and qa != "—":
        parts.append(qa)
    return "/".join(parts)


def queue_status_narrow_label(row: Any) -> str:
    return {
        "complete": "done",
        "review": "review",
        "baseline": "base",
        "manual": "manual",
        "refresh": "refresh",
        "restore": "restore",
        "legacy": "legacy",
        "blocked": "block",
    }.get(queue_state_label(row), queue_state_label(row))


def queue_need_narrow_label(
    row: Any,
    *,
    baseline_required: int,
    interactive_required: int,
) -> str:
    need = queue_need_label(
        row,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
    )
    if need.startswith("base "):
        return "b " + need.split(" ", 1)[1]
    if need.startswith("manual "):
        return "m " + need.split(" ", 1)[1]
    return {
        "local pack": "local",
        "local+curr": "loc+cur",
        "current": "current",
        "refresh": "refresh",
        "review": "review",
    }.get(need, need)


def queue_runs_narrow_label(row: Any, *, total_required: int) -> str:
    text = queue_runs_label(row, total_required=total_required)
    if " need " not in text:
        return text
    prefix, missing = text.split(" need ", 1)
    return f"{prefix} n{missing}"


def queue_action_narrow_label(row: Any) -> str:
    return {
        "manual": "man",
        "script": "scr",
        "review": "rev",
        "refresh": "ref",
        "restore": "rest",
    }.get(queue_action_label(row), queue_action_label(row))


def display_action_label(row: Any) -> str:
    if row.live_build_drift:
        return "refresh"
    if row.lineage_state == "current_build_db_only":
        return "restore"
    action = main_action_label(row.next_label)
    if action != "manual":
        return action
    template = queue_template_label(row.package_name)
    if row.need_interactive > 0 and row.need_baseline <= 0 and template in {"news", "gen"}:
        return "scripted"
    return action


def display_next_line_action_label(row: Any) -> str:
    action = display_action_label(row)
    if action == "scripted":
        return "scripted interaction"
    if action == "manual":
        return "manual interaction"
    if action == "review":
        return "review QA"
    return action


def next_recommendation_priority(row: Any) -> tuple[int, str]:
    action = display_action_label(row)
    lineage_state = str(row.lineage_state or "")
    if action == "review":
        return (0, row.display_name)
    if action == "refresh":
        return (1, row.display_name)
    if action == "restore":
        return (2, row.display_name)
    if action == "scripted":
        return (3, row.display_name)
    if action == "manual":
        return (4, row.display_name)
    if action == "baseline":
        if lineage_state == "no_evidence_anywhere":
            return (5, row.display_name)
        if lineage_state == "historical_local_only":
            return (6, row.display_name)
        if lineage_state == "historical_db_only":
            return (7, row.display_name)
        return (8, row.display_name)
    return (99, row.display_name)


def next_recommended_row(rows: list[Any]) -> Any | None:
    candidates = [row for row in rows if display_action_label(row) != "—"]
    if not candidates:
        return None
    return min(candidates, key=next_recommendation_priority)


def group_queue_sections(row_models: list[Any]) -> list[tuple[str, list[Any]]]:
    needs_refresh: list[Any] = []
    ready_manual: list[Any] = []
    needs_baseline: list[Any] = []
    complete_or_extra: list[Any] = []
    other_blocked: list[Any] = []
    for row in row_models:
        if row.live_build_drift:
            needs_refresh.append(row)
        elif row.need_baseline > 0:
            needs_baseline.append(row)
        elif row.need_interactive > 0 and row.next_label == "manual interaction":
            ready_manual.append(row)
        elif row.next_label == "—":
            complete_or_extra.append(row)
        else:
            other_blocked.append(row)
    sections: list[tuple[str, list[Any]]] = []
    sections.append(("Needs static refresh", needs_refresh))
    sections.append(("Ready for manual interaction", ready_manual))
    sections.append(("Needs baseline capture", needs_baseline))
    sections.append(("Complete / over-quota", complete_or_extra))
    if other_blocked:
        sections.append(("Other / blocked", other_blocked))
    return sections


def main_progress_label(
    countable: int,
    extra: int,
    *,
    required: int,
    missing: int | None = None,
) -> str:
    count_i = max(0, int(countable))
    extra_i = max(0, int(extra))
    required_i = max(0, int(required))
    missing_i = max(0, int(missing if missing is not None else max(required_i - count_i, 0)))
    if missing_i == 0:
        if extra_i > 0:
            suffix = " extra" if extra_i == 1 else " extras"
            return f"{count_i}/{required_i} +{extra_i}{suffix}"
        return f"{count_i}/{required_i} complete"
    return f"{count_i}/{required_i} need {missing_i}"


def manual_progress_label(row: Any, *, interactive_required: int) -> str:
    if row.need_baseline > 0:
        return "locked"
    return main_progress_label(
        row.interactive_countable,
        row.interactive_extra,
        required=interactive_required,
        missing=row.need_interactive,
    )


def main_action_label(value: str) -> str:
    text = str(value or "").strip()
    if text == "manual interaction":
        return "manual"
    if text == "refresh static":
        return "refresh"
    if text == "review QA":
        return "review"
    return text or "—"


def compact_progress_label(value: str) -> str:
    text = str(value or "").strip()
    if not text or text == "—":
        return text or "—"
    if text == "locked":
        return "locked"
    complete_match = re.fullmatch(r"(\d+)/(\d+)\s+complete(?:\s+\(\+(\d+)\s+extra\))?", text)
    if complete_match:
        count = int(complete_match.group(1))
        required = int(complete_match.group(2))
        extra = int(complete_match.group(3) or 0)
        if extra > 0:
            return f"{count + extra}/{required}"
        return f"{count}/{required}"
    need_match = re.fullmatch(r"(\d+)/(\d+)\s+need\s+(\d+)(?:\s+\(\+(\d+)\s+extra\))?", text)
    if need_match:
        count = int(need_match.group(1))
        required = int(need_match.group(2))
        missing = int(need_match.group(3))
        return f"{count}/{required} n{missing}"
    return text


def compact_next_action(value: str) -> str:
    text = str(value or "").strip().lower()
    if text == "manual interaction":
        return "manual"
    return str(value or "").strip() or "—"


def compact_prep_label(value: str) -> str:
    text = str(value or "").strip().lower()
    mapping = {
        "current": "current",
        "mixed": "mixed",
        "legacy": "legacy",
        "db-only": "db-only",
        "hist-db": "hist-db",
        "ready": "ready",
        "stale": "stale",
    }
    return mapping.get(text, str(value or "").strip() or "—")


def compact_qa_label(value: str) -> str:
    text = str(value or "").strip()
    if text == "valid (L)":
        return "valid+L"
    if text == "valid (id_mismatch) (L)":
        return "valid+id+L"
    if text == "valid (id_mismatch)":
        return "valid+id"
    return text or "—"


__all__ = [
    "archive_blocker_summary",
    "attention_items",
    "compact_next_action",
    "compact_prep_label",
    "compact_progress_label",
    "compact_qa_label",
    "compact_warning_line",
    "display_action_label",
    "display_next_line_action_label",
    "group_queue_sections",
    "main_action_label",
    "main_progress_label",
    "manual_progress_label",
    "next_recommendation_priority",
    "next_recommended_row",
    "queue_action_label",
    "queue_action_narrow_label",
    "queue_build_label",
    "queue_evidence_label",
    "queue_need_label",
    "queue_need_narrow_label",
    "queue_qa_badge",
    "queue_runs_label",
    "queue_runs_narrow_label",
    "queue_state_label",
    "queue_state_summary_label",
    "queue_status_narrow_label",
    "queue_template_label",
    "recommended_reason",
]
