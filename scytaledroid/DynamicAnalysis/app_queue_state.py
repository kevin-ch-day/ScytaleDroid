"""State and label helpers for the dynamic app queue."""

from __future__ import annotations

import re
from typing import Any

from scytaledroid.DynamicAnalysis import app_queue_guidance
from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_build_compact_label,
    selected_app_evidence_compact_label,
    selected_app_evidence_label,
    selected_app_qa_badge_from_label,
)
from scytaledroid.DynamicAnalysis.run_qualification import (
    bucket_detail_column_label,
    bucket_evidence_label,
    bucket_quota_label,
    format_quota_progress_compact,
    format_quota_progress_label,
    format_supplemental_column_label,
    format_supplemental_suffix,
    row_baseline_ml_pool_size,
    supplemental_baseline_queue_action,
)
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package


def _supplemental_suffix(*, extra: int = 0, low_signal: int = 0) -> str:
    return format_supplemental_suffix(extra=extra, low_signal=low_signal)


def queue_supplemental_column_label(*, extra: int = 0, low_signal: int = 0) -> str:
    """Compact supplemental evidence label for queue table columns."""
    return format_supplemental_column_label(extra=extra, low_signal=low_signal)


_QUEUE_TABLE_APP_LABEL_OVERRIDES: dict[str, str] = {
    "facebook messenger": "Facebook Msg",
    "x (twitter)": "X",
    "the guardian": "Guardian",
}
_QUEUE_TABLE_QA_DISPLAY_LABELS: dict[str, str] = {
    "valid+L": "valid",
    "valid+id+L": "valid+id",
    "valid+id": "valid+id",
    "inv": "invalid",
}
_QUEUE_TABLE_BUILD_DISPLAY_LABELS: dict[str, str] = {
    "mixed": "current",
    "prior-build": "prior-only",
    "prior-build-db": "prior-only",
    "db-only": "db-only",
    "ready": "none yet",
    "stale": "drift",
}


def queue_table_app_label(display_name: object) -> str:
    """Compact app label for the queue table (full name remains elsewhere)."""
    raw = str(display_name or "").strip()
    if not raw:
        return "—"
    override = _QUEUE_TABLE_APP_LABEL_OVERRIDES.get(raw.casefold())
    if override:
        return override
    if re.fullmatch(r"x\s*\(twitter\)", raw, flags=re.IGNORECASE):
        return "X"
    messenger_suffix = " messenger"
    if raw.casefold().endswith(messenger_suffix):
        return f"{raw[: -len(messenger_suffix)]} Msg"
    if raw.startswith("The ") and len(raw) > 4:
        return raw[4:].strip()
    return raw


def recommended_reason(row: Any) -> str:
    return app_queue_guidance.recommended_reason(row)


def lineage_rank(lineage_state: str) -> int:
    return app_queue_guidance.lineage_rank(lineage_state)


def capture_candidate_priority(row: Any) -> tuple[int, int, int, int, str]:
    return app_queue_guidance.capture_candidate_priority(row)


def select_capture_candidates(rows: list[Any], *, limit: int = 5) -> list[Any]:
    return app_queue_guidance.select_capture_candidates(rows, limit=limit)


def build_drift_app_summaries(
    row_models: list[Any],
    *,
    queue_status_label_fn,
    baseline_label_fn,
    interactive_label_fn,
) -> list[dict[str, str]]:
    return app_queue_guidance.build_drift_app_summaries(
        row_models,
        queue_status_label_fn=queue_status_label_fn,
        baseline_label_fn=baseline_label_fn,
        interactive_label_fn=interactive_label_fn,
    )


def format_capture_plan_line(rows: list[Any], *, limit: int = 3) -> str:
    return app_queue_guidance.format_capture_plan_line(
        rows,
        action_label_fn=display_action_label,
        limit=limit,
    )


def compact_warning_line(row_models: list[Any]) -> str:
    return app_queue_guidance.compact_warning_line(row_models)


def compact_note_line(row_models: list[Any]) -> str:
    return app_queue_guidance.compact_note_line(row_models)


def attention_items(row_models: list[Any]) -> list[str]:
    return app_queue_guidance.attention_items(row_models)


def archive_blocker_summary(row_models: list[Any]) -> str:
    return app_queue_guidance.archive_blocker_summary(
        row_models,
        queue_state_label_fn=queue_state_label,
    )


def queue_remaining_summary(row_models: list[Any]) -> str:
    return app_queue_guidance.queue_remaining_summary(
        row_models,
        queue_state_label_fn=queue_state_label,
    )


def queue_state_label(row: Any) -> str:
    if bool(getattr(row, "live_build_drift", False)):
        return "refresh"
    lineage_state = str(getattr(row, "lineage_state", "") or "")
    if lineage_state == "current_build_db_only":
        return "restore"
    if lineage_state in {"historical_local_only", "historical_db_only"}:
        if int(getattr(row, "need_baseline", 0) or 0) > 0:
            return "baseline"
        return "legacy"
    if str(getattr(row, "qa_label", "") or "").startswith("invalid"):
        return "review"
    if int(getattr(row, "need_baseline", 0) or 0) > 0:
        return "baseline"
    if int(getattr(row, "need_interactive", 0) or 0) > 0:
        return "manual"
    if supplemental_baseline_queue_action(getattr(row, "next_label", None)):
        return "complete"
    if str(getattr(row, "next_label", "") or "") == "—":
        return "complete"
    if str(getattr(row, "prep_label", "") or "") == "mixed":
        return "review"
    return "blocked"


def queue_status_label(row: Any) -> str:
    return {
        "complete": "complete",
        "review": "review",
        "baseline": "baseline",
        "manual": "interactive",
        "refresh": "refresh",
        "restore": "restore",
        "legacy": "baseline",
        "blocked": "blocked",
    }.get(queue_state_label(row), queue_state_label(row))


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


def queue_quota_gap_label(row: Any) -> str:
    """Compact quota shortfall for archive math (e.g. 3B, 2I, 3B 2I)."""
    parts: list[str] = []
    need_baseline = int(getattr(row, "need_baseline", 0) or 0)
    need_interactive = int(getattr(row, "need_interactive", 0) or 0)
    if need_baseline > 0:
        parts.append(f"{need_baseline}B")
    if need_interactive > 0:
        parts.append(f"{need_interactive}I")
    return " ".join(parts) if parts else "—"


def queue_table_qa_label(row: Any) -> str:
    value = compact_qa_label(str(getattr(row, "qa_label", "") or "—"))
    return _QUEUE_TABLE_QA_DISPLAY_LABELS.get(value, value)


def queue_table_next_label(row: Any, *, narrow: bool = False) -> str:
    action = display_action_label(row)
    if action == "—":
        return "—"
    if action == "ml_pool":
        return "ML pool" if not narrow else "ml"
    if narrow:
        return queue_action_narrow_label(row)
    return action


def queue_table_build_label(row: Any) -> str:
    value = compact_prep_label(str(getattr(row, "prep_label", "") or "—"))
    return _QUEUE_TABLE_BUILD_DISPLAY_LABELS.get(value, value)


def queue_idle_baseline_label(row: Any, *, baseline_required: int) -> str:
    return bucket_quota_label(
        countable=int(row.baseline_countable),
        required=int(baseline_required),
    )


def queue_non_idle_baseline_label(row: Any) -> str:
    return str(int(getattr(row, "baseline_not_idle_supplemental", 0) or 0))


def queue_retained_prior_build_label(row: Any) -> str:
    runs = int(getattr(row, "historical_valid_runs_count", 0) or 0)
    builds = int(getattr(row, "historical_build_count", 0) or 0)
    if runs <= 0:
        return "0"
    if builds > 0:
        return f"{runs} ({builds}b)"
    return str(runs)


def queue_interactive_count_raw(row: Any) -> int:
    value = getattr(row, "interactive_count_raw", None)
    if value is not None:
        return max(0, int(value))
    return (
        int(getattr(row, "interactive_countable", 0) or 0)
        + int(getattr(row, "interactive_extra", 0) or 0)
        + int(getattr(row, "interactive_low_signal_supplemental", 0) or 0)
    )


def queue_interactive_display_state(row: Any) -> str:
    explicit = str(getattr(row, "interactive_display_state", "") or "").strip()
    if explicit:
        return explicit
    if int(getattr(row, "need_baseline", 0) or 0) > 0:
        return "held_by_strict_idle"
    return "unlocked"


def queue_interactive_hold_reason(row: Any) -> str:
    explicit = str(getattr(row, "interactive_hold_reason", "") or "").strip()
    if explicit:
        return explicit
    if int(getattr(row, "need_baseline", 0) or 0) > 0:
        return "strict_idle_incomplete"
    return "none"


def _held_by_strict_idle(label: str, row: Any) -> str:
    text = str(label or "").strip() or "0/0"
    if queue_interactive_display_state(row) == "held_by_strict_idle":
        return f"{text} held"
    return text


def queue_interactive_total_label(row: Any, *, interactive_required: int) -> str:
    total = queue_interactive_count_raw(row)
    label = f"{total}/{int(interactive_required)}"
    return _held_by_strict_idle(label, row)


def queue_row_is_next_recommended(row: Any, next_row: Any | None) -> bool:
    if next_row is None:
        return False
    row_pkg = str(getattr(row, "package_name", "") or "").strip().lower()
    next_pkg = str(getattr(next_row, "package_name", "") or "").strip().lower()
    if row_pkg and next_pkg and row_pkg == next_pkg:
        return True
    row_name = str(getattr(row, "display_name", "") or "").strip().casefold()
    next_name = str(getattr(next_row, "display_name", "") or "").strip().casefold()
    return bool(row_name and next_name and row_name == next_name)


def queue_table_index_label(row: Any, *, next_row: Any | None = None) -> str:
    idx = str((getattr(row, "full_row", None) or ["—"])[0])
    if queue_row_is_next_recommended(row, next_row):
        return f">{idx}"
    return idx


def queue_runs_label(row: Any, *, total_required: int) -> str:
    countable = int(row.baseline_countable) + int(row.interactive_countable)
    extra = (
        int(row.baseline_extra)
        + int(getattr(row, "baseline_low_signal_supplemental", 0) or 0)
        + int(getattr(row, "baseline_not_idle_supplemental", 0) or 0)
        + int(row.interactive_extra)
        + int(getattr(row, "interactive_low_signal_supplemental", 0) or 0)
    )
    missing = int(row.need_baseline) + int(row.need_interactive)
    if missing <= 0:
        if extra > 0:
            return f"{countable}/{int(total_required)} +{extra}"
        return f"{countable}/{int(total_required)}"
    return f"{countable}/{int(total_required)} need {missing}"


def queue_baseline_evidence_label(row: Any, *, baseline_required: int) -> str:
    return bucket_evidence_label(
        countable=int(row.baseline_countable),
        extra=int(row.baseline_extra),
        low_signal=int(getattr(row, "baseline_low_signal_supplemental", 0) or 0),
        non_idle=int(getattr(row, "baseline_not_idle_supplemental", 0) or 0),
        required=int(baseline_required),
    )


def queue_interactive_evidence_label(row: Any, *, interactive_required: int) -> str:
    if queue_interactive_display_state(row) == "held_by_strict_idle":
        return f"{queue_interactive_count_raw(row)}/{int(interactive_required)} held"
    label = bucket_evidence_label(
        countable=int(row.interactive_countable),
        extra=int(row.interactive_extra),
        low_signal=int(getattr(row, "interactive_low_signal_supplemental", 0) or 0),
        required=int(interactive_required),
    )
    return _held_by_strict_idle(label, row)


def queue_baseline_runs_label(row: Any, *, baseline_required: int) -> str:
    return queue_baseline_evidence_label(row, baseline_required=baseline_required)


def queue_baseline_quota_label(row: Any, *, baseline_required: int) -> str:
    return bucket_quota_label(
        countable=int(row.baseline_countable),
        required=int(baseline_required),
    )


def queue_baseline_detail_label(row: Any, *, baseline_required: int) -> str:
    non_idle = int(getattr(row, "baseline_not_idle_supplemental", 0) or 0)
    return bucket_detail_column_label(
        countable=int(row.baseline_countable),
        extra=int(row.baseline_extra),
        low_signal=int(getattr(row, "baseline_low_signal_supplemental", 0) or 0),
        non_idle=non_idle,
        required=int(baseline_required),
    )


def queue_baseline_supplemental_label(row: Any, *, baseline_required: int) -> str:
    return queue_baseline_detail_label(row, baseline_required=baseline_required)


def queue_baseline_progress_label(row: Any, *, baseline_required: int, compact: bool = False) -> str:
    formatter = format_quota_progress_compact if compact else format_quota_progress_label
    non_idle = int(getattr(row, "baseline_not_idle_supplemental", 0) or 0)
    return formatter(
        countable=int(row.baseline_countable),
        extra=int(row.baseline_extra),
        low_signal=int(getattr(row, "baseline_low_signal_supplemental", 0) or 0),
        non_idle=non_idle,
        required=int(baseline_required),
    )


def queue_interactive_progress_label(row: Any, *, interactive_required: int, compact: bool = False) -> str:
    if queue_interactive_display_state(row) == "held_by_strict_idle":
        return f"{queue_interactive_count_raw(row)}/{int(interactive_required)} held"
    formatter = format_quota_progress_compact if compact else format_quota_progress_label
    label = formatter(
        countable=int(row.interactive_countable),
        extra=int(row.interactive_extra),
        low_signal=int(getattr(row, "interactive_low_signal_supplemental", 0) or 0),
        required=int(interactive_required),
    )
    return _held_by_strict_idle(label, row)


def queue_interactive_runs_label(row: Any, *, interactive_required: int) -> str:
    return queue_interactive_evidence_label(row, interactive_required=interactive_required)


def queue_interactive_quota_label(row: Any, *, interactive_required: int) -> str:
    return bucket_quota_label(
        countable=int(row.interactive_countable),
        required=int(interactive_required),
    )


def queue_interactive_detail_label(row: Any, *, interactive_required: int) -> str:
    if int(getattr(row, "need_baseline", 0) or 0) > 0:
        return "—"
    return bucket_detail_column_label(
        countable=int(row.interactive_countable),
        extra=int(row.interactive_extra),
        low_signal=int(getattr(row, "interactive_low_signal_supplemental", 0) or 0),
        required=int(interactive_required),
    )


def queue_interactive_supplemental_label(row: Any, *, interactive_required: int) -> str:
    return queue_interactive_detail_label(row, interactive_required=interactive_required)


def queue_target_label(row: Any) -> str:
    if bool(getattr(row, "live_build_drift", False)):
        return "refresh"
    if str(getattr(row, "lineage_state", "") or "") == "no_evidence_anywhere":
        return "unknown"
    return "current"


def queue_build_label(row: Any) -> str:
    return queue_target_label(row)


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
    if template_id in {"news_reader_basic_v1", "news_reader_behavior_v2"}:
        return "news"
    if template_id in {
        "social_feed_basic_v2",
        "facebook_basic_v2",
        "facebook_behavior_v3",
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
        "whatsapp_text_behavior_v2",
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
        return "baseline"
    if action == "ml_pool":
        return "ml_pool"
    if action == "interactive":
        return "interactive"
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
        "complete": "complete",
        "review": "review",
        "baseline": "baseline",
        "manual": "interactive",
        "refresh": "refresh",
        "restore": "restore",
        "legacy": "baseline",
        "blocked": "block",
    }.get(queue_state_label(row), queue_status_label(row))


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
        "interactive": "interactive",
        "review": "rev",
        "refresh": "ref",
        "restore": "rest",
    }.get(queue_action_label(row), queue_action_label(row))


def display_action_label(row: Any) -> str:
    """Map queue workflow state to the operator-facing next-move label."""
    state = queue_state_label(row)
    if state == "complete":
        if supplemental_baseline_queue_action(getattr(row, "next_label", None)):
            return "ml_pool"
        return "—"
    if state == "manual":
        return "interactive"
    if state == "legacy":
        return "baseline"
    return state


def display_next_line_action_label(row: Any) -> str:
    action = display_action_label(row)
    if action == "interactive":
        return "interactive"
    if action == "review":
        return "review QA"
    if action == "restore":
        return "restore/recollect"
    if action == "ml_pool":
        return "supplemental baseline"
    return action


def next_recommendation_priority(row: Any) -> tuple[int, int, str]:
    return app_queue_guidance.next_recommendation_priority(
        row,
        action_label_fn=display_action_label,
    )


def next_recommended_row(rows: list[Any]) -> Any | None:
    return app_queue_guidance.next_recommended_row(
        rows,
        action_label_fn=display_action_label,
    )


def group_queue_sections(row_models: list[Any]) -> list[tuple[str, list[Any]]]:
    needs_refresh: list[Any] = []
    ready_manual: list[Any] = []
    needs_baseline: list[Any] = []
    ml_training_ready: list[Any] = []
    complete_or_extra: list[Any] = []
    other_blocked: list[Any] = []
    for row in row_models:
        if row.live_build_drift:
            needs_refresh.append(row)
        elif row.need_baseline > 0:
            needs_baseline.append(row)
        elif row.need_interactive > 0 and row.next_label in {"manual interaction", "scripted interaction"}:
            ready_manual.append(row)
        elif supplemental_baseline_queue_action(getattr(row, "next_label", None)):
            ml_training_ready.append(row)
        elif str(getattr(row, "next_label", "") or "") == "—":
            complete_or_extra.append(row)
        else:
            other_blocked.append(row)
    sections: list[tuple[str, list[Any]]] = []
    sections.append(("Needs static refresh", needs_refresh))
    sections.append(("Ready for interactive capture", ready_manual))
    sections.append(("Needs baseline capture", needs_baseline))
    sections.append(("ML training pool (optional)", ml_training_ready))
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
            return f"{count_i}/{required_i}{format_supplemental_suffix(extra=extra_i)}"
        return f"{count_i}/{required_i} complete"
    return f"{count_i}/{required_i} need {missing_i}"


def manual_progress_label(row: Any, *, interactive_required: int) -> str:
    if queue_interactive_display_state(row) == "held_by_strict_idle":
        return f"{queue_interactive_count_raw(row)}/{int(interactive_required)} held"
    label = main_progress_label(
        row.interactive_countable,
        row.interactive_extra,
        required=interactive_required,
        missing=row.need_interactive,
    )
    return _held_by_strict_idle(label, row)


def main_action_label(value: str) -> str:
    text = str(value or "").strip()
    if text in {"manual interaction", "scripted interaction", "manual", "scripted"}:
        return "interactive"
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
    if text in {"manual interaction", "scripted interaction", "manual", "scripted"}:
        return "interactive"
    return str(value or "").strip() or "—"


def compact_prep_label(value: str) -> str:
    text = str(value or "").strip().lower()
    mapping = {
        "current": "current",
        "mixed": "mixed",
        "legacy": "prior-build",
        "db-only": "db-only",
        "hist-db": "prior-build-db",
        "ready": "ready",
        "stale": "drift",
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
    "build_drift_app_summaries",
    "capture_candidate_priority",
    "format_capture_plan_line",
    "lineage_rank",
    "main_action_label",
    "main_progress_label",
    "manual_progress_label",
    "next_recommendation_priority",
    "next_recommended_row",
    "queue_action_label",
    "queue_action_narrow_label",
    "queue_build_label",
    "queue_evidence_label",
    "queue_quota_gap_label",
    "queue_table_build_label",
    "queue_table_index_label",
    "queue_table_next_label",
    "queue_table_qa_label",
    "queue_row_is_next_recommended",
    "queue_need_narrow_label",
    "queue_qa_badge",
    "queue_remaining_summary",
    "queue_retained_prior_build_label",
    "queue_runs_label",
    "queue_runs_narrow_label",
    "queue_baseline_detail_label",
    "queue_baseline_evidence_label",
    "queue_interactive_detail_label",
    "queue_interactive_evidence_label",
    "queue_baseline_progress_label",
    "queue_baseline_supplemental_label",
    "queue_interactive_progress_label",
    "queue_interactive_quota_label",
    "queue_interactive_supplemental_label",
    "queue_table_app_label",
    "queue_state_label",
    "queue_status_label",
    "queue_state_summary_label",
    "queue_status_narrow_label",
    "queue_target_label",
    "queue_template_label",
    "recommended_reason",
    "select_capture_candidates",
]
