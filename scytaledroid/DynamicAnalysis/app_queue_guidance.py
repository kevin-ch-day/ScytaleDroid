"""Summary and guidance helpers for the dynamic app queue."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scytaledroid.DynamicAnalysis.run_qualification import (
    row_baseline_ml_pool_size,
    supplemental_baseline_queue_action,
)


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
    baseline_pool = row_baseline_ml_pool_size(row)
    if baseline_pool > 0:
        return f"quota complete; ML training pool has {baseline_pool} supplemental baseline(s)"
    if supplemental_baseline_queue_action(getattr(row, "next_label", None)):
        return "quota complete; supplemental baselines improve ML training and pattern averages"
    extra_total = (
        int(row.baseline_extra)
        + int(getattr(row, "baseline_low_signal_supplemental", 0) or 0)
        + int(row.interactive_extra)
        + int(getattr(row, "interactive_low_signal_supplemental", 0) or 0)
    )
    if extra_total > 0:
        return f"quota complete, {extra_total} extra run(s) retained"
    return "quota state up to date"


def lineage_rank(lineage_state: str) -> int:
    order = {
        "current_build_observed": 0,
        "current_build_db_only": 1,
        "historical_local_only": 2,
        "historical_db_only": 3,
        "no_evidence_anywhere": 4,
    }
    return order.get(str(lineage_state or ""), 9)


def capture_candidate_priority(row: Any) -> tuple[int, int, int, int, str]:
    state = str(getattr(row, "lineage_state", "") or "")
    need_baseline = int(getattr(row, "need_baseline", 0) or 0)
    need_interactive = int(getattr(row, "need_interactive", 0) or 0)
    if need_baseline <= 0 and need_interactive > 0:
        phase_rank = 0
        remaining = need_interactive
        scope_rank = lineage_rank(state)
    elif need_baseline > 0:
        phase_rank = 1
        remaining = need_baseline
        scope_rank = {
            "no_evidence_anywhere": 0,
            "historical_local_only": 1,
            "historical_db_only": 2,
            "current_build_observed": 3,
            "current_build_db_only": 4,
        }.get(state, 9)
    else:
        phase_rank = 9
        remaining = 99
        scope_rank = 9
    current_progress = -(
        int(getattr(row, "baseline_countable", 0) or 0)
        + int(getattr(row, "interactive_countable", 0) or 0)
    )
    display_name = str(getattr(row, "display_name", "") or "").strip().lower()
    return (phase_rank, scope_rank, remaining, current_progress, display_name)


def select_capture_candidates(rows: list[Any], *, limit: int = 5) -> list[Any]:
    filtered = [
        row
        for row in rows
        if not getattr(row, "live_build_drift", False)
        and (
            int(getattr(row, "need_baseline", 0) or 0) > 0
            or int(getattr(row, "need_interactive", 0) or 0) > 0
        )
    ]
    if not filtered:
        return []
    ranked = sorted(filtered, key=capture_candidate_priority)
    return ranked[: max(1, int(limit))]


def build_drift_app_summaries(
    row_models: list[Any],
    *,
    queue_status_label_fn,
    baseline_label_fn,
    interactive_label_fn,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in row_models:
        if not getattr(row, "live_build_drift", False):
            continue
        lineage_state = str(getattr(row, "lineage_state", "") or "")
        if lineage_state == "current_build_observed":
            evidence_scope = "current-build evidence exists, but it is no longer live-current after device drift"
        elif lineage_state == "current_build_db_only":
            evidence_scope = "DB-known current-build evidence exists, but live device drift blocks new current-build claims"
        else:
            evidence_scope = "older build evidence remains historically valid, but not live-current"
        rows.append(
            {
                "package_name": str(getattr(row, "package_name", "") or "").strip(),
                "app": str(getattr(row, "display_name", "") or "").strip(),
                "status": str(queue_status_label_fn(row) or "").strip(),
                "baseline": str(baseline_label_fn(row) or "").strip(),
                "interactive": str(interactive_label_fn(row) or "").strip(),
                "installed_build": str(getattr(row, "live_observed_version_code", "") or "").strip() or "unknown",
                "static_plan_build": str(getattr(row, "live_expected_version_code", "") or "").strip() or "unknown",
                "static_plan_version_name": str(getattr(row, "live_expected_version_name", "") or "").strip() or "unknown",
                "static_run_id": str(getattr(row, "live_static_run_id", "") or "").strip() or "unknown",
                "lineage_state": lineage_state,
                "evidence_scope": evidence_scope,
                "recommendation": "refresh inventory/harvest/static before new live-current capture",
            }
        )
    return sorted(rows, key=lambda item: (item["app"].lower(), item["package_name"]))


def format_capture_plan_line(
    rows: list[Any],
    *,
    action_label_fn: Callable[[Any], str],
    limit: int = 3,
) -> str:
    candidates = select_capture_candidates(rows, limit=limit)
    if not candidates:
        return ""
    parts: list[str] = []
    for index, row in enumerate(candidates, start=1):
        action = action_label_fn(row)
        parts.append(f"{index}. {getattr(row, 'display_name', '?')} ({action})")
    return " | ".join(parts)


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
    mismatch_rows = [
        row.display_name
        for row in row_models
        if "id_mismatch" in str(row.qa_label)
        and row.lineage_state in {"current_build_observed", "current_build_db_only"}
    ]
    db_only_current_rows = [
        row.display_name
        for row in row_models
        if row.lineage_state == "current_build_db_only"
    ]

    if mismatch_rows:
        issues.append(
            _format_issue(
                mismatch_rows,
                singular_suffix="identity mismatch",
                plural_label="identity mismatches",
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


def compact_note_line(row_models: list[Any]) -> str:
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
    legacy_mismatch_rows = [
        row.display_name
        for row in row_models
        if "id_mismatch" in str(row.qa_label)
        and row.lineage_state in {"historical_local_only", "historical_db_only"}
    ]
    historical_rows = [
        row.display_name
        for row in row_models
        if row.lineage_state in {"historical_local_only", "historical_db_only"}
    ]
    if mixed_rows:
        issues.append(
            _format_issue(
                mixed_rows,
                singular_suffix="mixed current/legacy evidence",
                plural_label="mixed current/legacy evidence states",
            )
        )
    if legacy_mismatch_rows:
        issues.append(
            _format_issue(
                legacy_mismatch_rows,
                singular_suffix="legacy identity note",
                plural_label="legacy identity notes",
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
    if not issues:
        return ""
    return " | ".join(issues[:4]) + ". Press D."


def attention_items(
    row_models: list[Any],
) -> list[str]:
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


def archive_blocker_summary(
    row_models: list[Any],
    *,
    queue_state_label_fn: Callable[[Any], str],
) -> str:
    if not row_models:
        return ""
    review_count = sum(1 for row in row_models if queue_state_label_fn(row) == "review")
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


def queue_remaining_summary(
    row_models: list[Any],
    *,
    queue_state_label_fn: Callable[[Any], str],
) -> str:
    if not row_models:
        return ""
    review_count = sum(1 for row in row_models if queue_state_label_fn(row) == "review")
    refresh_count = sum(1 for row in row_models if row.live_build_drift)
    baseline_count = sum(1 for row in row_models if row.need_baseline > 0)
    interactive_count = sum(1 for row in row_models if row.need_baseline <= 0 and row.need_interactive > 0)
    parts: list[str] = []
    if review_count > 0:
        parts.append(f"{review_count} review")
    if refresh_count > 0:
        parts.append(f"{refresh_count} refresh")
    if baseline_count > 0:
        parts.append(f"{baseline_count} baseline gap{'s' if baseline_count != 1 else ''}")
    if interactive_count > 0:
        parts.append(f"{interactive_count} interactive gap{'s' if interactive_count != 1 else ''}")
    return " | ".join(parts)


def next_recommendation_priority(
    row: Any,
    *,
    action_label_fn: Callable[[Any], str],
) -> tuple[int, int, str]:
    action = action_label_fn(row)
    lineage_state = str(row.lineage_state or "")
    if action == "review":
        return (0, 0, row.display_name)
    if action == "refresh":
        return (1, 0, row.display_name)
    if action == "restore":
        return (2, 0, row.display_name)
    if action == "interactive":
        return (3, 0, row.display_name)
    if action == "baseline":
        if lineage_state == "no_evidence_anywhere":
            return (4, 0, row.display_name)
        if lineage_state == "historical_local_only":
            return (5, 0, row.display_name)
        if lineage_state == "historical_db_only":
            return (6, 0, row.display_name)
        return (7, 0, row.display_name)
    if action == "ml_pool":
        return (8, -row_baseline_ml_pool_size(row), row.display_name)
    return (99, 0, row.display_name)


def next_recommended_row(
    rows: list[Any],
    *,
    action_label_fn: Callable[[Any], str],
) -> Any | None:
    if not rows:
        return None
    review_rows = [row for row in rows if action_label_fn(row) == "review"]
    if review_rows:
        return min(review_rows, key=lambda row: next_recommendation_priority(row, action_label_fn=action_label_fn))
    capture_ready = select_capture_candidates(rows, limit=1)
    if capture_ready:
        return capture_ready[0]
    candidates = [row for row in rows if action_label_fn(row) != "—"]
    if not candidates:
        return None
    return min(candidates, key=lambda row: next_recommendation_priority(row, action_label_fn=action_label_fn))


__all__ = [
    "archive_blocker_summary",
    "attention_items",
    "build_drift_app_summaries",
    "capture_candidate_priority",
    "compact_note_line",
    "compact_warning_line",
    "format_capture_plan_line",
    "lineage_rank",
    "next_recommendation_priority",
    "next_recommended_row",
    "queue_remaining_summary",
    "recommended_reason",
    "select_capture_candidates",
]
