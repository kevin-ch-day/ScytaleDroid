"""Selected-app state helpers for guided dynamic runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class SelectedAppStateSnapshot:
    build: str
    evidence: str
    qa: str
    need: str
    action: str
    quota: str


def selected_app_queue_action(
    *,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    scripted_template_ready: bool,
    latest_valid: bool | None,
    latest_invalid_reason: str | None,
    db_active_sessions: int,
    active_valid_runs: int,
) -> tuple[str, str | None]:
    baseline_missing = max(0, int(baseline_required) - int(baseline_valid_runs))
    interactive_missing = max(0, int(interactive_required) - int(interactive_valid_runs))
    if baseline_missing <= 0 and interactive_missing <= 0 and latest_valid is False:
        detail = str(latest_invalid_reason or "").strip().upper() or "UNKNOWN"
        return ("review QA", f"latest current-build run is invalid ({detail})")
    if int(active_valid_runs) <= 0 and int(db_active_sessions) > 0:
        return ("restore local evidence", "DB knows current-build sessions but the local evidence pack is missing")
    if baseline_missing > 0:
        suffix = "" if baseline_missing == 1 else "s"
        return ("baseline", f"{baseline_missing} baseline run{suffix} needed")
    if interactive_missing > 0:
        action = "scripted interaction" if scripted_template_ready else "manual interaction"
        suffix = "" if interactive_missing == 1 else "s"
        return (action, f"{interactive_missing} interactive run{suffix} needed")
    return ("—", None)


def print_selected_app_queue_action(action: str, reason: str | None, *, status_messages: Any) -> None:
    text = str(action or "").strip()
    if not text or text == "—":
        return
    print(status_messages.status(f"Queue action: {text}", level="info"))
    if str(reason or "").strip():
        print(status_messages.status(f"Reason: {reason}", level="info"))


def selected_app_build_label(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
) -> str:
    if int(active_valid_runs) > 0 or int(db_active_sessions) > 0:
        return "current"
    if int(legacy_valid_runs) > 0 or int(db_historical_sessions) > 0:
        return "legacy"
    return "unknown"


def selected_app_evidence_label(lineage_state: str) -> str:
    state = str(lineage_state or "").strip()
    if state == "current_build_observed":
        return "local+db"
    if state == "current_build_db_only":
        return "db-only"
    if state == "historical_local_only":
        return "local-only"
    if state == "historical_db_only":
        return "db-only"
    if state == "no_evidence_anywhere":
        return "empty"
    return "none"


def selected_app_qa_badge(latest_valid: bool | None) -> str:
    if latest_valid is True:
        return "✓"
    if latest_valid is False:
        return "inv"
    return "—"


def selected_app_need_label(
    *,
    queue_action: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    queue_action_restore_local: str,
    queue_action_baseline: str,
    queue_action_manual: str,
    queue_action_scripted: str,
) -> str:
    action_key = queue_action_key_fn(queue_action)
    if action_key == queue_action_review_qa:
        return "review"
    if action_key == queue_action_restore_local:
        return "local pack"
    if action_key == queue_action_baseline:
        return f"base {int(baseline_valid_runs)}/{int(baseline_required)}"
    if action_key in {queue_action_manual, queue_action_scripted}:
        return f"manual {int(interactive_valid_runs)}/{int(interactive_required)}"
    return "—"


def selected_app_action_label(
    queue_action: str,
    *,
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    queue_action_restore_local: str,
    queue_action_baseline: str,
    queue_action_manual: str,
    queue_action_scripted: str,
) -> str:
    action_key = queue_action_key_fn(queue_action)
    if action_key == queue_action_review_qa:
        return "review"
    if action_key == queue_action_restore_local:
        return "restore/recollect"
    if action_key == queue_action_manual:
        return "manual"
    if action_key == queue_action_scripted:
        return "script"
    if action_key == queue_action_baseline:
        return "base"
    return str(queue_action or "").strip() or "—"


def selected_app_quota_label(
    *,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    extra_valid_runs: int,
) -> str:
    countable = int(baseline_valid_runs) + int(interactive_valid_runs)
    required = int(baseline_required) + int(interactive_required)
    missing = max(0, int(baseline_required) - int(baseline_valid_runs)) + max(
        0, int(interactive_required) - int(interactive_valid_runs)
    )
    if missing <= 0:
        if int(extra_valid_runs) > 0:
            return f"{countable}/{required}+{int(extra_valid_runs)}"
        return f"{countable}/{required}"
    return f"{countable}/{required} n{missing}"


def selected_app_state_snapshot(
    *,
    lineage_state: str,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    latest_valid: bool | None,
    queue_action: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    extra_valid_runs: int,
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    queue_action_restore_local: str,
    queue_action_baseline: str,
    queue_action_manual: str,
    queue_action_scripted: str,
) -> SelectedAppStateSnapshot:
    return SelectedAppStateSnapshot(
        build=selected_app_build_label(
            active_valid_runs=active_valid_runs,
            legacy_valid_runs=legacy_valid_runs,
            db_active_sessions=db_active_sessions,
            db_historical_sessions=db_historical_sessions,
        ),
        evidence=selected_app_evidence_label(lineage_state),
        qa=selected_app_qa_badge(latest_valid),
        need=selected_app_need_label(
            queue_action=queue_action,
            baseline_valid_runs=baseline_valid_runs,
            interactive_valid_runs=interactive_valid_runs,
            baseline_required=baseline_required,
            interactive_required=interactive_required,
            queue_action_key_fn=queue_action_key_fn,
            queue_action_review_qa=queue_action_review_qa,
            queue_action_restore_local=queue_action_restore_local,
            queue_action_baseline=queue_action_baseline,
            queue_action_manual=queue_action_manual,
            queue_action_scripted=queue_action_scripted,
        ),
        action=selected_app_action_label(
            queue_action,
            queue_action_key_fn=queue_action_key_fn,
            queue_action_review_qa=queue_action_review_qa,
            queue_action_restore_local=queue_action_restore_local,
            queue_action_baseline=queue_action_baseline,
            queue_action_manual=queue_action_manual,
            queue_action_scripted=queue_action_scripted,
        ),
        quota=selected_app_quota_label(
            baseline_valid_runs=baseline_valid_runs,
            interactive_valid_runs=interactive_valid_runs,
            baseline_required=baseline_required,
            interactive_required=interactive_required,
            extra_valid_runs=extra_valid_runs,
        ),
    )


def print_selected_app_state_summary(
    *,
    lineage_state: str,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    latest_valid: bool | None,
    queue_action: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    extra_valid_runs: int,
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    queue_action_restore_local: str,
    queue_action_baseline: str,
    queue_action_manual: str,
    queue_action_scripted: str,
    menu_utils: Any,
) -> None:
    snapshot = selected_app_state_snapshot(
        lineage_state=lineage_state,
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=legacy_valid_runs,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        latest_valid=latest_valid,
        queue_action=queue_action,
        baseline_valid_runs=baseline_valid_runs,
        interactive_valid_runs=interactive_valid_runs,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        extra_valid_runs=extra_valid_runs,
        queue_action_key_fn=queue_action_key_fn,
        queue_action_review_qa=queue_action_review_qa,
        queue_action_restore_local=queue_action_restore_local,
        queue_action_baseline=queue_action_baseline,
        queue_action_manual=queue_action_manual,
        queue_action_scripted=queue_action_scripted,
    )
    menu_utils.print_header("App state")
    rows = [
        ["Build", snapshot.build],
        ["Evidence", snapshot.evidence],
        ["QA", snapshot.qa],
        ["Need", snapshot.need],
        ["Action", snapshot.action],
        ["Quota", snapshot.quota],
    ]
    menu_utils.print_table(["Field", "Value"], rows)


__all__ = [
    "SelectedAppStateSnapshot",
    "print_selected_app_queue_action",
    "print_selected_app_state_summary",
    "selected_app_action_label",
    "selected_app_build_label",
    "selected_app_evidence_label",
    "selected_app_need_label",
    "selected_app_qa_badge",
    "selected_app_queue_action",
    "selected_app_quota_label",
    "selected_app_state_snapshot",
]
