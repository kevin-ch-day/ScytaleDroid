"""Selected-app state labels and recommendation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


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
    live_build_drift: bool = False,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    scripted_template_ready: bool,
    latest_valid: bool | None,
    latest_invalid_reason: str | None,
    latest_pcap_failure_detail: str | None,
    db_active_sessions: int,
    active_valid_runs: int,
) -> tuple[str, str | None]:
    if bool(live_build_drift):
        return ("refresh", "installed build does not match the newest static plan")
    baseline_missing = max(0, int(baseline_required) - int(baseline_valid_runs))
    interactive_missing = max(0, int(interactive_required) - int(interactive_valid_runs))
    if baseline_missing <= 0 and interactive_missing <= 0 and latest_valid is False:
        detail = (
            str(latest_pcap_failure_detail or "").strip().upper()
            or str(latest_invalid_reason or "").strip().upper()
            or "UNKNOWN"
        )
        return ("review QA", f"latest current-build QA invalid ({detail})")
    if int(active_valid_runs) <= 0 and int(db_active_sessions) > 0:
        return ("restore local evidence", "current-build evidence exists in the DB, but the local evidence pack is missing")
    if baseline_missing > 0:
        suffix = "" if baseline_missing == 1 else "s"
        return ("baseline", f"{baseline_missing} baseline run{suffix} needed")
    if interactive_missing > 0:
        action = "scripted interaction" if scripted_template_ready else "manual interaction"
        suffix = "" if interactive_missing == 1 else "s"
        return (action, f"{interactive_missing} interactive run{suffix} needed")
    return ("—", None)


def selected_app_build_label(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    lineage_state: str = "",
    live_build_drift: bool = False,
) -> str:
    state = str(lineage_state or "").strip()
    if bool(live_build_drift):
        return "drift"
    if int(active_valid_runs) > 0 or int(db_active_sessions) > 0:
        return "current"
    if int(legacy_valid_runs) > 0 or int(db_historical_sessions) > 0:
        return "legacy"
    if state in {"current_build_observed", "current_build_db_only"}:
        return "current"
    if state in {"historical_local_only", "historical_db_only"}:
        return "legacy"
    return "unknown"


def selected_app_build_text(build: str) -> str:
    return {
        "current": "Current build",
        "legacy": "Legacy build",
        "unknown": "Unknown build",
        "drift": "Build drift detected",
    }.get(str(build or "").strip(), "Unknown build")


def selected_app_build_compact_label(build: str) -> str:
    return {
        "current": "cur",
        "legacy": "leg",
        "unknown": "unk",
        "drift": "drift",
    }.get(str(build or "").strip(), str(build or "").strip() or "unk")


def selected_app_evidence_label(
    lineage_state: str,
    *,
    technical_valid_active: int = 0,
    db_active_sessions: int = 0,
    historical_valid_runs_count: int = 0,
    db_historical_sessions: int = 0,
) -> str:
    state = str(lineage_state or "").strip()
    if int(technical_valid_active) > 0 or state == "current_build_observed":
        return "local+db"
    if int(db_active_sessions) > 0 or state == "current_build_db_only":
        return "db-only"
    if int(historical_valid_runs_count) > 0 or state == "historical_local_only":
        return "local-only"
    if int(db_historical_sessions) > 0 or state == "historical_db_only":
        return "db-only"
    if state == "no_evidence_anywhere":
        return "empty"
    return "none"


def selected_app_evidence_text(build: str, evidence: str) -> str:
    build_key = str(build or "").strip()
    evidence_key = str(evidence or "").strip()
    if evidence_key == "local+db":
        return "current-build evidence (local+db)"
    if evidence_key == "db-only":
        if build_key == "legacy":
            return "historical evidence (db-only)"
        return "current-build evidence (db-only)"
    if evidence_key == "local-only":
        return "historical evidence (local-only)"
    if evidence_key in {"empty", "none"}:
        return "no current-build evidence"
    return evidence_key or "no current-build evidence"


def selected_app_evidence_compact_label(evidence: str) -> str:
    return {
        "local+db": "ldb",
        "local-only": "local",
        "db-only": "db",
        "empty": "empty",
        "none": "—",
    }.get(str(evidence or "").strip(), str(evidence or "").strip() or "—")


def selected_app_qa_badge(latest_valid: bool | None) -> str:
    if latest_valid is True:
        return "✓"
    if latest_valid is False:
        return "inv"
    return "—"


def selected_app_qa_badge_from_label(value: str) -> str:
    text = str(value or "").strip()
    if text in {"", "—"}:
        return "—"
    if text == "valid":
        return "✓"
    if text == "valid (L)":
        return "+L"
    if text == "valid (id_mismatch)":
        return "+id"
    if text == "valid (id_mismatch) (L)":
        return "+id+L"
    if text.startswith("invalid"):
        return "inv"
    return text


def selected_app_qa_text(qa_badge: str) -> str:
    badge = str(qa_badge or "").strip()
    if badge == "✓":
        return "QA valid"
    if badge == "inv":
        return "QA needs review"
    if badge in {"", "—"}:
        return "QA unknown"
    return f"QA {badge}"


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
    queue_action_refresh: str,
    queue_action_baseline: str,
    queue_action_manual: str,
    queue_action_scripted: str,
) -> str:
    action_key = queue_action_key_fn(queue_action)
    if action_key == queue_action_review_qa:
        return "review"
    if action_key == queue_action_restore_local:
        return "local pack"
    if action_key == queue_action_refresh:
        return "refresh"
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
    queue_action_refresh: str,
    queue_action_baseline: str,
    queue_action_manual: str,
    queue_action_scripted: str,
) -> str:
    action_key = queue_action_key_fn(queue_action)
    if action_key == queue_action_review_qa:
        return "review"
    if action_key == queue_action_restore_local:
        return "restore/recollect"
    if action_key == queue_action_refresh:
        return "refresh"
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
    queue_action_refresh: str,
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
            lineage_state=lineage_state,
        ),
        evidence=selected_app_evidence_label(
            lineage_state,
            db_active_sessions=db_active_sessions,
            db_historical_sessions=db_historical_sessions,
            historical_valid_runs_count=legacy_valid_runs,
            technical_valid_active=active_valid_runs,
        ),
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
            queue_action_refresh=queue_action_refresh,
            queue_action_baseline=queue_action_baseline,
            queue_action_manual=queue_action_manual,
            queue_action_scripted=queue_action_scripted,
        ),
        action=selected_app_action_label(
            queue_action,
            queue_action_key_fn=queue_action_key_fn,
            queue_action_review_qa=queue_action_review_qa,
            queue_action_restore_local=queue_action_restore_local,
            queue_action_refresh=queue_action_refresh,
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


__all__ = [
    "SelectedAppStateSnapshot",
    "selected_app_action_label",
    "selected_app_build_compact_label",
    "selected_app_build_label",
    "selected_app_build_text",
    "selected_app_evidence_compact_label",
    "selected_app_evidence_label",
    "selected_app_evidence_text",
    "selected_app_need_label",
    "selected_app_qa_badge",
    "selected_app_qa_badge_from_label",
    "selected_app_qa_text",
    "selected_app_queue_action",
    "selected_app_quota_label",
    "selected_app_state_snapshot",
]
