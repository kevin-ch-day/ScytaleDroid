"""Canonical dynamic target state helpers.

This layer separates:
- study/build-scoped evidence status
- live device alignment/drift
- capture readiness
- publication/QA readiness

It is intentionally read-only and derived from existing state/read-model inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DynamicStudyIdentity:
    package_name: str
    version_code: str | None = None
    base_apk_sha256: str | None = None
    version_name: str | None = None
    artifact_set_hash: str | None = None
    static_run_id: str | None = None


@dataclass(frozen=True)
class DynamicHistoricalEvidenceSummary:
    valid_runs: int
    build_count: int
    db_sessions: int


@dataclass(frozen=True)
class DynamicTargetState:
    package_name: str
    study_status: str
    live_device_status: str
    capture_status: str
    publication_status: str
    study_identity: DynamicStudyIdentity
    historical: DynamicHistoricalEvidenceSummary
    baseline_countable: int
    baseline_required: int
    interactive_countable: int
    interactive_required: int
    quota_counted: int
    quota_required: int
    quota_met: bool
    active_valid_runs: int
    latest_valid: bool | None
    latest_invalid_reason: str | None
    latest_pcap_failure_detail: str | None
    has_identity_mismatch: bool = False


def _study_status(
    *,
    active_valid_runs: int,
    quota_met: bool,
    latest_valid: bool | None,
    historical_valid_runs: int,
    db_historical_sessions: int,
) -> str:
    if active_valid_runs <= 0:
        if historical_valid_runs > 0 or db_historical_sessions > 0:
            return "historical_only"
        return "not_started"
    if latest_valid is False:
        return "qa_review"
    if quota_met:
        return "complete"
    return "in_progress"


def _live_device_status(*, live_build_drift: bool | None) -> str:
    if live_build_drift is True:
        return "drifted"
    if live_build_drift is False:
        return "aligned"
    return "unknown"


def _capture_status(
    *,
    live_device_status: str,
    study_status: str,
    study_identity_available: bool | None,
    capture_device_available: bool | None,
) -> str:
    if capture_device_available is False:
        return "blocked_no_device"
    if live_device_status == "drifted":
        return "blocked_refresh_required"
    if study_identity_available is False:
        return "blocked_missing_static"
    if study_status == "qa_review":
        return "blocked_qa_review"
    return "allowed"


def _publication_status(
    *,
    study_status: str,
    live_device_status: str,
) -> str:
    if study_status == "complete":
        return "historical_candidate" if live_device_status == "drifted" else "ready_for_build"
    if study_status == "qa_review":
        return "historical_candidate" if live_device_status == "drifted" else "ready_after_qa"
    if study_status == "historical_only":
        return "historical_candidate"
    return "not_ready"


def derive_dynamic_target_state(
    *,
    package_name: str,
    state: Any,
    latest_recent: Any | None = None,
    db_active_sessions: int = 0,
    db_historical_sessions: int = 0,
    has_identity_mismatch: bool = False,
    live_build_drift: bool | None = None,
    study_identity_available: bool | None = None,
    capture_device_available: bool | None = None,
    version_name: str | None = None,
    artifact_set_hash: str | None = None,
    static_run_id: str | None = None,
) -> DynamicTargetState:
    counts = getattr(state, "counts")
    baseline_countable = int(getattr(counts, "baseline_valid_runs", 0) or 0)
    interactive_countable = int(getattr(counts, "interactive_valid_runs", 0) or 0)
    baseline_required = int(getattr(state, "baseline_required", 0) or 0)
    interactive_required = int(getattr(state, "interactive_required", 0) or 0)
    active_valid_runs = baseline_countable + interactive_countable
    quota_required = baseline_required + interactive_required
    quota_counted = active_valid_runs
    quota_met = bool(getattr(counts, "quota_met", False))
    historical_valid_runs = int(getattr(state, "historical_valid_runs", 0) or 0)
    historical_build_count = int(getattr(state, "historical_build_count", 0) or 0)

    latest = latest_recent or (getattr(state, "recent_runs", ()) or [None])[0]
    latest_valid = getattr(latest, "valid", None)
    latest_invalid_reason = str(getattr(latest, "invalid_reason_code", "") or "").strip() or None
    latest_pcap_failure_detail = str(getattr(latest, "pcap_failure_detail", "") or "").strip() or None

    version_code = str(getattr(state, "active_version_code", "") or "").strip() or None
    base_sha = str(getattr(state, "active_base_sha", "") or "").strip().lower() or None
    if study_identity_available is None:
        study_identity_available = None if not (version_code or base_sha) else True

    study_status = _study_status(
        active_valid_runs=active_valid_runs,
        quota_met=quota_met,
        latest_valid=latest_valid,
        historical_valid_runs=historical_valid_runs,
        db_historical_sessions=int(db_historical_sessions),
    )
    live_status = _live_device_status(live_build_drift=live_build_drift)
    capture_status = _capture_status(
        live_device_status=live_status,
        study_status=study_status,
        study_identity_available=study_identity_available,
        capture_device_available=capture_device_available,
    )
    publication_status = _publication_status(
        study_status=study_status,
        live_device_status=live_status,
    )

    return DynamicTargetState(
        package_name=str(package_name or "").strip(),
        study_status=study_status,
        live_device_status=live_status,
        capture_status=capture_status,
        publication_status=publication_status,
        study_identity=DynamicStudyIdentity(
            package_name=str(package_name or "").strip(),
            version_code=version_code,
            base_apk_sha256=base_sha,
            version_name=str(version_name or "").strip() or None,
            artifact_set_hash=str(artifact_set_hash or "").strip().lower() or None,
            static_run_id=str(static_run_id or "").strip() or None,
        ),
        historical=DynamicHistoricalEvidenceSummary(
            valid_runs=historical_valid_runs,
            build_count=historical_build_count,
            db_sessions=int(db_historical_sessions),
        ),
        baseline_countable=baseline_countable,
        baseline_required=baseline_required,
        interactive_countable=interactive_countable,
        interactive_required=interactive_required,
        quota_counted=quota_counted,
        quota_required=quota_required,
        quota_met=quota_met,
        active_valid_runs=active_valid_runs,
        latest_valid=latest_valid,
        latest_invalid_reason=latest_invalid_reason,
        latest_pcap_failure_detail=latest_pcap_failure_detail,
        has_identity_mismatch=bool(has_identity_mismatch),
    )


__all__ = [
    "DynamicHistoricalEvidenceSummary",
    "DynamicStudyIdentity",
    "DynamicTargetState",
    "derive_dynamic_target_state",
]
