"""Device pilot cohort: a protocol object, not a capture runner.

Defines the research pass's device pilot as a cohort of 24 controlled sessions
over at least three days, one source-owned non-root device path, three
controlled states, per-session partition labels from the held-out calibration
allocator, and explicit outcome states. Nothing here touches a phone, runs a
capture or writes into an evidence pack; the guided queue consults
``count_dataset_tier_captures`` so that only dataset-tier captures count.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from typing import Any

from scytaledroid.DynamicAnalysis.ml.heldout_calibration import Session, allocate_sessions

CONTRACT = "device_pilot_cohort_v1"
STATES = ("strict_idle", "qfg", "scripted_interactive")
OUTCOMES = ("executed_send", "no_send_control", "unreached", "capture_loss", "false_attribution")
PLANNED = "planned"
PARTITIONS = ("fit", "calibrate", "test")
REQUIRED_SESSIONS = 24
MIN_DAYS = 3
SESSIONS_PER_STATE = REQUIRED_SESSIONS // len(STATES)
ROOT_ONLY_PREFIXES = ("/data/data/", "/data/user/", "/data/system/", "/system/", "/root/", "/vendor/")
DATASET_TIER = "dataset"


@dataclass(frozen=True)
class PilotSession:
    session_id: str
    day: str
    state: str
    partition_label: str
    outcome: str = PLANNED
    capture_run_id: str | None = None

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise ValueError(f"unsupported state: {self.state}")
        if self.partition_label not in PARTITIONS:
            raise ValueError(f"unsupported partition label: {self.partition_label}")
        if self.outcome != PLANNED and self.outcome not in OUTCOMES:
            raise ValueError(f"unsupported outcome: {self.outcome}")
        date.fromisoformat(self.day)


@dataclass(frozen=True)
class CohortDefinition:
    cohort_id: str
    package_name: str
    source_owned_path: str
    seed: str
    sessions: tuple[PilotSession, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": CONTRACT,
            "cohort_id": self.cohort_id,
            "package_name": self.package_name,
            "source_owned_path": self.source_owned_path,
            "seed": self.seed,
            "sessions": [
                {
                    "session_id": s.session_id, "day": s.day, "state": s.state,
                    "partition_label": s.partition_label, "outcome": s.outcome,
                    "capture_run_id": s.capture_run_id,
                }
                for s in self.sessions
            ],
        }


def non_root_path_errors(path: str) -> list[str]:
    """A source-owned path the pilot can read without root."""
    errors = []
    if not path or not path.startswith("/"):
        errors.append("source_owned_path must be an absolute device path")
        return errors
    if any(path.startswith(prefix) for prefix in ROOT_ONLY_PREFIXES):
        errors.append("source_owned_path lies under a root-only prefix")
    if ".." in path.split("/"):
        errors.append("source_owned_path must not contain parent references")
    return errors


def validate_cohort(cohort: CohortDefinition) -> list[str]:
    """Return every protocol violation; an empty list means the cohort is well formed."""
    errors = non_root_path_errors(cohort.source_owned_path)
    if not cohort.cohort_id:
        errors.append("cohort_id is required")
    if not cohort.package_name:
        errors.append("package_name is required")
    if len(cohort.sessions) != REQUIRED_SESSIONS:
        errors.append(f"cohort needs exactly {REQUIRED_SESSIONS} sessions, has {len(cohort.sessions)}")
    ids = [s.session_id for s in cohort.sessions]
    if len(set(ids)) != len(ids):
        errors.append("session ids must be unique")
    days = {s.day for s in cohort.sessions}
    if len(days) < MIN_DAYS:
        errors.append(f"sessions must span at least {MIN_DAYS} distinct days, span {len(days)}")
    states = Counter(s.state for s in cohort.sessions)
    for state in STATES:
        if states.get(state, 0) == 0:
            errors.append(f"state {state} has no sessions")
    idle_labels = Counter(s.partition_label for s in cohort.sessions if s.state == "strict_idle")
    for partition in PARTITIONS:
        if idle_labels.get(partition, 0) == 0:
            errors.append(f"strict_idle sessions do not cover partition {partition}")
    if any(s.partition_label != "test" for s in cohort.sessions if s.state != "strict_idle"):
        errors.append("qfg and scripted_interactive sessions must be held-out test sessions")
    return errors


def plan_cohort(
    *,
    cohort_id: str,
    package_name: str,
    source_owned_path: str,
    days: Sequence[str],
    seed: str,
) -> CohortDefinition:
    """Lay out 24 sessions, 8 per state, round-robin over the days, labelled by partition."""
    if len(set(days)) < MIN_DAYS:
        raise ValueError(f"at least {MIN_DAYS} distinct days are required")
    ordered_days = sorted(set(days))
    for day in ordered_days:
        date.fromisoformat(day)
    stubs: list[Session] = []
    layout: list[tuple[str, str, str]] = []
    for state in STATES:
        for index in range(SESSIONS_PER_STATE):
            session_id = f"{cohort_id}-{state}-{index + 1:02d}"
            day = ordered_days[index % len(ordered_days)]
            layout.append((session_id, day, state))
            if state == "strict_idle":
                stubs.append(Session(
                    session_id=session_id, group=package_name, mode="baseline",
                    windows=({"packet_count": 0, "byte_count": 0, "avg_packet_size_bytes": 0.0},),
                    window_size_s=10.0, day=day,
                ))
    allocation = allocate_sessions(stubs, seed=seed)
    sessions = []
    for session_id, day, state in layout:
        label = allocation.partition_of(session_id) if state == "strict_idle" else "test"
        if label is None:
            raise ValueError(f"allocation left {session_id} without a partition")
        sessions.append(PilotSession(session_id=session_id, day=day, state=state, partition_label=label))
    cohort = CohortDefinition(
        cohort_id=cohort_id, package_name=package_name, source_owned_path=source_owned_path,
        seed=seed, sessions=tuple(sessions),
    )
    errors = validate_cohort(cohort)
    if errors:
        raise ValueError("; ".join(errors))
    return cohort


def record_outcome(
    cohort: CohortDefinition, *, session_id: str, outcome: str, capture_run_id: str | None = None,
) -> CohortDefinition:
    """Return a cohort with one session's explicit outcome; planned sessions stay planned."""
    if outcome not in OUTCOMES:
        raise ValueError(f"unsupported outcome: {outcome}")
    found = False
    sessions = []
    for session in cohort.sessions:
        if session.session_id == session_id:
            if session.outcome != PLANNED:
                raise ValueError(f"session {session_id} already has outcome {session.outcome}")
            sessions.append(replace(session, outcome=outcome, capture_run_id=capture_run_id))
            found = True
        else:
            sessions.append(session)
    if not found:
        raise ValueError(f"unknown session {session_id}")
    return replace(cohort, sessions=tuple(sessions))


def count_dataset_tier_captures(
    cohort: CohortDefinition, captures: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Count captures toward the cohort: dataset tier only, one per planned session.

    ``captures`` rows carry ``session_id``, ``tier`` and ``run_id``. Anything that
    is not dataset tier, not a cohort session, or a second capture for a session
    is reported separately and never counted.
    """
    by_session = {s.session_id: s for s in cohort.sessions}
    counted: dict[str, str] = {}
    ignored = Counter()
    for row in captures:
        session_id = str(row.get("session_id") or "")
        tier = str(row.get("tier") or "").lower()
        if session_id not in by_session:
            ignored["not_in_cohort"] += 1
            continue
        if tier != DATASET_TIER:
            ignored["not_dataset_tier"] += 1
            continue
        if session_id in counted:
            ignored["duplicate_session_capture"] += 1
            continue
        counted[session_id] = str(row.get("run_id") or "")
    per_state = Counter(by_session[sid].state for sid in counted)
    return {
        "contract": CONTRACT,
        "cohort_id": cohort.cohort_id,
        "counted": len(counted),
        "required": REQUIRED_SESSIONS,
        "remaining": REQUIRED_SESSIONS - len(counted),
        "per_state": {state: per_state.get(state, 0) for state in STATES},
        "ignored": dict(ignored),
        "counted_sessions": dict(sorted(counted.items())),
        "policy": "dataset-tier captures only; one capture per planned session; outcomes are recorded separately",
    }


def cohort_summary(cohort: CohortDefinition) -> dict[str, Any]:
    outcomes = Counter(s.outcome for s in cohort.sessions)
    return {
        "contract": CONTRACT,
        "cohort_id": cohort.cohort_id,
        "sessions": len(cohort.sessions),
        "days": sorted({s.day for s in cohort.sessions}),
        "per_state": {state: sum(1 for s in cohort.sessions if s.state == state) for state in STATES},
        "partitions": {p: sum(1 for s in cohort.sessions if s.partition_label == p) for p in PARTITIONS},
        "outcomes": {name: outcomes.get(name, 0) for name in (PLANNED, *OUTCOMES)},
        "validation_errors": validate_cohort(cohort),
    }


def dump_cohort(cohort: CohortDefinition) -> str:
    return json.dumps(cohort.to_dict(), indent=2, sort_keys=True) + "\n"


__all__ = [
    "CONTRACT", "OUTCOMES", "PARTITIONS", "PLANNED", "REQUIRED_SESSIONS", "STATES",
    "CohortDefinition", "PilotSession", "cohort_summary", "count_dataset_tier_captures",
    "dump_cohort", "non_root_path_errors", "plan_cohort", "record_outcome", "validate_cohort",
]
