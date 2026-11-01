"""Device pilot cohort: protocol validation and dataset-tier-only queue counting."""

from __future__ import annotations

import json

import pytest
from scytaledroid.DynamicAnalysis.research import device_pilot_cohort as dpc

DAYS = ("2026-11-03", "2026-11-04", "2026-11-05")


def _cohort(**overrides):
    kwargs = dict(cohort_id="pilot-01", package_name="com.example.app",
                  source_owned_path="/sdcard/Android/data/com.example.app/files", days=DAYS, seed="pilot-seed")
    kwargs.update(overrides)
    return dpc.plan_cohort(**kwargs)


def test_planned_cohort_meets_the_protocol_and_is_deterministic():
    cohort = _cohort()
    assert dpc.validate_cohort(cohort) == []
    summary = dpc.cohort_summary(cohort)
    assert summary["sessions"] == 24
    assert summary["days"] == list(DAYS)
    assert summary["per_state"] == {"strict_idle": 8, "qfg": 8, "scripted_interactive": 8}
    assert summary["partitions"]["fit"] >= 1 and summary["partitions"]["calibrate"] >= 1
    assert summary["partitions"]["test"] == 16 + (8 - summary["partitions"]["fit"] - summary["partitions"]["calibrate"])
    assert summary["outcomes"]["planned"] == 24
    assert dpc.plan_cohort(cohort_id="pilot-01", package_name="com.example.app",
                           source_owned_path="/sdcard/x", days=DAYS, seed="pilot-seed").sessions[0].partition_label == cohort.sessions[0].partition_label
    assert json.loads(dpc.dump_cohort(cohort))["contract"] == "device_pilot_cohort_v1"


def test_root_only_paths_short_day_spans_and_missing_states_are_refused():
    with pytest.raises(ValueError, match="root-only"):
        _cohort(source_owned_path="/data/data/com.example.app/files")
    with pytest.raises(ValueError, match="at least 3 distinct days"):
        _cohort(days=("2026-11-03", "2026-11-03", "2026-11-04"))
    assert dpc.non_root_path_errors("relative/path") == ["source_owned_path must be an absolute device path"]
    cohort = _cohort()
    broken = dpc.CohortDefinition(
        cohort_id=cohort.cohort_id, package_name=cohort.package_name,
        source_owned_path=cohort.source_owned_path, seed=cohort.seed,
        sessions=tuple(s for s in cohort.sessions if s.state != "qfg"),
    )
    errors = dpc.validate_cohort(broken)
    assert "cohort needs exactly 24 sessions, has 16" in errors
    assert "state qfg has no sessions" in errors
    with pytest.raises(ValueError, match="unsupported state"):
        dpc.PilotSession(session_id="x", day="2026-11-03", state="rooted_idle", partition_label="test")
    with pytest.raises(ValueError, match="unsupported outcome"):
        dpc.PilotSession(session_id="x", day="2026-11-03", state="qfg", partition_label="test", outcome="maybe")


def test_outcomes_are_explicit_and_recorded_once():
    cohort = _cohort()
    session_id = cohort.sessions[8].session_id
    updated = dpc.record_outcome(cohort, session_id=session_id, outcome="executed_send", capture_run_id="run-1")
    assert next(s for s in updated.sessions if s.session_id == session_id).outcome == "executed_send"
    assert dpc.cohort_summary(updated)["outcomes"]["executed_send"] == 1
    with pytest.raises(ValueError, match="already has outcome"):
        dpc.record_outcome(updated, session_id=session_id, outcome="capture_loss")
    with pytest.raises(ValueError, match="unsupported outcome"):
        dpc.record_outcome(cohort, session_id=session_id, outcome="sent_probably")
    with pytest.raises(ValueError, match="unknown session"):
        dpc.record_outcome(cohort, session_id="nope", outcome="unreached")
    assert cohort.sessions[8].outcome == "planned"


def test_guided_queue_counts_only_dataset_tier_captures_once_per_session():
    cohort = _cohort()
    ids = [s.session_id for s in cohort.sessions]
    captures = [
        {"session_id": ids[0], "tier": "dataset", "run_id": "r1"},
        {"session_id": ids[0], "tier": "dataset", "run_id": "r1-dup"},
        {"session_id": ids[1], "tier": "exploratory", "run_id": "r2"},
        {"session_id": ids[2], "tier": "DATASET", "run_id": "r3"},
        {"session_id": "foreign", "tier": "dataset", "run_id": "r4"},
        {"session_id": ids[9], "tier": "dataset", "run_id": "r5"},
    ]
    counted = dpc.count_dataset_tier_captures(cohort, captures)
    assert counted["counted"] == 3 and counted["remaining"] == 21
    assert counted["per_state"] == {"strict_idle": 2, "qfg": 1, "scripted_interactive": 0}
    assert counted["ignored"] == {"duplicate_session_capture": 1, "not_dataset_tier": 1, "not_in_cohort": 1}
    assert counted["counted_sessions"][ids[2]] == "r3"
