from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution import results_persist
from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
    StaticSessionRunRollups,
)


def test_persist_cohort_rollup_refreshes_static_session_header(monkeypatch) -> None:
    calls: list[tuple[str | None, str | None, str]] = []
    audit_refresh_calls: list[tuple[str | None, bool, bool]] = []
    materialize_calls: list[tuple[str | None, str | None]] = []

    monkeypatch.setattr(
        results_persist,
        "fetch_static_session_run_rollups",
        lambda stamp, scope: StaticSessionRunRollups(
            total_run_count=4,
            completed_run_count=4,
            failed_run_count=0,
            running_run_count=0,
            interrupted_run_count=0,
            persist_error_run_count=0,
            missing_artifacts_run_count=0,
            first_created_at=None,
            last_ended_at=None,
        ),
    )
    monkeypatch.setattr(
        results_persist,
        "materialize_static_session_rollup",
        lambda *, session_stamp, scope_label: materialize_calls.append((session_stamp, scope_label))
        or True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.static_session_summary.maybe_refresh_static_analysis_session_summary",
        lambda stamp, scope, *, reason: calls.append((stamp, scope, reason)),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit.refresh_persistence_audit_artifact_for_session",
        lambda session_stamp, *, write, prefer_reconcile: audit_refresh_calls.append(
            (session_stamp, write, prefer_reconcile)
        ),
    )

    results_persist._persist_cohort_rollup("sess-1", "All harvested apps")

    assert materialize_calls == [("sess-1", "All harvested apps")]
    assert calls == [("sess-1", "All harvested apps", "post_cohort_rollup")]
    assert audit_refresh_calls == [("sess-1", True, False)]
