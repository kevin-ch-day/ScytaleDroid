from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.cli.persistence.finalization_flow import (
    StaticRunFinalizationCallbacks,
    finalize_persisted_static_run,
)


class _Outcome:
    def __init__(self) -> None:
        self.persisted_findings = 0
        self.canonical_failed = False
        self.errors: list[str] = []

    def add_error(self, message: str) -> None:
        self.errors.append(message)


class _SlottedOutcome:
    __slots__ = ("persisted_findings", "canonical_failed", "errors")

    def __init__(self) -> None:
        self.persisted_findings = 0
        self.canonical_failed = False
        self.errors: list[str] = []

    def add_error(self, message: str) -> None:
        self.errors.append(message)


def _build_callbacks() -> StaticRunFinalizationCallbacks:
    def run_sql(sql: str, params=None, fetch=None):
        sql_norm = " ".join(sql.split())
        if "SELECT session_label FROM static_analysis_runs WHERE id=%s" in sql_norm:
            return ("20260428-all-full",)
        if "COUNT(*) AS run_rows" in sql_norm:
            return (120, 120, 120)
        if "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND is_canonical=1" in sql_norm:
            return (1,)
        return None

    return StaticRunFinalizationCallbacks(
        run_sql=run_sql,
        export_dep_json=lambda *_a, **_k: None,
        maybe_set_canonical_static_run=lambda **_k: None,
        update_static_run_metadata=lambda *_a, **_k: None,
        update_static_run_status=lambda **_k: None,
        normalize_run_status=lambda status: str(status or "").upper(),
    )


@pytest.mark.unit
def test_group_scope_skip_logs_once_per_session(monkeypatch):
    messages: list[str] = []
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.finalization_flow.log.info",
        lambda message, **_kwargs: messages.append(message),
    )

    outcome = _Outcome()
    callbacks = _build_callbacks()

    common = dict(
        dry_run=False,
        package_for_run="pkg.alpha",
        session_stamp="20260428-all-full",
        scope_label="All harvested apps",
        run_package="pkg.alpha",
        run_status="COMPLETED",
        paper_grade_requested=True,
        canonical_action=None,
        persistence_failed=False,
        outcome=outcome,
        ended_at_utc="2026-04-28 17:03:52",
        abort_reason=None,
        abort_signal=None,
        callbacks=callbacks,
    )

    finalize_persisted_static_run(static_run_id=101, **common)
    finalize_persisted_static_run(static_run_id=102, **common)

    skip_logs = [m for m in messages if "Skipping canonical singleton enforcement" in m]
    assert skip_logs == [
        "Skipping canonical singleton enforcement for group scope session_label=20260428-all-full"
    ]


@pytest.mark.unit
def test_group_scope_skip_does_not_mutate_slotted_outcome(monkeypatch):
    messages: list[str] = []
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.finalization_flow.log.info",
        lambda message, **_kwargs: messages.append(message),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.finalization_flow._GROUP_SCOPE_SKIP_LOGGED_SESSIONS",
        set(),
    )

    callbacks = _build_callbacks()
    outcome = _SlottedOutcome()

    run_status = finalize_persisted_static_run(
        static_run_id=101,
        dry_run=False,
        package_for_run="pkg.alpha",
        session_stamp="20260428-all-full",
        scope_label="All harvested apps",
        run_package="pkg.alpha",
        run_status="COMPLETED",
        paper_grade_requested=True,
        canonical_action=None,
        persistence_failed=False,
        outcome=outcome,
        ended_at_utc="2026-04-28 17:03:52",
        abort_reason=None,
        abort_signal=None,
        callbacks=callbacks,
    )

    assert run_status == "COMPLETED"
    assert outcome.errors == []
    assert messages == [
        "Skipping canonical singleton enforcement for group scope session_label=20260428-all-full"
    ]
