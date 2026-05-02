from __future__ import annotations

from typing import Any

import pytest


def test_fetch_prior_profile_session_snapshot_requires_scope_and_packages() -> None:
    mod = pytest.importorskip("scytaledroid.StaticAnalysis.cli.flows.profile_prior_session")

    assert mod.fetch_prior_profile_session_snapshot("", frozenset({"a.example"})) is None
    assert mod.fetch_prior_profile_session_snapshot("Cohort", frozenset()) is None


def test_fetch_prior_profile_session_snapshot_none_when_schema_gate_fails(monkeypatch) -> None:
    from scytaledroid.Database.db_utils import schema_gate

    mod = pytest.importorskip("scytaledroid.StaticAnalysis.cli.flows.profile_prior_session")
    monkeypatch.setattr(schema_gate, "static_schema_gate", lambda: (False, "nope", ""))

    assert mod.fetch_prior_profile_session_snapshot("Cohort Alpha", frozenset({"com.a"})) is None


def test_format_audit_session_command() -> None:
    mod = pytest.importorskip("scytaledroid.StaticAnalysis.cli.flows.profile_prior_session")

    assert "audit_static_session.py" in mod.format_audit_session_command("")
    assert "20260502-rda-full" in mod.format_audit_session_command("20260502-rda-full")


def test_fetch_prior_profile_session_snapshot_returns_aggregates(monkeypatch) -> None:
    from scytaledroid.Database.db_core import db_queries as core_q
    from scytaledroid.Database.db_utils import schema_gate

    mod = pytest.importorskip("scytaledroid.StaticAnalysis.cli.flows.profile_prior_session")
    monkeypatch.setattr(schema_gate, "static_schema_gate", lambda: (True, "OK", ""))

    sequence: list[Any] = [
        ("20260502-rda-full",),
        (12,),
        (535,),
        (797,),
        (12,),
        [{"p": "com.a"}, {"p": "com.b"}],
    ]

    def fake_run_sql(
        *_a: Any,
        fetch: str = "none",
        **_kw: Any,
    ) -> Any:
        if not sequence:
            raise AssertionError("unexpected run_sql call")
        return sequence.pop(0)

    monkeypatch.setattr(core_q, "run_sql", fake_run_sql)

    snap = mod.fetch_prior_profile_session_snapshot(
        "Cohort Alpha",
        frozenset({"com.a", "com.b"}),
    )
    assert snap is not None
    assert snap.session_stamp == "20260502-rda-full"
    assert snap.static_runs == 12
    assert snap.findings_count == 535
    assert snap.permissions_count == 797
    assert snap.handoff_rows == 12
    assert snap.dynamic_ready == (2, 2)
