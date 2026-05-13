"""Tests for static scan lifecycle helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import static_scan_lifecycle as lifecycle


def test_collect_static_run_ids_merges_db_started_rows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def _fake_run_sql(query: str, params_sql: tuple, *, fetch: str):
        if "FROM static_analysis_runs" in query and fetch == "all":
            return [(99,), (100,)]
        return None

    monkeypatch.setattr("scytaledroid.Database.db_core.db_queries.run_sql", _fake_run_sql)

    now = datetime.now(UTC)
    scope = ScopeSelection(scope="app", label="x", groups=tuple())
    outcome = RunOutcome(
        results=[SimpleNamespace(static_run_id=1, package_name="a")],
        started_at=now,
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
    )
    ids = lifecycle.collect_static_run_ids_for_finalize(outcome, "sess-1")
    assert ids == [1, 99, 100]


def test_collect_static_run_ids_empty_when_no_ids(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    scope = ScopeSelection(scope="app", label="x", groups=tuple())
    outcome = RunOutcome(
        results=[SimpleNamespace(static_run_id=None, package_name="a")],
        started_at=now,
        finished_at=now,
        scope=scope,
        base_dir=tmp_path,
    )
    assert lifecycle.collect_static_run_ids_for_finalize(outcome, None) == []
