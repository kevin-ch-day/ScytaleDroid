"""Tests for static scan lifecycle helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core import run_lifecycle
from scytaledroid.StaticAnalysis.cli.core.models import RunOutcome, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import static_scan_lifecycle as lifecycle


def test_collect_static_run_ids_uses_only_invocation_owned_rows(tmp_path: Path) -> None:
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
    assert ids == [1]


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


def test_cleanup_finalizes_only_current_invocation_owned_run(monkeypatch, tmp_path: Path) -> None:
    now = datetime.now(UTC)
    outcome = RunOutcome(
        results=[SimpleNamespace(static_run_id=202, package_name="current")],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="app", label="x", groups=tuple()),
        base_dir=tmp_path,
    )
    finalized: list[list[int]] = []
    monkeypatch.setattr(
        run_lifecycle,
        "finalize_open_static_runs",
        lambda ids, **_kwargs: finalized.append(list(ids)),
    )

    owned_ids = lifecycle.collect_static_run_ids_for_finalize(outcome, "historical-session")
    run_lifecycle.finalize_open_runs(owned_ids, status="FAILED")

    assert owned_ids == [202]
    assert finalized == [[202]]
