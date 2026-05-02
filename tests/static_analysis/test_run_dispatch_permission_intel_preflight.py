from __future__ import annotations

from pathlib import Path

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


def _base_params(**kw) -> RunParameters:
    base = dict(
        profile="full",
        scope="app",
        scope_label="Ex",
        dry_run=False,
        paper_grade_requested=True,
    )
    base.update(kw)
    return RunParameters(**base)


def _ctx(*, quiet: bool = False, batch: bool = False) -> StaticRunContext:
    return StaticRunContext(
        run_mode="direct",
        quiet=quiet,
        batch=batch,
        noninteractive=False,
        show_splits=False,
        session_stamp="sess",
        persistence_ready=True,
        paper_grade_requested=True,
    )


@pytest.fixture
def _preflight_no_primary_db(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid real MariaDB / schema gate during preflight unit tests."""

    monkeypatch.setattr("scytaledroid.Database.db_core.db_config.db_enabled", lambda: False)


@pytest.mark.parametrize(
    "params_kw,frozen_kwargs",
    [
        ({"dry_run": True}, {}),
        ({}, {"quiet": True, "batch": True}),
    ],
)
def test_static_preflight_short_circuits(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
    params_kw: dict,
    frozen_kwargs: dict,
) -> None:
    called: list[bool] = []

    def _boom() -> bool:
        called.append(True)
        return True

    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        _boom,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(**params_kw),
        frozen_ctx=_ctx(**frozen_kwargs),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert not called
    assert "Static run preflight" not in out


def test_static_preflight_runs_when_canonical_grade_off(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(paper_grade_requested=False),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "Static run preflight" in out
    assert "Paper-grade: experimental (SCYTALEDROID_CANONICAL_GRADE=0)" in out
    assert "DB persistence: enabled" in out
    assert "mirror removed" in out.lower()
    assert "Split scan:" in out


def test_static_preflight_notes_legacy_mirror_removed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "legacy" in out.lower() and "mirror removed" in out.lower()


def test_static_preflight_shows_persistence_skipped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(persistence_ready=False),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "DB persistence: skipped" in out
    assert "SCYTALEDROID_PERSISTENCE_READY=0" in out


def test_preflight_warns_when_intel_not_configured(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "Permission Intel: missing" in out
    assert "SCYTALEDROID_CANONICAL_GRADE=0" in out


def test_preflight_ok_when_governance_ready(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.pipeline.governance_ready",
        lambda: (True, "ok"),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "Permission Intel: OK" in out
    assert "paper-grade ready" in out
    assert "Paper-grade: ready" in out


def test_preflight_governance_missing_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.pipeline.governance_ready",
        lambda: (False, "governance_missing"),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "governance_missing" in out


def test_preflight_warns_other_governance_detail(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.pipeline.governance_ready",
        lambda: (False, "conn_failed"),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "conn_failed" in out


def test_preflight_handles_governance_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: True,
    )

    def _raise() -> tuple[bool, str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.execution.pipeline.governance_ready",
        _raise,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "query_failed" in out
    assert "boom" in out
