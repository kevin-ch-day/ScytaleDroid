from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
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
        scan_splits_enabled=True,
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
    assert "Core readiness" in out
    assert "After this run" in out
    assert "Post-run diagnostics" in out
    assert "Permission Intel" in out
    assert "Run grade: EXPERIMENTAL" in out
    assert "SCYTALEDROID_CANONICAL_GRADE=0" in out
    assert "DB persistence: ON" in out
    assert "Legacy mirrors" in out
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
    assert "legacy mirrors" in out.lower()


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
    assert "DB persistence:" in out
    assert "SCYTALEDROID_PERSISTENCE_READY=0" in out
    assert "[WARN]" in out


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
    assert "Permission Intel: not configured" in out
    assert "Run grade: EXPERIMENTAL" in out
    assert (
        "Paper-grade / governance-complete evidence requires Permission Intel readiness." in out
        or "paper-grade needs Permission Intel + governance snapshots" in out
    )
    assert "SCYTALEDROID_PERMISSION_INTEL_DB_" in out


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
        "scytaledroid.StaticAnalysis.cli.intel_gate.governance_ready",
        lambda: (True, "ok"),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "Permission Intel: OK" in out
    assert "Run grade: PAPER-GRADE READY" in out
    assert "does not gate" in out.lower()


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
        "scytaledroid.StaticAnalysis.cli.intel_gate.governance_ready",
        lambda: (False, "governance_missing"),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "snapshots not loaded" in out


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
        "scytaledroid.StaticAnalysis.cli.intel_gate.governance_ready",
        lambda: (False, "conn_failed"),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "conn_failed" in out
    assert "[WARN]" in out


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
        "scytaledroid.StaticAnalysis.cli.intel_gate.governance_ready",
        _raise,
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "query failed" in out.lower()
    assert "boom" in out
    assert "[WARN]" in out


def test_preflight_run_context_includes_package_and_apk_counts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )
    group = SimpleNamespace(artifacts=("base.apk", "split.apk"))
    selection = ScopeSelection("all", "All harvested apps", (group,))
    run_dispatch._emit_static_run_preflight_summary(
        _base_params(scope="all", scope_label="All harvested apps"),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
        selection=selection,
    )
    out = capsys.readouterr().out
    assert "Run context" in out
    assert "Packages in this run: 1" in out
    assert "APK files in this run: 2" in out


def test_preflight_catalog_labels_line_is_compact(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.catalog.app_display_label_preflight.summarize_apps_display_labels_for_groups",
        lambda _groups: (135, 152),
    )
    group = SimpleNamespace(artifacts=("base.apk",), package_name="com.example.app")
    selection = ScopeSelection("all", "All harvested apps", (group,))

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(scope="all", scope_label="All harvested apps"),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
        selection=selection,
    )
    out = capsys.readouterr().out
    assert "Display labels: 135/152 labeled · 17 need review" in out
    assert "Catalog hygiene: Database Tools → option 8" in out
    assert "PYTHONPATH=. python scripts/db/report_app_label_hygiene.py" not in out


class _FakeDatabaseEngine:
    def fetch_one(self, _q: str) -> tuple[int]:
        return (1,)

    def close(self) -> None:
        return


def test_preflight_primary_db_connect_failure_emits_error_row(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("scytaledroid.Database.db_core.db_config.db_enabled", lambda: True)

    class _Boom:
        def __init__(self) -> None:
            raise ConnectionError("refused")

    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_engine.DatabaseEngine",
        _Boom,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.static_run_preflight.check_static_persistence_readiness",
        lambda _p: (True, "OK", ""),
    )

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "[ERROR]" in out
    assert "Primary DB: ERROR" in out


def test_preflight_static_schema_gate_failure_emits_error_row(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("scytaledroid.Database.db_core.db_config.db_enabled", lambda: True)
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_engine.DatabaseEngine",
        lambda: _FakeDatabaseEngine(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.static_run_preflight.check_static_persistence_readiness",
        lambda _p: (False, "static DDL incomplete", "apply migrations"),
    )
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
    assert "[ERROR]" in out
    assert "Static schema gate: ERROR" in out
    assert "static DDL incomplete" in out


def test_preflight_output_paths_not_writable_emits_error_row(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    _preflight_no_primary_db: None,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.permission_intel.is_permission_intel_configured",
        lambda: False,
    )
    _orig_write = Path.write_text

    def _write_text(self: Path, *args: object, **kwargs: object) -> int:
        if self.name == ".scytaledroid_write_probe_delete_me":
            raise OSError("read-only filesystem")
        return _orig_write(self, *args, **kwargs)  # type: ignore[misc]

    monkeypatch.setattr(Path, "write_text", _write_text)

    run_dispatch._emit_static_run_preflight_summary(
        _base_params(),
        frozen_ctx=_ctx(),
        base_dir=Path("."),
    )
    out = capsys.readouterr().out
    assert "[ERROR]" in out
    assert "Output paths: ERROR" in out
