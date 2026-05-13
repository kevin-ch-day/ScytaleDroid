"""DB health summary — Permission Intel / governance presentation (no live DB)."""

from __future__ import annotations

from dataclasses import fields
from types import SimpleNamespace

import pytest

from scytaledroid.Database.db_utils.health_checks.analysis_integrity import AnalysisIntegritySummary
from scytaledroid.Database.db_utils.menus import health_checks as menu_module


def _analysis_integrity_stub() -> AnalysisIntegritySummary:
    kw = {f.name: None for f in fields(AnalysisIntegritySummary)}
    kw["static_dynamic_summary_source"] = "stub"
    kw["legacy_non_utf8_package_tables"] = ()
    kw["missing_schema_objects"] = ()
    return AnalysisIntegritySummary(**kw)


def _patch_health_summary_common(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(menu_module, "fetch_analysis_integrity_summary", lambda: _analysis_integrity_stub())
    monkeypatch.setattr(
        menu_module,
        "fetch_health_summary",
        lambda: SimpleNamespace(
            running_total=0,
            running_recent=0,
            ok_recent=0,
            failed_recent=0,
            aborted_recent=0,
            orphan_findings=0,
            orphan_samples=0,
            orphan_selected_samples=0,
            orphan_sample_sets=0,
            orphan_audit_apps=0,
        ),
    )
    monkeypatch.setattr(menu_module, "_column_exists", lambda *_a, **_k: False)
    monkeypatch.setattr(menu_module, "scalar", lambda *_a, **_k: 0)
    monkeypatch.setattr(menu_module.prompt_utils, "press_enter_to_continue", lambda *args, **kwargs: None)


def test_health_summary_pi_not_configured_shows_skipped(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _patch_health_summary_common(monkeypatch)
    monkeypatch.setattr(menu_module.intel_db, "is_permission_intel_configured", lambda: False)
    monkeypatch.setattr(
        menu_module.intel_db,
        "describe_target",
        lambda: (_ for _ in ()).throw(AssertionError("describe_target must not run when PI unset")),
    )
    monkeypatch.setattr(
        menu_module.intel_db,
        "governance_snapshot_count",
        lambda: (_ for _ in ()).throw(AssertionError("governance_snapshot_count must not run when PI unset")),
    )
    monkeypatch.setattr(menu_module, "list_operational_managed_tables", lambda: [])

    menu_module.run_health_summary()
    out = capsys.readouterr().out
    assert "Permission Intel        : SKIPPED — DSN not configured" in out


def test_health_summary_describe_target_failure_shows_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _patch_health_summary_common(monkeypatch)
    monkeypatch.setattr(menu_module.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        menu_module.intel_db,
        "describe_target",
        lambda: (_ for _ in ()).throw(ValueError("invalid PI env")),
    )
    monkeypatch.setattr(menu_module.intel_db, "governance_snapshot_count", lambda: 3)
    monkeypatch.setattr(menu_module.intel_db, "governance_row_count", lambda: 4)
    monkeypatch.setattr(menu_module, "list_operational_managed_tables", lambda: [])

    menu_module.run_health_summary()
    out = capsys.readouterr().out
    assert "Permission Intel        : ERROR — " in out
    assert "target:" in out
    assert "ValueError" in out
    assert "3" in out
    assert "4" in out


def test_health_summary_pi_configured_governance_failure_shows_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _patch_health_summary_common(monkeypatch)
    monkeypatch.setattr(menu_module.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        menu_module.intel_db,
        "describe_target",
        lambda: {"database": "pi_catalog", "source": "env"},
    )
    monkeypatch.setattr(
        menu_module.intel_db,
        "governance_snapshot_count",
        lambda: (_ for _ in ()).throw(OSError("PI unreachable")),
    )
    monkeypatch.setattr(menu_module.intel_db, "governance_row_count", lambda: 0)
    monkeypatch.setattr(menu_module, "list_operational_managed_tables", lambda: [])

    menu_module.run_health_summary()
    out = capsys.readouterr().out
    assert "Permission Intel        : ERROR — " in out
    assert "governance:" in out
    assert "OSError" in out


def test_health_summary_duplicate_scan_failure_keeps_governance_metrics(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _patch_health_summary_common(monkeypatch)
    snap, rows = 91355, 91356
    monkeypatch.setattr(menu_module.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        menu_module.intel_db,
        "describe_target",
        lambda: {"database": "pi_catalog", "source": "env"},
    )
    monkeypatch.setattr(menu_module.intel_db, "governance_snapshot_count", lambda: snap)
    monkeypatch.setattr(menu_module.intel_db, "governance_row_count", lambda: rows)
    monkeypatch.setattr(
        menu_module,
        "list_operational_managed_tables",
        lambda: (_ for _ in ()).throw(RuntimeError("core duplicate scan failed")),
    )
    monkeypatch.setattr(menu_module, "governance_ready", lambda: (True, "ok"))

    menu_module.run_health_summary()
    out = capsys.readouterr().out
    assert "Permission Intel        : ERROR" not in out
    assert str(snap) in out
    assert str(rows) in out
    assert "governance_ready (static CLI / paper-grade gate): True" in out
