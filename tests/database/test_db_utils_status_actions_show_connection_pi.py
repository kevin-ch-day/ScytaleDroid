"""`show_connection_and_config` Permission Intel presentation (no live DB)."""

from __future__ import annotations

import pytest
from scytaledroid.Database.db_utils.action_groups import status_actions as sa


def _patch_show_connection_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sa.db_config,
        "DB_CONFIG",
        {
            "engine": "mysql",
            "host": "localhost",
            "port": 3306,
            "database": "core_db",
            "user": "dbuser",
        },
    )
    monkeypatch.setattr(sa.db_config, "DB_CONFIG_SOURCE", "test")
    monkeypatch.setattr(sa.diagnostics, "get_schema_version", lambda: "0.0.1")
    monkeypatch.setattr(sa.diagnostics, "check_connection", lambda: True)
    monkeypatch.setattr(
        sa,
        "bridge_posture_summary",
        lambda: {
            "compat_only_keep": 0,
            "compat_mirror_review": 0,
            "derived_review": 0,
            "freeze_candidate": 0,
        },
    )
    monkeypatch.setattr(sa, "list_bridge_postures", lambda: [])
    monkeypatch.setattr(sa.prompt_utils, "press_enter_to_continue", lambda *a, **k: None)


def test_show_connection_pi_not_configured_shows_skipped(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _patch_show_connection_baseline(monkeypatch)
    monkeypatch.setattr(sa.intel_db, "is_permission_intel_configured", lambda: False)
    monkeypatch.setattr(sa, "list_operational_managed_tables", lambda: [])

    sa.show_connection_and_config()
    out = capsys.readouterr().out
    assert "SKIPPED" in out
    assert "DSN not configured" in out


def test_show_connection_pi_configured_describe_target_raises(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _patch_show_connection_baseline(monkeypatch)
    monkeypatch.setattr(sa.intel_db, "is_permission_intel_configured", lambda: True)
    monkeypatch.setattr(
        sa.intel_db,
        "describe_target",
        lambda: (_ for _ in ()).throw(RuntimeError("resolve failed")),
    )
    monkeypatch.setattr(sa, "list_operational_managed_tables", lambda: [])

    sa.show_connection_and_config()
    out = capsys.readouterr().out
    assert "ERROR" in out
    assert "unable to inspect target" in out
