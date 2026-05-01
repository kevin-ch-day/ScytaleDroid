"""Unit checks for Fedora/ADB/MariaDB deployment probe."""

from __future__ import annotations

import pytest

from scytaledroid.Diagnostics import deployment_check as dc


@pytest.fixture
def isolate_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dc, "_fedora_check", lambda: dc.CheckLine("ok", "os", "Fedora-class host detected (pytest)"))
    monkeypatch.setattr(
        dc,
        "_adb_check",
        lambda timeout_s=8.0: [dc.CheckLine("ok", "adb", "`adb devices` stub")],
    )


def test_collect_checks_python_too_old(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dc,
        "_python_check",
        lambda: dc.CheckLine("fail", "python", "requires Python 3.11+ (stub)"),
    )
    checks = dc.collect_checks(require_database=False)
    assert any(c.level == "fail" and c.topic == "python" for c in checks)


def test_collect_checks_db_optional_warn(monkeypatch: pytest.MonkeyPatch, isolate_probes: None) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: False,
    )
    checks = dc.collect_checks(require_database=False)
    warns = [c for c in checks if c.topic == "database"]
    assert any(c.level == "warn" for c in warns)
    assert not any(c.level == "fail" for c in checks)


def test_collect_checks_require_database_fail(monkeypatch: pytest.MonkeyPatch, isolate_probes: None) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: False,
    )
    checks = dc.collect_checks(require_database=True)
    fails = [c for c in checks if c.topic == "database"]
    assert any(c.level == "fail" for c in fails)


def test_run_exit_code_reflects_fail(monkeypatch: pytest.MonkeyPatch, isolate_probes: None, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: False,
    )
    rc = dc.run(json_mode=False, require_database=True)
    assert rc == 1
    captured = capsys.readouterr().out
    assert "DSN unset" in captured
