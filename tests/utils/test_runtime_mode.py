from __future__ import annotations

from scytaledroid.Utils.System import runtime_mode


def test_runtime_mode_defaults_to_physical_preset(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_RUNTIME_PRESET", raising=False)
    monkeypatch.delenv("SCYTALEDROID_DEBUG_MODE", raising=False)
    monkeypatch.delenv("SCYTALEDROID_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("SCYTALEDROID_SYS_ENV", raising=False)
    monkeypatch.delenv("SCYTALEDROID_SYS_TEST", raising=False)

    mode = runtime_mode.resolve_runtime_mode()

    assert mode.preset == "physical"
    assert mode.debug_mode is False
    assert mode.sys_test is False
    assert mode.execution_mode == "PROD"
    assert mode.sys_env == "PHYSICAL"
    assert mode.show_runtime_identity is False


def test_runtime_mode_virtual_preset_enables_dev_virtual(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_RUNTIME_PRESET", "virtual")
    monkeypatch.delenv("SCYTALEDROID_DEBUG_MODE", raising=False)
    monkeypatch.delenv("SCYTALEDROID_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("SCYTALEDROID_SYS_ENV", raising=False)
    monkeypatch.delenv("SCYTALEDROID_SYS_TEST", raising=False)

    mode = runtime_mode.resolve_runtime_mode()

    assert mode.preset == "virtual"
    assert mode.debug_mode is True
    assert mode.sys_test is False
    assert mode.execution_mode == "DEV"
    assert mode.sys_env == "VIRTUAL"
    assert mode.show_runtime_identity is True


def test_runtime_mode_explicit_env_overrides_preset(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_RUNTIME_PRESET", "validation")
    monkeypatch.setenv("SCYTALEDROID_DEBUG_MODE", "false")
    monkeypatch.setenv("SCYTALEDROID_SYS_TEST", "false")
    monkeypatch.setenv("SCYTALEDROID_EXECUTION_MODE", "PROD")
    monkeypatch.setenv("SCYTALEDROID_SYS_ENV", "PHYSICAL")

    mode = runtime_mode.resolve_runtime_mode()

    assert mode.preset == "validation"
    assert mode.debug_mode is False
    assert mode.sys_test is False
    assert mode.execution_mode == "PROD"
    assert mode.sys_env == "PHYSICAL"
    assert mode.show_runtime_identity is False
