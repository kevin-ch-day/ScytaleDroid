from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.DeviceAnalysis import package_inventory


pytestmark = [pytest.mark.unit]


def test_parse_package_listing_preserves_raw_package_case():
    parsed = package_inventory._parse_package_listing(
        "package:com.qualcomm.qti.uimGbaApp versionCode:35\n"
    )

    assert parsed == [("com.qualcomm.qti.uimGbaApp", "35", None)]


def test_list_packages_with_versions_uses_portable_versioncode_only_probe(monkeypatch):
    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=20):
        del timeout
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout="package:com.example.app versionCode:42\n",
        )

    monkeypatch.setattr(package_inventory.adb_client, "run_shell_command", _run_shell_command)

    rows = package_inventory.list_packages_with_versions("SER123", allow_fallbacks=False)

    assert calls == [["cmd", "package", "list", "packages", "--show-versioncode", "--user", "0"]]
    assert rows == [("com.example.app", "42", None)]


def test_list_packages_with_versions_falls_back_from_cmd_to_pm_when_cmd_is_unsupported(monkeypatch):
    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=20):
        del timeout
        calls.append(command)
        if command[:3] == ["cmd", "package", "list"]:
            return SimpleNamespace(returncode=0, stdout="Unknown option: --user\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="package:com.example.app versionCode:42\n", stderr="")

    monkeypatch.setattr(package_inventory.adb_client, "run_shell_command", _run_shell_command)

    rows = package_inventory.list_packages_with_versions("SER123", allow_fallbacks=False)

    assert calls == [
        ["cmd", "package", "list", "packages", "--show-versioncode", "--user", "0"],
        ["cmd", "package", "list", "packages", "--show-versioncode"],
        ["pm", "list", "packages", "--show-versioncode", "--user", "0"],
    ]
    assert rows == [("com.example.app", "42", None)]


def test_list_packages_with_versions_honors_configured_user_override(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setenv("SCYTALEDROID_ADB_PACKAGE_USER_ID", "10")

    def _run_shell_command(_serial, command, timeout=20):
        del timeout
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="package:com.example.app versionCode:42\n", stderr="")

    monkeypatch.setattr(package_inventory.adb_client, "run_shell_command", _run_shell_command)

    rows = package_inventory.list_packages_with_versions("SER123", allow_fallbacks=False)

    assert calls == [["cmd", "package", "list", "packages", "--show-versioncode", "--user", "10"]]
    assert rows == [("com.example.app", "42", None)]


def test_list_packages_with_versions_falls_back_to_package_only_when_versioncode_unsupported(
    monkeypatch,
):
    monkeypatch.setattr(
        package_inventory.adb_client,
        "run_shell_command",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
    )
    monkeypatch.setattr(package_inventory, "list_packages", lambda _serial: ["com.example.app"])

    rows = package_inventory.list_packages_with_versions("SER123", allow_fallbacks=True)

    assert rows == [("com.example.app", None, None)]
