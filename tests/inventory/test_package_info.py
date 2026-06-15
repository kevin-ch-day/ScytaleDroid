from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DeviceAnalysis import package_info


def test_get_package_metadata_extracts_signer_digests(monkeypatch) -> None:
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "get", lambda _key: None)
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "set", lambda _key, _value: None)

    completed = SimpleNamespace(
        returncode=0,
        stdout="""
            packageName=com.example.app
            versionName=1.2.3
            signer #1 certificate SHA-256 digest: AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
            signer #2 certificate SHA-256 digest: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
        """,
    )
    monkeypatch.setattr(package_info.adb_client, "run_shell_command", lambda *_a, **_k: completed)

    metadata = package_info.get_package_metadata("SERIAL123", "com.example.app", refresh=True)

    assert metadata["signer_cert_digest"] == "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    assert metadata["signer_set_hash"]
    assert len(str(metadata["signer_set_hash"])) == 64


def test_get_package_metadata_prefers_dumpsys_package_output(monkeypatch) -> None:
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "get", lambda _key: None)
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "set", lambda _key, _value: None)

    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=25):
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout="""
  Package [com.example.app] (abc123):
    appId=10234
    versionName=2.4.6
    lastUpdateTime=2026-06-14 00:40:13
    installerPackageName=com.android.vending
    User 0: installed=true
      firstInstallTime=2026-05-08 16:33:35
        """,
        )

    monkeypatch.setattr(package_info.adb_client, "run_shell_command", _run_shell_command)

    metadata = package_info.get_package_metadata("SER123", "com.example.app", refresh=True)

    assert calls == [["dumpsys", "package", "--user", "0", "com.example.app"]]
    assert metadata["package_name"] == "com.example.app"
    assert metadata["user_id"] == "10234"
    assert metadata["version_name"] == "2.4.6"
    assert metadata["last_update"] == "2026-06-14 00:40:13"
    assert metadata["first_install"] == "2026-05-08 16:33:35"
    assert metadata["installer"] == "com.android.vending"


def test_get_package_metadata_falls_back_to_pm_dump_when_dumpsys_has_no_inventory_fields(
    monkeypatch,
) -> None:
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "get", lambda _key: None)
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "set", lambda _key, _value: None)

    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=25):
        calls.append(command)
        if command[:2] == ["dumpsys", "package"]:
            return SimpleNamespace(returncode=0, stdout="Packages:\n")
        if command[:3] == ["cmd", "package", "dump-package"]:
            return SimpleNamespace(returncode=0, stdout="Activity Resolver Table:\n")
        return SimpleNamespace(
            returncode=0,
            stdout="""
            packageName=com.example.app
            userId=10234
            versionName=1.2.3
            lastUpdateTime=2026-06-14 00:40:13
            installerPackageName=com.android.vending
            """,
        )

    monkeypatch.setattr(package_info.adb_client, "run_shell_command", _run_shell_command)

    metadata = package_info.get_package_metadata("SER123", "com.example.app", refresh=True)

    assert calls == [
        ["dumpsys", "package", "--user", "0", "com.example.app"],
        ["dumpsys", "package", "com.example.app"],
        ["cmd", "package", "dump-package", "com.example.app"],
        ["pm", "dump", "com.example.app"],
    ]
    assert metadata["package_name"] == "com.example.app"
    assert metadata["user_id"] == "10234"
    assert metadata["version_name"] == "1.2.3"
    assert metadata["installer"] == "com.android.vending"


def test_get_package_metadata_normalizes_null_installer(monkeypatch) -> None:
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "get", lambda _key: None)
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "set", lambda _key, _value: None)
    monkeypatch.setattr(
        package_info.adb_client,
        "run_shell_command",
        lambda *_a, **_k: SimpleNamespace(
            returncode=0,
            stdout="""
  Package [com.example.app] (abc123):
    appId=10234
    installerPackageName=null
            """,
        ),
    )

    metadata = package_info.get_package_metadata("SER123", "com.example.app", refresh=True)

    assert metadata["installer"] is None


def test_get_package_metadata_falls_back_when_user_scoped_dumpsys_is_unsupported(
    monkeypatch,
) -> None:
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "get", lambda _key: None)
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_META_CACHE, "set", lambda _key, _value: None)

    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=25):
        calls.append(command)
        if command[:2] == ["dumpsys", "package"] and "--user" in command:
            return SimpleNamespace(returncode=0, stdout="Unknown argument: --user; use -h for help", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout="""
  Package [com.example.app] (abc123):
    appId=10234
    versionName=2.4.6
            """,
        )

    monkeypatch.setattr(package_info.adb_client, "run_shell_command", _run_shell_command)

    metadata = package_info.get_package_metadata("SER123", "com.example.app", refresh=True)

    assert calls == [
        ["dumpsys", "package", "--user", "0", "com.example.app"],
        ["dumpsys", "package", "com.example.app"],
    ]
    assert metadata["user_id"] == "10234"
    assert metadata["version_name"] == "2.4.6"


def test_get_package_paths_prefers_user_scoped_cmd_path_and_falls_back(monkeypatch) -> None:
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_PATH_CACHE, "get", lambda _key: None)
    monkeypatch.setattr(package_info.adb_cache.PACKAGE_PATH_CACHE, "set", lambda _key, _value: None)

    calls: list[list[str]] = []

    def _run_shell_command(_serial, command, timeout=15):
        calls.append(command)
        if command[:3] == ["cmd", "package", "path"]:
            return SimpleNamespace(returncode=0, stdout="Unknown option: --user", stderr="")
        if command[:2] == ["pm", "path"] and "--user" in command:
            return SimpleNamespace(returncode=0, stdout="package:/data/app/base.apk\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unsupported")

    monkeypatch.setattr(package_info.adb_client, "run_shell_command", _run_shell_command)

    paths = package_info.get_package_paths("SER123", "com.example.app", refresh=True, allow_fallbacks=False)

    assert calls == [
        ["cmd", "package", "path", "--user", "0", "com.example.app"],
        ["cmd", "package", "path", "com.example.app"],
        ["pm", "path", "--user", "0", "com.example.app"],
    ]
    assert paths == ["/data/app/base.apk"]
