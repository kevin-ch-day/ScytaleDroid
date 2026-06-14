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

