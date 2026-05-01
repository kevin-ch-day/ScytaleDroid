from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.masvs_mapper import summarise_controls


def test_masvs_mapper_includes_provider_diff_rules():
    summary = summarise_controls([
        ("BASE-002", {"evidence": "provider"}),
        ("diff_exported_services", {"details": "new service"}),
    ])
    assert "PLATFORM-IPC-1" in summary
    assert summary["PLATFORM-IPC-1"].status == "FAIL"


def test_masvs_mapper_handles_privacy_and_network_diff_rules():
    summary = summarise_controls([
        ("diff_new_permissions", {"permissions": ["android.permission.CAMERA"]}),
        ("diff_flag_usesCleartextTraffic", {"flag": "usesCleartextTraffic"}),
    ])
    assert "PRIVACY-1" in summary
    assert summary["PRIVACY-1"].status == "FAIL"
    assert "NETWORK-1" in summary
    assert summary["NETWORK-1"].status == "FAIL"
