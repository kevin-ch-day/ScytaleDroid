from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.masvs_mapper import summarise_controls
from scytaledroid.StaticAnalysis.cli.persistence.findings_writer import compute_cvss_base


# =============================================================================
# Former tests/static_analysis/test_cvss_fallback.py
# =============================================================================


def test_cvss_fallback_for_base002():
    vector, score, meta = compute_cvss_base("BASE-002")
    assert vector is not None
    assert score and score > 0
    assert meta["base"]["rule_id"] == "BASE-002"


def test_cvss_fallback_for_diff_new_permissions():
    vector, score, meta = compute_cvss_base("diff_new_permissions")
    assert vector is not None
    assert score and score > 0
    assert meta["base"]["rule_id"] == "diff_new_permissions"


# =============================================================================
# Former tests/static_analysis/test_masvs_mapper.py
# =============================================================================


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
