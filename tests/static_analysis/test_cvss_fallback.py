from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence.findings_writer import compute_cvss_base


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
