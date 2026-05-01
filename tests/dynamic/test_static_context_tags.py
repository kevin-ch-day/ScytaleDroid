from __future__ import annotations

from scytaledroid.DynamicAnalysis.core.static_context import compute_static_context


def test_compute_static_context_basic_tags() -> None:
    plan = {
        "permissions": {"declared": ["a"], "dangerous": ["b"], "high_value": ["CAMERA"]},
        "exported_components": {"total": 25},
        "risk_flags": {
            "uses_cleartext_traffic": True,
            "request_legacy_external_storage": True,
            "allow_backup": True,
        },
        "network_targets": {"domains": ["example.com"], "cleartext_domains": [], "domain_sources": []},
    }
    ctx = compute_static_context(plan)
    tags = ctx.get("tags")
    assert isinstance(tags, list)
    assert "PRIVACY_SENSITIVE" in tags
    assert "EXPORT_HEAVY" in tags
    assert "NETWORK_CLEARTEXT_ALLOWED" in tags
    assert "LEGACY_STORAGE" in tags
    assert "ALLOW_BACKUP" in tags

