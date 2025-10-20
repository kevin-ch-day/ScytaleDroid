from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.renderer import _build_modernization_guidance
from scytaledroid.StaticAnalysis.core.models import ManifestFlags


def test_guidance_includes_legacy_storage_message():
    report = SimpleNamespace(manifest_flags=ManifestFlags(request_legacy_external_storage=True))
    guidance = _build_modernization_guidance(report, {})
    combined = "\n".join(guidance)
    assert "requestLegacyExternalStorage" in combined
    assert "scoped storage" in combined


def test_guidance_recommends_removing_cleartext_when_unused():
    report = SimpleNamespace(manifest_flags=ManifestFlags(uses_cleartext_traffic=True))
    guidance = _build_modernization_guidance(report, {"aggregates": {}})
    combined = "\n".join(guidance)
    assert "usesCleartextTraffic" in combined
    assert "remove" in combined.lower()


def test_guidance_provides_network_security_config_template():
    flags = ManifestFlags(uses_cleartext_traffic=True)
    report = SimpleNamespace(manifest_flags=flags)
    string_payload = {
        "aggregates": {
            "endpoint_roots": [
                {"root_domain": "api.example.com", "schemes": {"http": 3, "https": 10}},
                {"root_domain": "cdn.example.com", "schemes": {"https": 5}},
            ]
        }
    }
    guidance = _build_modernization_guidance(report, string_payload)
    combined = "\n".join(guidance)
    assert "network_security_config.xml" in combined
    assert "api.example.com" in combined
    assert "@xml/network_security_config" in combined
