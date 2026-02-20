from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.core.findings import Badge
from scytaledroid.StaticAnalysis.core.models import ManifestFlags
from scytaledroid.StaticAnalysis.detectors.network import NetworkSurfaceDetector
from scytaledroid.StaticAnalysis.modules.network_security.models import NetworkSecurityPolicy


def test_network_surface_empty_index_passes_has_code_http_false() -> None:
    detector = NetworkSurfaceDetector()
    context = SimpleNamespace(
        apk_path=Path("dummy.apk"),
        string_index=None,
        manifest_flags=ManifestFlags(
            uses_cleartext_traffic=True,
            network_security_config="res/xml/network_security_config.xml",
        ),
        network_security_policy=NetworkSecurityPolicy(
            source_path="res/xml/network_security_config.xml",
            base_cleartext=True,
            debug_overrides_cleartext=None,
            trust_user_certificates=True,
            domain_policies=tuple(),
            base_trust_anchors=tuple(),
            raw_xml_hash=None,
        ),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.INFO
    assert result.metrics.get("error") is None
    assert any(f.finding_id == "network_nsc_user_certs" for f in result.findings)
    assert not any(
        f.finding_id in {"network_nsc_base_cleartext", "network_nsc_domain_cleartext"}
        for f in result.findings
    )
