from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from scytaledroid.StaticAnalysis.core.findings import Badge
from scytaledroid.StaticAnalysis.core.models import ManifestFlags
from scytaledroid.StaticAnalysis.detectors.network import NetworkSurfaceDetector
from scytaledroid.StaticAnalysis.engine.strings_detectors import _detect_endpoints
from scytaledroid.StaticAnalysis.modules.network_security.models import NetworkSecurityPolicy
from scytaledroid.StaticAnalysis.modules.string_analysis.network import extract_endpoints
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.url_tokenizer import (
    extract_candidates,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.urlsafe import (
    safe_urlsplit,
)

# =============================================================================
# Former tests/static_analysis/test_string_url_parsing.py
# =============================================================================


@pytest.mark.unit
def test_safe_urlsplit_returns_none_for_invalid_ipv6_url() -> None:
    assert safe_urlsplit("http://[::1") is None


@pytest.mark.unit
def test_detect_endpoints_skips_invalid_ipv6_url() -> None:
    assert list(_detect_endpoints("bad endpoint http://[::1")) == []


@pytest.mark.unit
def test_extract_candidates_skips_invalid_ipv6_url() -> None:
    candidates = extract_candidates("bad endpoint http://[::1")

    assert all(candidate.raw != "http://[::1" for candidate in candidates)


@pytest.mark.unit
def test_extract_endpoints_skips_invalid_ipv6_url() -> None:
    index = SimpleNamespace(
        strings=[
            SimpleNamespace(
                value="bad endpoint http://[::1",
                sha256="abc123",
            )
        ]
    )

    assert extract_endpoints(index) == ()


# =============================================================================
# Former tests/static_analysis/test_network_surface_detector.py
# =============================================================================


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
