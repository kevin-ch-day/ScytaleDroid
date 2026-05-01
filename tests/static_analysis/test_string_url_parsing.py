from __future__ import annotations

from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.engine.strings_detectors import _detect_endpoints
from scytaledroid.StaticAnalysis.modules.string_analysis.network import extract_endpoints
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.url_tokenizer import (
    extract_candidates,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.urlsafe import (
    safe_urlsplit,
)


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
