"""Tests for network helpers used during string analysis."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.string_analysis.indexing import (
    IndexedString,
    StringIndex,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.network import (
    detect_tls_keywords,
    extract_endpoints,
)


def _index(*values: IndexedString) -> StringIndex:
    return StringIndex(strings=values)


def test_extract_endpoints_filters_scheme_and_deduplicates() -> None:
    entry_http = IndexedString(
        value="Visit http://api.example.com/login and http://api.example.com/logout",
        origin="classes.dex",
        origin_type="dex",
    )
    entry_https = IndexedString(
        value="https://secure.example.com/auth",
        origin="res/raw/strings.xml",
        origin_type="res",
    )
    entry_other = IndexedString(
        value="ftp://files.example.com/archive",
        origin="assets/config.txt",
        origin_type="asset",
    )

    matches = extract_endpoints(_index(entry_http, entry_https, entry_other))

    urls = {match.url for match in matches}
    hosts = {match.host for match in matches}

    assert "http://api.example.com/login" in urls
    assert "https://secure.example.com/auth" in urls
    assert all(host.endswith("example.com") for host in hosts)
    # The FTP endpoint should be ignored entirely.
    assert all("ftp://" not in url for url in urls)
    # Duplicate HTTP matches within the same string are deduplicated by scheme+hash.
    assert len([match for match in matches if match.scheme == "http"]) == 1


def test_detect_tls_keywords_groups_unique_matches() -> None:
    entry = IndexedString(
        value="trustmanager hostnameverifier certificatepinner",
        origin="classes.dex",
        origin_type="dex",
    )
    # Duplicate values should be ignored thanks to hash-based de-duplication.
    duplicate = IndexedString(
        value="trustmanager hostnameverifier certificatepinner",
        origin="classes2.dex",
        origin_type="dex",
    )

    groups = detect_tls_keywords(_index(entry, duplicate))

    assert set(groups) == {
        "trust_manager",
        "hostname_verifier",
        "certificate_pinning",
    }
    assert len(groups["trust_manager"]) == 1
    assert len(groups["hostname_verifier"]) == 1
    assert len(groups["certificate_pinning"]) == 1
