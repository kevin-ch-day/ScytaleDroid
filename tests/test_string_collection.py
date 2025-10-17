"""Tests for the string collection and normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.StaticAnalysis.cli.renderer import render_exploratory_summary
from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import NoisePolicy
from scytaledroid.StaticAnalysis.modules.string_analysis.extractor import (
    CollectionSummary,
    normalise_index,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing import (
    IndexedString,
    StringIndex,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.sources import (
    collect_file_strings,
)


@dataclass
class _FakeAPK:
    files: dict[str, bytes]

    def get_files(self) -> list[str]:
        return list(self.files)

    def get_file(self, name: str) -> bytes:
        return self.files[name]


def test_collect_file_strings_records_offsets() -> None:
    blob = b"xxx http://prod.example.com/api yyy"
    apk = _FakeAPK({"assets/config.txt": blob})
    strings = collect_file_strings(apk)
    assert strings
    record = strings[0]
    assert record.origin == "assets/config.txt"
    assert record.origin_type == "asset"
    assert record.byte_offset == 0
    assert record.pointer == "assets/config.txt@0"
    assert record.source_sha_short is not None and len(record.source_sha_short) == 8
    assert "http://prod.example.com/api" in (record.context or "")
    assert record.apk_sha256 is None
    assert record.split_id == "base"
    assert record.apk_offset_kind == "byte_offset"
    assert record.dex_id is None
    assert record.locale_qualifier is None


def test_normalise_index_produces_metrics() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="Call http://public.example.com/api for data",
                origin="classes.dex",
                origin_type="dex",
                byte_offset=12,
                source_sha256="a" * 64,
                context="Call http://public.example.com/api",
            ),
            IndexedString(
                value="http://ns.adobe.com/xap/1.0/",
                origin="res/raw/filter_resources.smf",
                origin_type="res",
                source_sha256="b" * 64,
                context="Adobe namespace",
            ),
            IndexedString(
                value="Q29udGFjdCBodHRwOi8vZXhhbXBsZS5jb20=",
                origin="assets/config.txt",
                origin_type="asset",
                byte_offset=64,
                source_sha256="c" * 64,
                context="secret base64",
            ),
        )
    )
    policy = NoisePolicy(frozenset({"ns.adobe.com"}), frozenset())
    summary: CollectionSummary = normalise_index(index, noise_policy=policy)

    assert isinstance(summary, CollectionSummary)
    assert len(summary.strings) == 3

    url_obs = next(obs for obs in summary.strings if obs.source_type == "dex")
    assert "endpoint" in url_obs.tags
    assert "cleartext" in url_obs.tags
    assert url_obs.host == "public.example.com"
    assert url_obs.value_hash.startswith("sha1:")
    assert url_obs.split_id == "base"
    assert url_obs.auth_proximity is None

    encoded = next(obs for obs in summary.strings if "encoded" in obs.tags)
    assert encoded.decoded_kind == "url"
    assert encoded.decoded and "http://example.com" in encoded.decoded
    assert encoded.decoded_len is not None
    assert encoded.decoded_hash is not None

    documentary = next(obs for obs in summary.strings if obs.source_type == "res")
    assert documentary.is_allowlisted
    assert documentary.kind == "doc_namespace"
    assert documentary.unknown_fingerprint is None

    metrics = summary.metrics
    assert metrics.strings_total == 3
    assert metrics.strings_by_source["dex"] == 1
    assert metrics.strings_by_source["asset"] == 1
    assert metrics.strings_by_split["base"] == 3
    assert metrics.base64_candidates == 1
    assert metrics.decoded_blobs_total == 1
    assert metrics.decoded_total_bytes > 0
    assert metrics.endpoints_nonlocal_http == 1
    assert metrics.doc_noise_count == 1
    assert 0 < metrics.doc_noise_ratio < 1
    assert metrics.base64_decode_failures == 0
    assert 0 <= metrics.unknown_kind_ratio <= 1
    assert metrics.splits_present == ("base",)
    assert metrics.obfuscation_hint is False
    assert metrics.issue_flags
    assert any(issue.slug == "cleartext_endpoints" for issue in metrics.issue_flags)


def test_render_exploratory_summary_outputs_samples() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="http://prod.example.com/api",
                origin="classes.dex",
                origin_type="dex",
                byte_offset=12,
                source_sha256="a" * 64,
                context="auth bearer http://prod.example.com/api",
            ),
            IndexedString(
                value="AKIA1234567890ABCD12",
                origin="assets/creds.json",
                origin_type="asset",
                byte_offset=24,
                source_sha256="b" * 64,
                context="aws_access_key_id",
            ),
            IndexedString(
                value="aws_secret_access_key\":\"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD\"",
                origin="assets/creds.json",
                origin_type="asset",
                byte_offset=40,
                source_sha256="b" * 64,
                context="aws_secret_access_key",
            ),
        )
    )
    summary = normalise_index(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    text = render_exploratory_summary("com.example.app", "1.0.0", summary)
    assert "Exploratory SNI  com.example.app 1.0.0" in text
    assert "http_nonlocal=1" in text
    assert "aws_pairs=" in text
    assert "decode_fail=0" in text
    assert "unknown_ratio=" in text
    assert "Top tags:" in text
    assert "Potential issues:" in text
    assert "[HIGH] Non-local cleartext endpoints observed" in text
    assert "Samples (evidence):" in text
    assert "classes.dex@12" in text


def _dex_piece(value: str, offset: int) -> IndexedString:
    return IndexedString(
        value=value,
        origin="classes.dex",
        origin_type="dex",
        byte_offset=offset,
        source_sha256="d" * 64,
        context=value,
    )


def test_constant_host_reconstruction_emits_derived_endpoint() -> None:
    pieces = (
        _dex_piece("https://", 0),
        _dex_piece("api.", 8),
        _dex_piece("example", 16),
        _dex_piece(".com", 24),
    )
    index = StringIndex(strings=pieces)
    summary = normalise_index(index, noise_policy=NoisePolicy(frozenset(), frozenset()))

    all_derived = [obs for obs in summary.strings if obs.derived]
    url_derived = [obs for obs in all_derived if obs.kind == "url"]
    assert url_derived, "expected at least one reconstructed URL string"
    values = {obs.value for obs in url_derived}
    assert "https://api.example.com" in values
    endpoint = next(obs for obs in url_derived if obs.value == "https://api.example.com")
    assert endpoint.host == "api.example.com"
    assert "endpoint" in endpoint.tags
    assert "prod-domain" in endpoint.tags
    assert endpoint.derived_from is not None and len(endpoint.derived_from) >= 2
    assert summary.metrics.strings_total == len(pieces) + len(all_derived)


def _junk_payload(index: int) -> IndexedString:
    value = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="  # 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return IndexedString(
        value=value,
        origin=f"assets/fail{index}.txt",
        origin_type="asset",
        byte_offset=0,
        source_sha256=f"{index:064x}",
        context=value,
    )


def test_base64_failure_metrics_and_flags() -> None:
    strings = tuple(_junk_payload(i) for i in range(10))
    index = StringIndex(strings=strings)
    summary = normalise_index(index, noise_policy=NoisePolicy(frozenset(), frozenset()))

    metrics = summary.metrics
    assert metrics.base64_candidates == len(strings)
    assert metrics.decoded_blobs_total == 0
    assert metrics.base64_decode_failures == len(strings)
    assert metrics.decoded_yield_rate == 0
    assert any(issue.slug == "base64_failures" for issue in metrics.issue_flags)
    assert any(issue.slug == "base64_low_yield" for issue in metrics.issue_flags)
    assert metrics.unknown_kind_count == len(strings)
    assert metrics.unknown_kind_ratio == 1.0

    for obs in summary.strings:
        assert obs.decoded is None
        assert obs.decoded_kind == "junk"
        assert "encoded" in obs.tags


def test_auth_proximity_records_metrics_and_issue() -> None:
    entries = (
        IndexedString(
            value="session_token",
            origin="classes.dex",
            origin_type="dex",
            byte_offset=0,
            source_sha256="e" * 64,
            context="Authorization: Bearer session_token",
        ),
        IndexedString(
            value="http://prod.example.com/api",
            origin="classes.dex",
            origin_type="dex",
            byte_offset=128,
            source_sha256="f" * 64,
            context="http://prod.example.com/api",
        ),
    )
    index = StringIndex(strings=entries)
    summary = normalise_index(index, noise_policy=NoisePolicy(frozenset(), frozenset()))

    token_obs = next(obs for obs in summary.strings if obs.value == "session_token")
    assert token_obs.auth_proximity is not None and token_obs.auth_proximity <= 32
    assert summary.metrics.auth_close_hits == 1
    assert any(issue.slug == "auth_proximity" for issue in summary.metrics.issue_flags)
