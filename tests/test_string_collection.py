"""Tests for the string collection and normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.renderer import render_exploratory_summary
from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (
    DEFAULT_POLICY_ROOT,
    NoisePolicy,
    load_noise_policy,
)
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


def test_noise_policy_matches_registrable_root() -> None:
    policy = NoisePolicy(frozenset({"adobe.com"}), frozenset())
    assert policy.is_documentary_host("adobe.com") is True
    assert policy.is_documentary_host("ns.adobe.com") is True
    assert policy.is_documentary_host("files.adobe.com") is True
    assert policy.is_documentary_host("example.com") is False


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
    policy = NoisePolicy(frozenset({"adobe.com"}), frozenset())
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
    assert metrics.effective_http == 1
    assert metrics.effective_https == 0
    assert metrics.placeholders_dropped == 0
    assert metrics.suppressed_doc_host == 0
    assert metrics.suppressed_doc_cdn == 0
    assert metrics.downgraded_placeholder == 0
    assert metrics.annotated_fragment == 0
    assert metrics.ipv6_seen == 0
    assert metrics.ws_seen == 0
    assert metrics.wss_seen == 0
    assert metrics.https_seen == 0


def test_policy_rules_from_config_apply() -> None:
    policy = load_noise_policy(DEFAULT_POLICY_ROOT)
    index = StringIndex(
        strings=(
            IndexedString(
                value="http://schemas.android.com/tools",
                origin="res/raw/app_keep.xml",
                origin_type="res",
                source_sha256="d" * 64,
                context="http://schemas.android.com/tools",
            ),
        )
    )

    summary = normalise_index(index, noise_policy=policy)
    assert len(summary.strings) == 1
    record = summary.strings[0]
    assert record.is_allowlisted is True
    assert record.policy_action == "suppress"
    assert record.policy_rule == "suppress-doc-hosts"
    assert record.policy_reason == "policy_drift:doc_reference_host"


def test_policy_downgrades_placeholder_hosts() -> None:
    policy = load_noise_policy(DEFAULT_POLICY_ROOT)
    index = StringIndex(
        strings=(
            IndexedString(
                value="http://localhost/internal",
                origin="assets/config.json",
                origin_type="asset",
                source_sha256="e" * 64,
                context="http://localhost/internal",
            ),
        )
    )

    summary = normalise_index(index, noise_policy=policy)
    record = summary.strings[0]
    assert record.policy_action == "downgrade"
    assert record.policy_tag == "dev_placeholder_host"
    assert record.policy_severity == "info"
    assert record.is_allowlisted is False
    assert summary.metrics.downgraded_placeholder == 1
    assert summary.metrics.placeholders_dropped == 1


def test_policy_respects_host_key_for_full_host(tmp_path: Path) -> None:
    config_file = tmp_path / "policy.toml"
    config_file.write_text(
        """
[hosts.allow_cdn_doc]
list = ["fonts.googleapis.com"]

[[rules]]
name = "suppress-fonts"
when.buckets_any = ["endpoints"]
when.host_in_group = "hosts.allow_cdn_doc"
when.host_key = "full_host"
then.action = "suppress"
then.reason = "policy_drift:doc_cdn_in_asset"
""".strip()
    )

    policy = load_noise_policy(config_file)
    index = StringIndex(
        strings=(
            IndexedString(
                value="http://fonts.googleapis.com/css?family=Roboto",
                origin="assets/compose.css",
                origin_type="asset",
                source_sha256="f" * 64,
                context="http://fonts.googleapis.com/css?family=Roboto",
            ),
            IndexedString(
                value="http://api.googleapis.com/service",
                origin="assets/config.json",
                origin_type="asset",
                source_sha256="a" * 64,
                context="http://api.googleapis.com/service",
            ),
        )
    )

    summary = normalise_index(index, noise_policy=policy)
    assert len(summary.strings) == 2
    actions = {record.value: record.policy_action for record in summary.strings}
    assert actions["http://fonts.googleapis.com/css?family=Roboto"] == "suppress"
    assert actions["http://api.googleapis.com/service"] is None
    assert summary.metrics.suppressed_doc_cdn == 1
    assert summary.metrics.suppressed_doc_host == 0


def test_doc_cdn_source_path_normalization() -> None:
    policy = load_noise_policy(DEFAULT_POLICY_ROOT)
    index = StringIndex(
        strings=(
            IndexedString(
                value="https://fonts.googleapis.com/css?family=Roboto",
                origin="assets\\legal.html",
                origin_type="asset",
                source_sha256="1" * 64,
                context="https://fonts.googleapis.com/css?family=Roboto",
            ),
            IndexedString(
                value="https://fonts.googleapis.com/css?family=Roboto",
                origin="assets/readme.txt",
                origin_type="asset",
                source_sha256="2" * 64,
                context="https://fonts.googleapis.com/css?family=Roboto",
            ),
        )
    )

    summary = normalise_index(index, noise_policy=policy)
    records = {record.source_path: record for record in summary.strings}
    doc_record = records["assets\\legal.html"]
    assert doc_record.is_allowlisted
    assert doc_record.policy_action == "suppress"
    non_doc = records["assets/readme.txt"]
    assert not non_doc.is_allowlisted
    assert summary.metrics.suppressed_doc_cdn == 1
    assert summary.metrics.suppressed_doc_http == 0


def test_policy_loads_from_directory(tmp_path: Path) -> None:
    doc_cfg = tmp_path / "01-doc.toml"
    doc_cfg.write_text(
        """
[hosts.allow_doc]
list = ["docs.example.com"]
""".strip()
    )
    placeholder_cfg = tmp_path / "02-placeholders.toml"
    placeholder_cfg.write_text(
        """
[placeholders.hosts_exact]
list = ["dev.local"]
""".strip()
    )

    policy = load_noise_policy(tmp_path)
    assert policy.is_documentary_host("docs.example.com")
    assert policy.is_documentary_host("api.docs.example.com")
    group = policy.host_groups.get("placeholders.hosts_exact")
    assert group is not None
    assert "dev.local" in group.full_hosts


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
    assert "effective_http=1" in text
    assert "doc_host_suppr=" in text
    assert "aws_pairs=" in text
    assert "decode_fail=0" in text
    assert "unknown_ratio=" in text
    assert "Top tags:" in text
    assert "Potential issues:" in text
    assert "[HIGH] Non-local cleartext endpoints observed" in text
    assert "Samples (evidence):" in text
    assert "classes.dex@12" in text


def test_http_only_risk_switch() -> None:
    policy = NoisePolicy(frozenset(), frozenset())
    index = StringIndex(
        strings=(
            IndexedString(
                value="https://secure.example.com/api",
                origin="classes.dex",
                origin_type="dex",
                byte_offset=12,
                source_sha256="f" * 64,
                context="https://secure.example.com/api",
            ),
        )
    )
    summary_default = normalise_index(index, noise_policy=policy)
    assert summary_default.metrics.endpoints_nonlocal_http == 0
    assert summary_default.metrics.effective_https == 1
    assert summary_default.metrics.https_seen == 1

    summary_https = normalise_index(
        index,
        noise_policy=policy,
        include_https_for_risk=True,
    )
    assert summary_https.metrics.endpoints_nonlocal_http == 1
    assert summary_https.metrics.effective_https == 1
    assert summary_https.metrics.https_seen == 1


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


def test_protocol_counters_capture_ipv6_and_websockets() -> None:
    policy = NoisePolicy(frozenset(), frozenset())
    index = StringIndex(
        strings=(
            IndexedString(
                value="http://[2001:db8::1]:8080/api",
                origin="classes.dex",
                origin_type="dex",
                byte_offset=4,
                source_sha256="f" * 64,
                context="http://[2001:db8::1]:8080/api",
            ),
            IndexedString(
                value="ws://socket.example.com",
                origin="classes.dex",
                origin_type="dex",
                byte_offset=8,
                source_sha256="1" * 64,
                context="ws://socket.example.com",
            ),
            IndexedString(
                value="wss://socket.example.com",
                origin="classes.dex",
                origin_type="dex",
                byte_offset=12,
                source_sha256="2" * 64,
                context="wss://socket.example.com",
            ),
        )
    )
    summary = normalise_index(index, noise_policy=policy)
    metrics = summary.metrics
    assert metrics.ipv6_seen == 1
    assert metrics.ws_seen == 1
    assert metrics.wss_seen == 1
    assert metrics.ws_cleartext >= 1

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
