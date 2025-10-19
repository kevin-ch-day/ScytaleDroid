"""Tests for the public aggregate helpers exposed by string analysis."""

from __future__ import annotations

from collections import Counter, defaultdict

from scytaledroid.StaticAnalysis.modules.string_analysis.aggregates import (
    build_aggregates,
    summarise_api_keys,
    summarise_cleartext_hits,
    summarise_endpoint_roots,
    summarise_entropy,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.hit_record import StringHit


def _hit(**overrides: object) -> StringHit:
    base = dict(
        bucket="endpoints",
        value="http://api.example.com/login",
        src="classes.dex",
        tag="cleartext",
        sha256="a" * 64,
        masked=None,
        finding_type="cleartext_endpoint",
        provider=None,
        risk_tag="prod-domain",
        confidence="high",
        scheme="http",
        root_domain="api.example.com",
        resource_name=None,
        source_type="dex",
        sample_hash="deadbeef",
    )
    base.update(overrides)
    return StringHit(**base)  # type: ignore[arg-type]


def test_summarise_cleartext_hits_deduplicates_by_value_and_source() -> None:
    hits = [
        _hit(value="http://api.example.com/login", src="classes.dex"),
        _hit(value="http://api.example.com/login", src="classes.dex"),
        _hit(value="http://api.example.com/login", src="other.dex"),
    ]

    payload = summarise_cleartext_hits(hits)

    assert len(payload) == 2
    values = {(entry["value"], entry["src"]) for entry in payload}
    assert ("http://api.example.com/login", "classes.dex") in values
    assert ("http://api.example.com/login", "other.dex") in values


def test_summarise_api_keys_masks_high_confidence_values() -> None:
    hits = [
        _hit(
            bucket="api_keys",
            value="AKIA0123456789ABCDE",
            masked="AKIA…BCDE",
            tag="aws",
            provider="aws",
        ),
        _hit(
            bucket="api_keys",
            value="public-demo-key",
            masked="public-demo-key",
            tag="demo",
            provider="demo",
            confidence="low",
        ),
    ]

    payload = summarise_api_keys(hits)

    assert len(payload) == 1
    entry = payload[0]
    assert entry["provider"] == "aws"
    assert entry["masked"] == "AKIA…BCDE"


def test_summarise_endpoint_roots_orders_by_total_hits() -> None:
    endpoint_by_root = {
        "api.example.com": Counter({"https": 2, "http": 1}),
        "cdn.example.com": Counter({"https": 1}),
    }

    rows = summarise_endpoint_roots(endpoint_by_root)

    assert rows[0]["root_domain"] == "api.example.com"
    assert rows[0]["total"] == 3
    assert rows[1]["root_domain"] == "cdn.example.com"


def test_summarise_entropy_limits_output_size() -> None:
    hits = [_hit(bucket="entropy", value=f"token-{idx}") for idx in range(12)]

    rows = summarise_entropy(hits, limit=5)

    assert len(rows) == 5
    assert all("masked" in entry for entry in rows)


def test_build_aggregates_collects_all_sections() -> None:
    endpoint_totals = Counter({"api.example.com": 3})
    endpoint_by_root = {"api.example.com": Counter({"https": 2, "http": 1})}
    domain_sources = {"api.example.com": {"dex"}}
    endpoint_cleartext = [_hit()]
    api_key_hits = [_hit(bucket="api_keys", tag="github", provider="github", masked="ghp_…1234")]
    cloud_hits = [(_hit(bucket="cloud", tag="s3", provider="aws", resource_name="bucket"), "us-east-1")]
    analytics_vendor_ids = defaultdict(lambda: defaultdict(set))
    analytics_vendor_ids["firebase"]["classes.dex"].add("project-id")
    entropy_high_samples = [_hit(bucket="entropy", value="secret-value")]

    aggregates = build_aggregates(
        endpoint_totals=endpoint_totals,
        endpoint_by_root=endpoint_by_root,
        domain_sources=domain_sources,
        endpoint_cleartext=endpoint_cleartext,
        api_key_hits=api_key_hits,
        cloud_hits=cloud_hits,
        analytics_vendor_ids=analytics_vendor_ids,
        entropy_high_samples=entropy_high_samples,
    )

    assert set(aggregates) == {
        "endpoint_totals",
        "endpoint_roots",
        "endpoint_cleartext",
        "api_keys_high",
        "cloud_refs",
        "analytics_ids",
        "entropy_high_samples",
    }
    assert aggregates["endpoint_totals"]["api.example.com"] == 3
    assert aggregates["api_keys_high"][0]["provider"] == "github"
    assert aggregates["cloud_refs"][0]["region"] == "us-east-1"
