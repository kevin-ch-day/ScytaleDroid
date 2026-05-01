from __future__ import annotations

from pathlib import Path

from scytaledroid.StaticAnalysis.modules.string_analysis.bucketing.classifier import (
    BucketDecision,
    classify,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.host_normalizer import (
    normalize_host,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.punctuation import (
    strip_wrap_punct,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.url_tokenizer import (
    Candidate,
    extract_candidates,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.policy import loader
from scytaledroid.StaticAnalysis.modules.string_analysis.policy.evaluator import (
    PolicyOutcome,
    evaluate,
)


def test_punctuation_strip():
    assert strip_wrap_punct("bouncycastle.org)") == "bouncycastle.org"
    assert strip_wrap_punct("(http://example.com,)") == "http://example.com"
    assert (
        strip_wrap_punct("http://[2001:db8::1])") == "http://[2001:db8::1]"
    )
    assert strip_wrap_punct("'(api.example.co.uk,)") == "api.example.co.uk"
    assert strip_wrap_punct("'h'") == "h"
    assert strip_wrap_punct("[2001:db8::1])") == "[2001:db8::1]"
    assert strip_wrap_punct("[2001:db8::1]:443)") == "[2001:db8::1]:443"


def test_placeholder_rejection():
    samples = [
        "https://%s",
        "http://example.com",
        "webaddress.elided",
        "http://h/path",
    ]
    for sample in samples:
        candidates = extract_candidates(sample)
        assert candidates
        decisions = [
            classify(candidate, normalize_host(candidate.host or candidate.raw))
            for candidate in candidates
        ]
        assert any(decision.placeholder for decision in decisions)


def test_host_normalization_idn():
    normalized = normalize_host("münich.example")
    assert normalized.full_host == "xn--mnich-kva.example"
    assert normalized.etld_plus_one == "xn--mnich-kva.example"


def test_host_normalization_multilevel_suffix():
    normalized = normalize_host("api.service.co.uk")
    assert normalized.full_host == "api.service.co.uk"
    assert normalized.etld_plus_one == "service.co.uk"


def test_host_normalization_ipv6_literal():
    normalized = normalize_host("[2001:db8::1]:443")
    assert normalized.full_host == "2001:db8::1"
    assert normalized.etld_plus_one is None
    assert normalized.is_ip


def test_bucket_classification_http():
    candidate = Candidate(
        raw="http://example.com/api",
        scheme="http",
        host="example.com",
        port=None,
        path="/api",
        source_offset=0,
    )
    decision = classify(candidate, normalize_host(candidate.host))
    assert decision.placeholder


def test_ipv6_with_port():
    value = "http://[2606:4700::6810:85e5]:8080/path"
    candidates = extract_candidates(value)
    assert candidates
    ipv6_candidate = next(
        candidate for candidate in candidates if candidate.host and ":" in candidate.host
    )
    assert ipv6_candidate.port == 8080
    normalized = normalize_host(ipv6_candidate.host)
    decision = classify(ipv6_candidate, normalized)
    assert "http_cleartext" in decision.buckets


def test_ws_wss_classification():
    ws_candidates = extract_candidates("ws://socket.example.com")
    wss_candidates = extract_candidates("wss://socket.example.com")
    assert ws_candidates and wss_candidates
    ws_decision = classify(ws_candidates[0], normalize_host(ws_candidates[0].host))
    wss_decision = classify(wss_candidates[0], normalize_host(wss_candidates[0].host))
    assert "endpoints" in ws_decision.buckets
    assert "http_cleartext" in ws_decision.buckets
    assert "endpoints" in wss_decision.buckets
    assert "http_cleartext" not in wss_decision.buckets


def test_policy_doc_allow(tmp_path: Path):
    policy_file = tmp_path / "noise.toml"
    policy_file.write_text(
        """
[hosts.allow_doc]
list = ["bouncycastle.org"]

[[rules]]
name = "doc-host"
[rules.when]
host_in_group = "hosts.allow_doc"
[rules.then]
action = "suppress"
        """,
        encoding="utf-8",
    )
    policy = loader.load_policy(policy_file)
    normalized = normalize_host("bouncycastle.org")
    outcome = evaluate(
        policy,
        BucketDecision(buckets=("endpoints",)),
        normalized,
        source_path="docs/reference.md",
        value="https://bouncycastle.org",
        scheme="https",
    )
    assert isinstance(outcome, PolicyOutcome)
    assert outcome.action == "suppress"