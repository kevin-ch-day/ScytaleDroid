"""Unit tests for string-analysis post processing helpers."""
from __future__ import annotations

from pathlib import Path

from scytaledroid.StaticAnalysis.modules.string_analysis import IndexedString, StringIndex
from scytaledroid.StaticAnalysis.modules.string_analysis.post import NoisePolicy, load_noise_policy, summarise


def _index_for(*entries: IndexedString) -> StringIndex:
    return StringIndex(strings=entries)


def test_noise_policy_filters_documentary_hosts(tmp_path: Path) -> None:
    config = tmp_path / "noise.toml"
    config.write_text("""[hosts]\ndoc=[\"www.w3.org\"]\n""", "utf-8")
    policy = load_noise_policy(config)
    index = _index_for(
        IndexedString(value="http://www.w3.org/spec", origin="classes.dex", origin_type="code")
    )
    summary = summarise(index, noise_policy=policy)
    assert not summary.risk_relevant
    assert summary.documentary
    doc = summary.documentary[0]
    assert doc.host == "www.w3.org"
    assert "endpoint" in doc.tags


def test_endpoint_tagging_includes_graphql_and_prod() -> None:
    index = _index_for(
        IndexedString(
            value="See https://api.example.com/graphql?query=1 for data",
            origin="classes.dex",
            origin_type="code",
        )
    )
    summary = summarise(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    assert summary.risk_relevant
    obs = summary.risk_relevant[0]
    assert obs.host == "api.example.com"
    assert {"endpoint", "prod-domain", "graphql"}.issubset(set(obs.tags))
    assert obs.confidence == "high"


def test_detects_aws_pair_with_high_confidence() -> None:
    access = "AKIA1234567890ABCD12"
    secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"
    index = _index_for(
        IndexedString(value=access, origin="assets/creds.json", origin_type="asset"),
        IndexedString(
            value=f"aws_secret_access_key\":\"{secret}\"",
            origin="assets/creds.json",
            origin_type="asset",
        ),
    )
    summary = summarise(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    secrets = [obs for obs in summary.risk_relevant if obs.category == "secret"]
    assert secrets
    secret_obs = secrets[0]
    assert "aws-pair" in secret_obs.tags
    assert secret_obs.confidence == "high"
    assert secret[:4] in secret_obs.value
    assert secret[-4:] in secret_obs.value


def test_detects_authorization_jwt_token() -> None:
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    index = _index_for(
        IndexedString(
            value=f"Authorization: Bearer {token}",
            origin="classes.dex",
            origin_type="code",
        )
    )
    summary = summarise(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    tokens = [obs for obs in summary.risk_relevant if "auth-token" in obs.tags]
    assert tokens
    obs = tokens[0]
    assert obs.confidence == "high"
    assert obs.value.startswith(token[:6])
    assert obs.value.endswith(token[-4:])
    assert {"auth-token", "jwt-format", "bearer-context"}.issubset(set(obs.tags))
    assert summary.scorecard is not None
    auth_test = next(result for result in summary.scorecard.tests if result.test_id == "SNI-S102")
    assert auth_test.score >= 8.0
    assert auth_test.grade in {"E", "F", "D"}  # ensure non-passing grade


def test_base64_probe_emits_encoded_signal() -> None:
    payload = "Q29udGFjdCBodHRwOi8vZXhhbXBsZS5jb20="
    index = _index_for(
        IndexedString(value=payload, origin="assets/remote.txt", origin_type="asset"),
    )
    summary = summarise(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    encoded = [obs for obs in summary.risk_relevant if obs.category == "encoded"]
    assert encoded
    assert "encoded" in encoded[0].tags
    assert "http://example.com" in (encoded[0].decoded or "")


def test_feature_flag_remote_url_scores() -> None:
    index = _index_for(
        IndexedString(
            value='{"featureFlag":"beta","url":"http://config.example.com/toggle"}',
            origin="res/raw/config.json",
            origin_type="asset",
        )
    )
    summary = summarise(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    flags = [obs for obs in summary.risk_relevant if "feature-flag" in obs.tags]
    assert flags
    obs = flags[0]
    assert obs.host == "config.example.com"
    assert "cleartext" in obs.tags
    assert summary.scorecard is not None
    feature_test = next(result for result in summary.scorecard.tests if result.test_id == "SNI-C203")
    assert feature_test.score >= 6.0
    assert feature_test.grade in {"C", "D", "F"}


def test_scorecard_includes_cleartext_rollup() -> None:
    index = _index_for(
        IndexedString(
            value="Call http://public.example.com/api for data",
            origin="classes.dex",
            origin_type="code",
        )
    )
    summary = summarise(index, noise_policy=NoisePolicy(frozenset(), frozenset()))
    assert summary.scorecard is not None
    scorecard = summary.scorecard
    cleartext = next(result for result in scorecard.tests if result.test_id == "SNI-N001")
    assert cleartext.score > 6.0
    assert cleartext.grade in {"D", "F"}
    network_rollup = next(cat for cat in scorecard.categories if cat.category == "network")
    assert network_rollup.score == cleartext.score
    assert scorecard.final.profile == "enterprise"
