from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.core.context import AnalysisConfig, SecretsSamplerConfig
from scytaledroid.StaticAnalysis.detectors.secrets import SecretsDetector
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.execution.string_analysis_payload import (
    merge_string_analysis_payloads,
)
from scytaledroid.StaticAnalysis.engine.strings import _analyse_strings_from_index
from scytaledroid.StaticAnalysis.engine.strings_detectors import (
    _classify_analytics,
    _classify_token,
    _detect_endpoints,
)
from scytaledroid.StaticAnalysis.modules.string_analysis import IndexedString, StringIndex
from scytaledroid.StaticAnalysis.modules.string_analysis import (
    correlate_static_roots_with_dynamic_indicators,
    dynamic_indicators_from_report,
)


def test_high_entropy_suppresses_script_blob_noise() -> None:
    blob = (
        '!function(e,t){if("object"==typeof exports&&"object"==typeof module)'
        'module.exports=t();else if("function"==typeof define&&define.amd)define([],t);'
        'Object.defineProperty(exports,"__esModule",{value:!0});return webpackJsonp}'
    )
    index = StringIndex(
        strings=(
            IndexedString(
                value=blob,
                origin="assets/ace.min.js",
                origin_type="asset",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
    )

    assert payload["counts"]["high_entropy"] == 0
    assert payload["extra_counts"]["entropy_suppressed_noise"] == 1
    assert payload["selected_samples"].get("high_entropy") in (None, [])


def test_high_entropy_keeps_compact_secret_shaped_token() -> None:
    token = "z9K3vT1pQ8mN4xR7cL2sH5dF6gJ0wB1yU3oP4aS5eD7fG8"
    index = StringIndex(
        strings=(
            IndexedString(
                value=token,
                origin="classes.dex",
                origin_type="code",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
    )

    assert payload["counts"]["high_entropy"] == 1
    sample = payload["selected_samples"]["high_entropy"][0]
    assert sample["value"] == token
    assert sample["source_type"] == "dex"


def test_high_entropy_keeps_code_origin_secret_on_split_member() -> None:
    token = "z9K3vT1pQ8mN4xR7cL2sH5dF6gJ0wB1yU3oP4aS5eD7fG8"
    index = StringIndex(
        strings=(
            IndexedString(
                value=token,
                origin="classes.dex",
                origin_type="code",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
        artifact_context={"is_split_member": True},
    )

    assert payload["counts"]["high_entropy"] == 1


@pytest.mark.parametrize(
    ("value", "origin"),
    [
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "lib/arm64-v8a/libArchive.so",
        ),
        (
            "_ZNK5boost4asio15system_executor8dispatchINS0_6detail7binder2"
            "INSt6__ndk16__bindIMN3lfw15Asyn_HttpClientEFvRKNS_6system10error_code",
            "lib/arm64-v8a/libbase_live.so",
        ),
        (
            "CQTZKHGJYMUWPBDEVRASONFILXp4qvh1a053s98cti27ugkrnm6_yjfbxdewozl",
            "lib/arm64-v8a/libDavinciResourceJni.so",
        ),
        (
            "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP"
            "QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"
            "abcdefghijklmnopqrstuvwxyz0123456789+/",
            "lib/arm64-v8a/libaudioeffect.so",
        ),
        (
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqK2Ehep75rRzDzJQ4YtBjsk"
            "63BccPyq04WiyORIlx3uDdfEB3J8pHbosQ1lGbWuORFk4ruoyD1CbCg4FwBbZ8RuXnW"
            "XqsTrL7okUtVrIWCOcRksnqyJ8XAXyh31gL5QnX30duywGEOoEnTtovY48UFKxQp85wV"
            "vb0bCzpgN0Jmp3Q7SORxZFVZ0DGU",
            "lib/arm64-v8a/liblynxsecurity.so",
        ),
    ],
)
def test_high_entropy_suppresses_split_native_noise(value: str, origin: str) -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value=value,
                origin=origin,
                origin_type="asset",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
        artifact_context={"is_split_member": True},
    )

    assert payload["counts"]["high_entropy"] == 0
    assert payload["extra_counts"]["entropy_suppressed_noise"] == 1


def test_split_native_exploratory_regex_work_is_skipped_without_strong_context() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="https://telemetry.example.net/pixel",
                origin="assets/pixel_manifest.bin",
                origin_type="asset",
                confidence="low",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
        artifact_context={"is_split_member": True},
    )

    assert payload["counts"]["endpoints"] == 0
    assert payload["regex_skipped"] == 1


def _secrets_context(index: StringIndex, *, is_split_member: bool):
    return SimpleNamespace(
        apk_path=Path("/tmp/example.apk"),
        string_index=index,
        metadata={"is_split_member": is_split_member},
        config=AnalysisConfig(
            profile="full",
            secrets_sampler=SecretsSamplerConfig(),
        ),
    )


def test_secrets_detector_prefilters_low_value_split_native_entries() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm",
                origin="lib/arm64-v8a/libnoise.so",
                origin_type="native",
                confidence="low",
            ),
        )
    )

    result = SecretsDetector().run(_secrets_context(index, is_split_member=True))

    assert result.findings == ()
    assert result.metrics["split_prefilter_active"] is True
    assert result.metrics["prefilter_scanned_entries"] == 1
    assert result.metrics["prefilter_skipped_entries"] == 1
    assert result.metrics["prefilter_retained_entries"] == 0


def test_secrets_detector_prefilters_split_resource_noise_without_secret_context() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value='{"feature_flag":"headline_banner","cdn":"images.example.net"}',
                origin="res/raw/feature_config.json",
                origin_type="raw",
                confidence="low",
            ),
        )
    )

    result = SecretsDetector().run(_secrets_context(index, is_split_member=True))

    assert result.findings == ()
    assert result.metrics["split_prefilter_active"] is True
    assert result.metrics["prefilter_scanned_entries"] == 1
    assert result.metrics["prefilter_skipped_entries"] == 1
    assert result.metrics["prefilter_retained_entries"] == 0


def test_secrets_detector_keeps_split_code_origin_secret_candidates() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="REDACTED_GOOGLE_API_KEY",
                origin="classes.dex",
                origin_type="code",
                context="Authorization: Bearer token GoogleSignIn OkHttp",
            ),
        )
    )

    result = SecretsDetector().run(_secrets_context(index, is_split_member=True))

    assert result.findings
    assert result.metrics["split_prefilter_active"] is False
    assert result.metrics["validated_strings"] >= 1
    google_metrics = result.metrics["secret_types"]["google_api_key"]
    assert google_metrics["candidate_entries"] == 1
    assert google_metrics["raw_regex_matches"] >= 1


def test_secrets_detector_keeps_split_raw_secret_candidates_with_embedded_key_prefix() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value='{"apiKey":"REDACTED_GOOGLE_API_KEY"}',
                origin="res/raw/firebase_config.json",
                origin_type="raw",
                confidence="low",
            ),
        )
    )

    result = SecretsDetector().run(_secrets_context(index, is_split_member=True))

    assert result.metrics["split_prefilter_active"] is False
    google_metrics = result.metrics["secret_types"]["google_api_key"]
    assert google_metrics["candidate_entries"] == 1
    assert google_metrics["raw_regex_matches"] >= 1


def test_secrets_detector_reports_candidate_churn_for_zero_match_provider_pattern() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="datadog instrumentation marker without full key",
                origin="classes.dex",
                origin_type="code",
                context="datadog upload api key",
            ),
        )
    )

    result = SecretsDetector().run(_secrets_context(index, is_split_member=False))

    datadog_metrics = result.metrics["secret_types"]["datadog_api_key"]
    assert datadog_metrics["candidate_entries"] == 1
    assert datadog_metrics["raw_regex_matches"] == 0
    assert datadog_metrics["found"] == 0
    assert datadog_metrics["accepted_after_validation"] == 0


def test_analytics_patterns_do_not_match_embedded_class_name_fragments() -> None:
    text = "afsyouthshouldcancelsubscription.AfsMessengerafsyouthshouldcancel"

    matches = list(_classify_analytics(text))

    assert matches == []


def test_placeholder_aws_secret_is_rejected() -> None:
    text = "ABCD0123456789+/wxyzABCD0123456789+/wxyzABCD0123456789+/wxyz"

    matches = list(_classify_token(text))

    assert matches == []


def test_realistic_google_api_key_still_matches() -> None:
    text = "REDACTED_GOOGLE_API_KEY"

    matches = list(_classify_token(text))

    assert matches
    assert matches[0].provider == "google"


def test_placeholder_and_regex_urls_are_not_treated_as_endpoints() -> None:
    values = (
        "http://www.example.com",
        "http://tiny.jio.com/.*$",
        "HTTP://WEBADDRESS.ELIDED",
    )

    for value in values:
        assert list(_detect_endpoints(value)) == []


def test_documentary_urls_are_not_treated_as_network_endpoints() -> None:
    values = (
        "https://github.com/TooTallNate/Java-WebSocket/wiki/Lost-connection-detection",
        "https://www.internalfb.com/intern/staticdocs/bloks/docs/bloks_standard_library/components/collection_v2",
        "https://www.theguardian.com/help/ng-interactive/2017/mar/17/contact-the-guardian-securely",
    )

    for value in values:
        assert list(_detect_endpoints(value)) == []


def test_documentary_http_urls_do_not_raise_cleartext_bucket() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="http://xmlpull.org/v1/doc/features.html#indent-output",
                origin="classes.dex",
                origin_type="code",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
    )

    assert payload["counts"]["endpoints"] == 0
    assert payload["counts"]["http_cleartext"] == 0


def test_google_key_and_google_endpoint_form_actionable_pair() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="REDACTED_GOOGLE_API_KEY",
                origin="classes.dex",
                origin_type="code",
                context="Authorization: Bearer token OkHttpClient GoogleSignIn",
            ),
            IndexedString(
                value="https://google.com/a",
                origin="classes.dex",
                origin_type="code",
                context="Retrofit.Builder baseUrl google.com",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=3,
        cleartext_only=False,
        include_https_risk=False,
        artifact_context={"package_name": "com.example.mapsapp"},
    )

    api_sample = payload["selected_samples"]["api_keys"][0]
    endpoint_sample = payload["samples"]["endpoints"][0]
    assert api_sample["api_context"] == "auth_flow"
    assert api_sample["posture"] == "actionable"
    assert api_sample["pair_group"] == "google:token_endpoint_family"
    assert api_sample["verification_status"] == "supported_opt_in"
    assert endpoint_sample["ownership_class"] == "unknown_third_party"
    assert endpoint_sample["pair_group"] == "google:token_endpoint_family"
    assert payload["aggregates"]["pair_matches"][0]["pair_group"] == "google:token_endpoint_family"
    assert payload["aggregates"]["posture_counts"]["actionable"] >= 2


def test_high_entropy_stays_exploratory_without_stronger_context() -> None:
    token = "z9K3vT1pQ8mN4xR7cL2sH5dF6gJ0wB1yU3oP4aS5eD7fG8"
    index = StringIndex(
        strings=(
            IndexedString(
                value=token,
                origin="classes.dex",
                origin_type="code",
                context="const-string v1",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
        artifact_context={"package_name": "com.example.app"},
    )

    sample = payload["selected_samples"]["high_entropy"][0]
    assert sample["posture"] == "exploratory"
    assert sample["verification_status"] in {"supported_opt_in", "unverified"}
    assert payload["aggregates"]["exploratory_strings"]


def test_documentary_and_local_strings_classify_ownership() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="file://tmp/example.txt",
                origin="classes.dex",
                origin_type="code",
            ),
            IndexedString(
                value="https://github.com/example/project/wiki/readme",
                origin="classes.dex",
                origin_type="code",
            ),
        )
    )

    payload = _analyse_strings_from_index(
        index,
        mode="both",
        min_entropy=4.8,
        max_samples=2,
        cleartext_only=False,
        include_https_risk=False,
        artifact_context={"package_name": "com.example.app"},
    )

    uri_sample = payload["selected_samples"]["uris"][0]
    assert uri_sample["ownership_class"] == "local_or_non_network"
    assert payload["counts"]["endpoints"] == 0


def test_merge_payloads_preserves_posture_and_pair_fields() -> None:
    params = RunParameters(profile="full", scope="profile", scope_label="Research Dataset Beta")
    merged = merge_string_analysis_payloads(
        [
            {
                "counts": {"api_keys": 1},
                "samples": {
                    "api_keys": [
                        {
                            "value": "REDACTED_GOOGLE_API_KEY",
                            "value_masked": "AIza…vwxy",
                            "src": "classes.dex",
                            "tag": "google_api_key",
                            "provider": "google",
                            "posture": "actionable",
                            "pair_group": "google:token_endpoint_family",
                            "verification_status": "supported_opt_in",
                            "dynamic_corroboration": "unknown",
                        }
                    ]
                },
                "selected_samples": {},
                "aggregates": {
                    "pair_matches": [
                        {
                            "pair_group": "google:token_endpoint_family",
                            "pair_type": "provider_endpoint_family",
                            "provider": "google",
                        }
                    ],
                    "actionable_strings": [
                        {
                            "bucket": "api_keys",
                            "value_masked": "AIza…vwxy",
                            "src": "classes.dex",
                            "pair_group": "google:token_endpoint_family",
                        }
                    ],
                    "exploratory_strings": [],
                },
            },
            {
                "counts": {"endpoints": 1},
                "samples": {
                    "endpoints": [
                        {
                            "value": "https://maps.googleapis.com/maps/api",
                            "src": "classes.dex",
                            "root_domain": "googleapis.com",
                            "posture": "actionable",
                            "pair_group": "google:token_endpoint_family",
                        }
                    ]
                },
                "selected_samples": {},
                "aggregates": {"pair_matches": [], "actionable_strings": [], "exploratory_strings": []},
            },
        ],
        params=params,
    )

    api_sample = merged["samples"]["api_keys"][0]
    endpoint_sample = merged["samples"]["endpoints"][0]
    assert api_sample["posture"] == "actionable"
    assert endpoint_sample["pair_group"] == "google:token_endpoint_family"
    assert merged["aggregates"]["pair_matches"][0]["pair_group"] == "google:token_endpoint_family"


def test_dynamic_correlation_helpers_match_static_and_dynamic_domains() -> None:
    report = {
        "top_dns": [{"value": "api.example.com", "count": 3}],
        "top_sni": [{"value": "cdn.example.com", "count": 2}],
    }
    indicators = dynamic_indicators_from_report(report)
    result = correlate_static_roots_with_dynamic_indicators(
        static_roots=["api.example.com", "other.example.com"],
        dynamic_indicators=indicators,
    )

    assert result["status"] == "matched"
    assert result["matched_roots"] == ["api.example.com"]
