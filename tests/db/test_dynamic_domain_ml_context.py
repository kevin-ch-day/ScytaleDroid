from __future__ import annotations

from scripts.db import report_dynamic_domain_ml_context as report


def test_destination_class_groups_ad_verification_as_measurement() -> None:
    assert (
        report.destination_class(
            "third_party",
            "ad_verification",
            {"privacy"},
        )
        == "third_party_ad_or_measurement_destination"
    )
    assert (
        report.destination_class(
            "third_party",
            "subscription_paywall",
            {"privacy"},
        )
        == "third_party_subscription_or_paywall_destination"
    )


def test_data_activity_class_and_privacy_relevance_for_common_domain_roles() -> None:
    assert (
        report.data_activity_class(
            "publisher_collection",
            "publisher",
            {"first_party_content"},
        )
        == "analytics_or_audience_collection"
    )
    assert (
        report.data_activity_class(
            "device_fingerprinting",
            "security_or_bot_defense",
            {"security_abuse_prevention"},
        )
        == "security_or_abuse_prevention"
    )
    assert (
        report.data_activity_class(
            "subscription_paywall",
            "subscription_paywall",
            {"publisher_monetization"},
        )
        == "subscription_paywall_or_customer_journey"
    )
    assert report.privacy_relevance({"privacy"}, {"advertising"}, "adtech") == "high"
    assert report.privacy_relevance(set(), set(), "subscription_paywall") == "high"
    assert (
        report.privacy_relevance({"context"}, {"infrastructure"}, "platform_infrastructure")
        == "low"
    )


def test_package_ml_readiness_flags_unmapped_and_low_confidence_rows() -> None:
    ready, caveat = report._ml_readiness(
        [
            {"service_key": "google_ads", "confidence": "high"},
            {"service_key": "cnn_first_party", "confidence": "medium"},
        ]
    )
    assert ready == "ready"
    assert "no low-confidence" in caveat

    review, review_caveat = report._ml_readiness([{"service_key": "", "confidence": "medium"}])
    assert review == "review"
    assert "lack service mapping" in review_caveat

    low_ready, low_caveat = report._ml_readiness(
        [{"service_key": "wbd_streaming_platform", "confidence": "low"}]
    )
    assert low_ready == "usable_with_review"
    assert "low-confidence" in low_caveat
