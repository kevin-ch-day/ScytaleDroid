from __future__ import annotations

from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context


def test_summarize_pcap_service_context_resolves_services_and_signals() -> None:
    report = {
        "top_dns": [
            {"value": "collector.cdp.cnn.com", "count": 6},
            {"value": "combine.urbanairship.com", "count": 4},
        ],
        "top_sni": [
            {"value": "pagead2.googlesyndication.com", "count": 5},
            {"value": "media.cnn.com", "count": 3},
        ],
    }

    bundle = summarize_pcap_service_context(report, package_name="com.cnn.mobile.android.phone")
    service_context = bundle["service_context"]
    service_signals = bundle["service_signals"]

    assert service_context["status"] == "ok"
    assert service_context["service_count"] >= 3
    assert service_context["owner_class_hit_counts"]["first_party"] >= 9
    assert service_context["owner_class_hit_counts"]["third_party"] >= 9

    service_keys = [row["service_key"] for row in service_context["services"]]
    assert "cnn_first_party" in service_keys
    assert "urbanairship" in service_keys
    assert "google_ads" in service_keys

    assert service_signals["status"] == "ok"
    signal_keys = [row["signal_key"] for row in service_signals["signals"]]
    assert "first_party_publisher_api" in signal_keys
    assert "push_or_engagement_platform" in signal_keys
    assert "third_party_advertising" in signal_keys
    assert service_signals["focus_area_hit_counts"]["privacy"] >= 9


def test_summarize_pcap_service_context_returns_no_observations_when_empty() -> None:
    bundle = summarize_pcap_service_context({}, package_name="bbc.mobile.news.ww")
    assert bundle["service_context"]["status"] == "no_observations"
    assert bundle["service_signals"]["status"] == "no_observations"


def test_summarize_pcap_service_context_maps_whatsapp_platform_signal() -> None:
    report = {
        "top_dns": [
            {"value": "g.whatsapp.net", "count": 2},
        ],
        "top_sni": [],
    }

    bundle = summarize_pcap_service_context(report, package_name="com.whatsapp")
    service_signals = bundle["service_signals"]

    assert service_signals["status"] == "ok"
    signal_keys = [row["signal_key"] for row in service_signals["signals"]]
    assert "first_party_social_platform" in signal_keys
