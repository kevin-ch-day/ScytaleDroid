from scytaledroid.DynamicAnalysis.services.evidence_scope_audit import (
    SCOPE_CLEAN,
    SCOPE_CONTAMINATED_FULL_PCAP,
    SCOPE_REVIEW,
    EvidenceScopeMetrics,
    classify_scope,
)


def test_bbc_like_scope_is_clean() -> None:
    result = classify_scope(
        EvidenceScopeMetrics(
            dynamic_run_id="bbc",
            capinfos_capture_duration_s=365.495782,
            telemetry_sampling_window_s=358.0002017650004,
            pcap_data_bytes=49_331_770,
            netstats_total_bytes=50_560_423,
        )
    )

    assert result.scope_classification == SCOPE_CLEAN
    assert result.reasons == ()


def test_instagram_like_scope_is_review_without_segment_probe() -> None:
    result = classify_scope(
        EvidenceScopeMetrics(
            dynamic_run_id="instagram",
            capinfos_capture_duration_s=866.244456,
            telemetry_sampling_window_s=504.000092023,
            pcap_data_bytes=211_310_198,
            netstats_total_bytes=60_893_475,
        )
    )

    assert result.scope_classification == SCOPE_REVIEW
    assert any("duration delta" in reason for reason in result.reasons)


def test_instagram_like_scope_is_contaminated_with_measurable_pre_scenario_slice() -> None:
    result = classify_scope(
        EvidenceScopeMetrics(
            dynamic_run_id="instagram",
            capinfos_capture_duration_s=866.244456,
            telemetry_sampling_window_s=504.000092023,
            pcap_data_bytes=211_310_198,
            netstats_total_bytes=60_893_475,
            pre_scenario_duration_s=365.0,
            pre_scenario_bytes=150_000_000,
            packet_count=184_046,
            pre_scenario_packet_count=120_000,
        )
    )

    assert result.scope_classification == SCOPE_CONTAMINATED_FULL_PCAP


def test_tiktok_like_scope_is_contaminated_with_measurable_pre_scenario_slice() -> None:
    result = classify_scope(
        EvidenceScopeMetrics(
            dynamic_run_id="tiktok",
            capinfos_capture_duration_s=726.207217,
            telemetry_sampling_window_s=452.00005331396824,
            pcap_data_bytes=203_810_963,
            netstats_total_bytes=112_675_833,
            pre_scenario_duration_s=263.4,
            pre_scenario_bytes=88_477_998,
            packet_count=168_725,
            pre_scenario_packet_count=59_903,
        )
    )

    assert result.scope_classification == SCOPE_CONTAMINATED_FULL_PCAP


def test_missing_netstats_does_not_force_review_when_timing_is_clean() -> None:
    result = classify_scope(
        EvidenceScopeMetrics(
            dynamic_run_id="missing-netstats",
            capinfos_capture_duration_s=365.0,
            telemetry_sampling_window_s=360.0,
            pcap_data_bytes=2_000_000,
        )
    )

    assert result.scope_classification == SCOPE_CLEAN
    assert "netstats_total_bytes" in result.missing_metrics

