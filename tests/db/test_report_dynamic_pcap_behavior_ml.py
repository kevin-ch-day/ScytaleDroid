from __future__ import annotations

from scripts.db import report_dynamic_pcap_behavior_ml as report


def test_report_dynamic_pcap_behavior_ml_help_is_safe(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_dynamic_pcap_behavior_ml.py")
    assert "Read-only behavioral analysis over dynamic PCAP-derived features." in out
    assert "--recompute-exact-tls" in out


def test_run_feature_matrix_fieldnames_include_expected_headers() -> None:
    fields = report.run_feature_matrix_fieldnames()
    assert "dynamic_run_id" in fields
    assert "package_name" in fields
    assert "unique_ja4_count" in fields
    assert "top_ja4" in fields
    assert "service_entropy" in fields
    assert "service_families_observed" in fields
    assert "top_alpn" in fields
    assert "unresolved_share" in fields


def test_comparison_depth_and_readiness_labels_cover_expected_states() -> None:
    assert report._comparison_depth_label(baseline_runs=3, interactive_runs=3) == "tested"
    assert report._comparison_depth_label(baseline_runs=2, interactive_runs=2) == "limited"
    assert report._comparison_depth_label(baseline_runs=1, interactive_runs=1) == "descriptive_only"
    assert report._comparison_depth_label(baseline_runs=3, interactive_runs=0) == "no_interactive_comparison"
    assert report._inference_readiness_label(baseline_runs=3, interactive_runs=3, strongest_p_value=0.04) == "paper_ready_signal"
    assert report._inference_readiness_label(baseline_runs=3, interactive_runs=3, strongest_p_value=0.30) == "tested_but_inconclusive"
    assert report._inference_readiness_label(baseline_runs=2, interactive_runs=2, strongest_p_value=None) == "limited_comparison"
    assert report._inference_readiness_label(baseline_runs=3, interactive_runs=0, strongest_p_value=None) == "needs_interactive_depth"


def test_entropy_and_cliffs_delta_handle_edge_cases() -> None:
    assert report._entropy_from_counter({}) is None
    assert report._entropy_from_counter({"only": 5}) == 0.0
    delta = report._cliffs_delta([3.0, 4.0], [1.0, 2.0])
    assert delta == 1.0
    assert report._cliffs_delta_band(delta) == "large"
    p_value = report._exact_permutation_p_value_for_median_delta([10.0, 11.0], [1.0, 2.0])
    assert p_value is not None
    assert 0.0 <= p_value <= 1.0


def test_build_app_rollups_classifies_stable_vs_interaction_broadened() -> None:
    by_package = {
        "com.whatsapp": [
            {
                "package_name": "com.whatsapp",
                "app_label": "WhatsApp",
                "stats_eligible": 1,
                "countable": 1,
                "quota_state": "QUOTA_VALID",
                "interaction_mode": "baseline",
                "unique_ja4_count": 1,
                "unique_ja3_count": 1,
                "unique_ja3s_count": 1,
                "top1_ja4_share": 1.0,
                "service_families_observed": "social_platform",
                "top_service_family": "social_platform",
                "domain_count": 2,
                "unique_service_families": 1,
                "pcap_bytes": 1000,
                "adtech_share": 0.0,
                "unresolved_share": 0.0,
            },
            {
                "package_name": "com.whatsapp",
                "app_label": "WhatsApp",
                "stats_eligible": 1,
                "countable": 1,
                "quota_state": "QUOTA_VALID",
                "interaction_mode": "baseline",
                "unique_ja4_count": 1,
                "unique_ja3_count": 1,
                "unique_ja3s_count": 1,
                "top1_ja4_share": 1.0,
                "service_families_observed": "social_platform",
                "top_service_family": "social_platform",
                "domain_count": 2,
                "unique_service_families": 1,
                "pcap_bytes": 1100,
                "adtech_share": 0.0,
                "unresolved_share": 0.0,
            },
            {
                "package_name": "com.whatsapp",
                "app_label": "WhatsApp",
                "stats_eligible": 1,
                "countable": 0,
                "quota_state": "SUPPLEMENTAL_VALID",
                "interaction_mode": "manual",
                "unique_ja4_count": 4,
                "unique_ja3_count": 4,
                "unique_ja3s_count": 2,
                "top1_ja4_share": 0.6,
                "service_families_observed": "social_platform, messaging",
                "top_service_family": "social_platform",
                "domain_count": 8,
                "unique_service_families": 2,
                "pcap_bytes": 9000,
                "adtech_share": 0.0,
                "unresolved_share": 0.0,
            },
            {
                "package_name": "com.whatsapp",
                "app_label": "WhatsApp",
                "stats_eligible": 1,
                "countable": 0,
                "quota_state": "SUPPLEMENTAL_VALID",
                "interaction_mode": "manual",
                "unique_ja4_count": 5,
                "unique_ja3_count": 5,
                "unique_ja3s_count": 2,
                "top1_ja4_share": 0.5,
                "service_families_observed": "social_platform, messaging",
                "top_service_family": "social_platform",
                "domain_count": 9,
                "unique_service_families": 2,
                "pcap_bytes": 9100,
                "adtech_share": 0.0,
                "unresolved_share": 0.0,
            },
        ]
    }

    app_rollups, baseline_vs_interactive, paper_rows, app_vectors, _ = report._build_app_rollups(by_package)

    assert len(app_rollups) == 1
    rollup = app_rollups[0]
    assert rollup["interpretation"] == "interaction-broadened"
    assert rollup["baseline_stability"] == 1.0
    assert rollup["interactive_broadening"] == 4.5
    assert any(row["metric"] == "unique_ja4_count" for row in baseline_vs_interactive)
    ja4_compare = next(row for row in baseline_vs_interactive if row["metric"] == "unique_ja4_count")
    assert ja4_compare["comparison_status"] == "ok"
    assert ja4_compare["permutation_p_value"] is not None
    assert ja4_compare["cliffs_delta_band"] in {"medium", "large"}
    assert ja4_compare["inference_note"].startswith(("permutation_signal_", "no_clear_permutation_signal_"))
    assert paper_rows[0]["app"] == "WhatsApp"
    assert app_vectors[0]["package_name"] == "com.whatsapp"
    assert rollup["service_families_observed"] == "social_platform, messaging"
    assert rollup["comparison_depth"] == "limited"
    assert rollup["inference_readiness"] == "limited_comparison"
    assert rollup["strongest_shift_metric"] != ""


def test_build_cross_app_metric_summary_counts_shift_directions() -> None:
    rows = [
        {
            "metric": "unique_ja4_count",
            "baseline_n": 3,
            "interactive_n": 3,
            "delta_median": 1.5,
            "cliffs_delta": 0.58,
            "cliffs_delta_band": "large",
            "permutation_p_value": 0.08,
        },
        {
            "metric": "unique_ja4_count",
            "baseline_n": 3,
            "interactive_n": 3,
            "delta_median": -0.5,
            "cliffs_delta": -0.20,
            "cliffs_delta_band": "small",
            "permutation_p_value": 0.40,
        },
        {
            "metric": "domain_count",
            "baseline_n": 1,
            "interactive_n": 1,
            "delta_median": 0.0,
            "cliffs_delta": None,
            "cliffs_delta_band": "",
            "permutation_p_value": None,
        },
    ]
    summary = report._build_cross_app_metric_summary(rows)
    ja4 = next(row for row in summary if row["metric"] == "unique_ja4_count")
    assert ja4["apps_compared"] == 2
    assert ja4["apps_positive_delta"] == 1
    assert ja4["apps_negative_delta"] == 1
    assert ja4["apps_p_le_0_10"] == 1
    assert ja4["apps_large_effect"] == 1


def test_build_app_rollups_skips_packages_without_stats_eligible_runs() -> None:
    by_package = {
        "com.example.empty": [
            {
                "package_name": "com.example.empty",
                "app_label": "Empty App",
                "stats_eligible": 0,
                "countable": 0,
                "quota_state": "TECH_INVALID",
                "interaction_mode": "baseline",
            }
        ],
        "com.example.good": [
            {
                "package_name": "com.example.good",
                "app_label": "Good App",
                "stats_eligible": 1,
                "countable": 1,
                "quota_state": "QUOTA_VALID",
                "interaction_mode": "baseline",
                "unique_ja4_count": 3,
                "unique_ja3_count": 2,
                "unique_ja3s_count": 1,
                "top1_ja4_share": 0.7,
                "service_families_observed": "analytics, publisher",
                "top_service_family": "publisher",
                "domain_count": 4,
                "unique_service_families": 2,
                "pcap_bytes": 1000,
                "adtech_share": 0.0,
                "unresolved_share": 0.0,
            }
        ],
    }

    app_rollups, baseline_vs_interactive, paper_rows, app_vectors, _ = report._build_app_rollups(by_package)

    assert [row["package_name"] for row in app_rollups] == ["com.example.good"]
    assert [row["package_name"] for row in baseline_vs_interactive] == ["com.example.good"] * len(baseline_vs_interactive)
    assert [row["app"] for row in paper_rows] == ["Good App"]
    assert [row["package_name"] for row in app_vectors] == ["com.example.good"]
