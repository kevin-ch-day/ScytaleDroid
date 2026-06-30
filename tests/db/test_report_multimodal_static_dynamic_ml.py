from __future__ import annotations

from scripts.db import report_multimodal_static_dynamic_ml as report


def test_report_multimodal_static_dynamic_ml_help_is_safe(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/report_multimodal_static_dynamic_ml.py")
    assert "Read-only fused static + dynamic + PCAP analysis" in out
    assert "--recompute-exact-tls" in out


def test_fused_run_fieldnames_include_static_and_dynamic_surfaces() -> None:
    fields = report.fused_run_fieldnames()
    assert "dynamic_run_id" in fields
    assert "static_match_mode" in fields
    assert "matched_static_surface_run_id" in fields
    assert "permission_audit_score_capped" in fields
    assert "static_risk_load" in fields
    assert "unique_ja4_count" in fields
    assert "service_families_observed" in fields


def test_choose_static_surface_prefers_exact_then_package_latest() -> None:
    by_package = {
        "com.example.app": {"package_name": "com.example.app", "static_run_id": 101},
    }
    by_package_static_run = {
        ("com.example.app", 101): {"package_name": "com.example.app", "static_run_id": 101},
    }
    feature_row = {"package_name": "com.example.app", "static_run_id": 101}
    matched, mode = report._choose_static_surface(feature_row, by_package, by_package_static_run)
    assert matched is not None
    assert mode == "exact_latest"

    fallback_row = {"package_name": "com.example.app", "static_run_id": 999}
    matched, mode = report._choose_static_surface(fallback_row, by_package, by_package_static_run)
    assert matched is not None
    assert mode == "package_latest_fallback"

    missing_row = {"package_name": "com.example.missing", "static_run_id": 999}
    matched, mode = report._choose_static_surface(missing_row, by_package, by_package_static_run)
    assert matched is None
    assert mode == "missing_static_surface"


def test_build_fused_run_rows_derives_third_party_share_and_matched_static_id() -> None:
    feature_rows = [
        {
            "dynamic_run_id": "run-1",
            "package_name": "com.example.app",
            "app_label": "Example",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "technical_validity_state": "TECH_VALID",
            "interaction_mode": "baseline",
            "run_profile": "baseline_idle",
            "static_run_id": 101,
            "pcap_bytes": 1000,
            "packet_count": 10,
            "duration_s": 60.0,
            "bytes_per_second": 20.0,
            "packets_per_second": 1.0,
            "domain_count": 10,
            "first_party_domain_count": 3,
            "third_party_domain_count": 6,
            "unresolved_domain_count": 1,
            "unique_service_families": 2,
            "unique_ja4_count": 3,
            "top1_ja4_share": 0.5,
            "adtech_share": 0.2,
            "service_families_observed": "publisher, analytics",
        }
    ]
    static_rows = [
        {
            "package_name": "com.example.app",
            "app_label": "Example",
            "category": "User",
            "profile_key": "NEWS",
            "profile_label": "News",
            "static_run_id": 101,
            "permission_audit_grade": None,
            "permission_audit_score_capped": None,
            "static_high": 1.0,
            "static_med": 2.0,
            "static_low": 3.0,
            "static_info": 1.0,
            "permission_run_grade": "A",
            "permission_run_score": 0.2,
            "permission_run_dangerous_count": 1,
            "permission_run_signature_count": 0,
            "permission_run_vendor_count": 0,
            "canonical_findings_total": 7.0,
        }
    ]
    rows = report._build_fused_run_rows(feature_rows, static_rows)
    assert rows[0]["matched_static_surface_run_id"] == 101
    assert rows[0]["third_party_share"] == 0.6
    assert rows[0]["permission_audit_grade"] == "A"
    assert rows[0]["permission_audit_score_capped"] == 0.2


def test_spearman_rho_and_quadrants_cover_expected_cases() -> None:
    assert abs(float(report._spearman_rho([1.0, 2.0, 3.0], [2.0, 4.0, 6.0]) or 0.0) - 1.0) < 1e-9
    neg = report._spearman_rho([1.0, 2.0, 3.0], [6.0, 4.0, 2.0])
    assert abs(float(neg or 0.0) + 1.0) < 1e-9
    ci_low, ci_high = report._bootstrap_spearman_ci([1.0, 2.0, 3.0, 4.0], [2.0, 4.0, 6.0, 8.0], n_resamples=200)
    assert ci_low is not None
    assert ci_high is not None
    assert ci_low <= ci_high
    perm_p = report._spearman_permutation_p_value([1.0, 2.0, 3.0, 4.0], [2.0, 4.0, 6.0, 8.0], n_resamples=200)
    assert perm_p is not None
    assert 0.0 <= perm_p <= 1.0
    assert report._assign_quadrant(1.0, 1.0, static_cut=0.0, runtime_cut=0.0) == "high_static_high_runtime"
    assert report._assign_quadrant(1.0, -1.0, static_cut=0.0, runtime_cut=0.0) == "high_static_low_runtime"
    assert report._assign_quadrant(-1.0, 1.0, static_cut=0.0, runtime_cut=0.0) == "low_static_high_runtime"
    assert report._assign_quadrant(-1.0, -1.0, static_cut=0.0, runtime_cut=0.0) == "low_static_low_runtime"


def test_build_fused_app_rollups_computes_scores_and_priority() -> None:
    fused_rows = [
        {
            "package_name": "com.heavy.app",
            "app_label": "Heavy App",
            "profile_key": "SOCIAL",
            "profile_label": "Social",
            "category": "User",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "baseline",
            "static_match_mode": "exact_latest",
            "static_run_id": 1,
            "permission_audit_grade": "D",
            "permission_audit_score_capped": 8.0,
            "permission_run_grade": "D",
            "permission_run_score": 7.0,
            "static_high": 12.0,
            "static_med": 60.0,
            "static_low": 10.0,
            "static_info": 2.0,
            "static_findings_total": 84.0,
            "static_risk_load": 166.5,
            "domain_count": 20,
            "unique_service_families": 5,
            "unique_ja4_count": 9,
            "third_party_share": 0.7,
            "adtech_share": 0.4,
            "top1_ja4_share": 0.35,
            "pcap_bytes": 5_000_000,
            "packets_per_second": 120.0,
            "service_families_observed": "social_platform, analytics, adtech",
        },
        {
            "package_name": "com.heavy.app",
            "app_label": "Heavy App",
            "profile_key": "SOCIAL",
            "profile_label": "Social",
            "category": "User",
            "stats_eligible": 1,
            "countable": 0,
            "quota_state": "SUPPLEMENTAL_VALID",
            "interaction_mode": "manual",
            "static_match_mode": "exact_latest",
            "static_run_id": 1,
            "permission_audit_grade": "D",
            "permission_audit_score_capped": 8.0,
            "permission_run_grade": "D",
            "permission_run_score": 7.0,
            "static_high": 12.0,
            "static_med": 60.0,
            "static_low": 10.0,
            "static_info": 2.0,
            "static_findings_total": 84.0,
            "static_risk_load": 166.5,
            "domain_count": 24,
            "unique_service_families": 6,
            "unique_ja4_count": 11,
            "third_party_share": 0.8,
            "adtech_share": 0.5,
            "top1_ja4_share": 0.30,
            "pcap_bytes": 6_000_000,
            "packets_per_second": 130.0,
            "service_families_observed": "social_platform, analytics, adtech, cdn",
        },
        {
            "package_name": "com.light.app",
            "app_label": "Light App",
            "profile_key": "NEWS",
            "profile_label": "News",
            "category": "User",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "baseline",
            "static_match_mode": "exact_latest",
            "static_run_id": 2,
            "permission_audit_grade": "A",
            "permission_audit_score_capped": 0.5,
            "permission_run_grade": "A",
            "permission_run_score": 0.2,
            "static_high": 1.0,
            "static_med": 8.0,
            "static_low": 3.0,
            "static_info": 1.0,
            "static_findings_total": 13.0,
            "static_risk_load": 20.25,
            "domain_count": 4,
            "unique_service_families": 1,
            "unique_ja4_count": 2,
            "third_party_share": 0.1,
            "adtech_share": 0.0,
            "top1_ja4_share": 0.9,
            "pcap_bytes": 300_000,
            "packets_per_second": 12.0,
            "service_families_observed": "publisher",
        },
        {
            "package_name": "com.light.app",
            "app_label": "Light App",
            "profile_key": "NEWS",
            "profile_label": "News",
            "category": "User",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "manual",
            "static_match_mode": "exact_latest",
            "static_run_id": 2,
            "permission_audit_grade": "A",
            "permission_audit_score_capped": 0.5,
            "permission_run_grade": "A",
            "permission_run_score": 0.2,
            "static_high": 1.0,
            "static_med": 8.0,
            "static_low": 3.0,
            "static_info": 1.0,
            "static_findings_total": 13.0,
            "static_risk_load": 20.25,
            "domain_count": 5,
            "unique_service_families": 1,
            "unique_ja4_count": 2,
            "third_party_share": 0.15,
            "adtech_share": 0.0,
            "top1_ja4_share": 0.85,
            "pcap_bytes": 320_000,
            "packets_per_second": 10.0,
            "service_families_observed": "publisher",
        },
    ]

    rollups = report._build_fused_app_rollups(fused_rows)
    assert len(rollups) == 2
    by_pkg = {row["package_name"]: row for row in rollups}
    assert by_pkg["com.heavy.app"]["sample_scope"] == "all_governed"
    assert by_pkg["com.heavy.app"]["sample_hygiene"] == "strict_exact_only"
    assert by_pkg["com.heavy.app"]["exact_match_fraction"] == 1.0
    assert by_pkg["com.heavy.app"]["priority_band"] == "high"
    assert by_pkg["com.heavy.app"]["risk_behavior_quadrant"] == "high_static_high_runtime"
    assert by_pkg["com.light.app"]["risk_behavior_quadrant"] == "low_static_low_runtime"
    assert by_pkg["com.heavy.app"]["fused_pressure_score"] is not None
    assert by_pkg["com.heavy.app"]["service_families_observed"].startswith("adtech")


def test_build_priority_rows_preserves_priority_band() -> None:
    rows = report._build_priority_rows(
        [
            {
                "app_label": "Example",
                "package_name": "com.example",
                "priority_band": "high",
                "fused_pressure_score": 1.2,
                "static_risk_score": 0.8,
                "runtime_breadth_score": 0.6,
                "risk_behavior_quadrant": "high_static_high_runtime",
                "permission_audit_grade": "C",
                "static_findings_total": 10.0,
                "median_unique_ja4_count": 5.0,
                "median_domain_count": 7.0,
                "median_third_party_share": 0.5,
                "median_adtech_share": 0.2,
                "interpretation": "high static pressure with broad runtime behavior",
            }
        ]
    )
    assert rows[0]["priority_band"] == "high"


def test_bootstrap_priority_stability_returns_probabilities_and_intervals() -> None:
    fused_rows = [
        {
            "package_name": "pkg.high",
            "app_label": "High",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "baseline",
            "matched_static_surface_run_id": 1,
            "static_run_id": 1,
            "permission_audit_grade": "D",
            "permission_audit_score_capped": 8.0,
            "permission_run_grade": "D",
            "permission_run_score": 7.5,
            "static_high": 12.0,
            "static_med": 80.0,
            "static_low": 10.0,
            "static_info": 2.0,
            "static_findings_total": 104.0,
            "static_risk_load": 210.0,
            "domain_count": 20,
            "unique_service_families": 6,
            "unique_ja4_count": 10,
            "third_party_share": 0.7,
            "adtech_share": 0.4,
            "top1_ja4_share": 0.25,
            "pcap_bytes": 4_000_000,
            "packets_per_second": 20.0,
            "service_families_observed": "adtech, analytics, publisher",
        },
        {
            "package_name": "pkg.high",
            "app_label": "High",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "manual",
            "matched_static_surface_run_id": 1,
            "static_run_id": 1,
            "permission_audit_grade": "D",
            "permission_audit_score_capped": 8.0,
            "permission_run_grade": "D",
            "permission_run_score": 7.5,
            "static_high": 12.0,
            "static_med": 80.0,
            "static_low": 10.0,
            "static_info": 2.0,
            "static_findings_total": 104.0,
            "static_risk_load": 210.0,
            "domain_count": 22,
            "unique_service_families": 7,
            "unique_ja4_count": 11,
            "third_party_share": 0.75,
            "adtech_share": 0.5,
            "top1_ja4_share": 0.2,
            "pcap_bytes": 4_500_000,
            "packets_per_second": 22.0,
            "service_families_observed": "adtech, analytics, publisher, cdn",
        },
        {
            "package_name": "pkg.low",
            "app_label": "Low",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "baseline",
            "matched_static_surface_run_id": 2,
            "static_run_id": 2,
            "permission_audit_grade": "A",
            "permission_audit_score_capped": 0.2,
            "permission_run_grade": "A",
            "permission_run_score": 0.2,
            "static_high": 1.0,
            "static_med": 6.0,
            "static_low": 2.0,
            "static_info": 1.0,
            "static_findings_total": 9.0,
            "static_risk_load": 17.25,
            "domain_count": 4,
            "unique_service_families": 1,
            "unique_ja4_count": 2,
            "third_party_share": 0.1,
            "adtech_share": 0.0,
            "top1_ja4_share": 0.9,
            "pcap_bytes": 200_000,
            "packets_per_second": 5.0,
            "service_families_observed": "publisher",
        },
        {
            "package_name": "pkg.low",
            "app_label": "Low",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "manual",
            "matched_static_surface_run_id": 2,
            "static_run_id": 2,
            "permission_audit_grade": "A",
            "permission_audit_score_capped": 0.2,
            "permission_run_grade": "A",
            "permission_run_score": 0.2,
            "static_high": 1.0,
            "static_med": 6.0,
            "static_low": 2.0,
            "static_info": 1.0,
            "static_findings_total": 9.0,
            "static_risk_load": 17.25,
            "domain_count": 5,
            "unique_service_families": 1,
            "unique_ja4_count": 2,
            "third_party_share": 0.15,
            "adtech_share": 0.0,
            "top1_ja4_share": 0.85,
            "pcap_bytes": 220_000,
            "packets_per_second": 4.5,
            "service_families_observed": "publisher",
        },
    ]
    rollups = report._build_fused_app_rollups(fused_rows)
    priority_rows = report._build_priority_rows(rollups)
    stability = report._bootstrap_priority_stability(fused_rows, priority_rows, sample_scope="all_governed", n_resamples=100)
    assert len(stability) == 2
    first = stability[0]
    assert first["sample_scope"] == "all_governed"
    assert 0.0 <= float(first["top1_probability"]) <= 1.0
    assert 0.0 <= float(first["top3_probability"]) <= 1.0
    assert 0.0 <= float(first["high_priority_probability"]) <= 1.0
    assert first["rank_ci_low"] is not None
    assert first["rank_ci_high"] is not None


def test_build_correlation_rows_sorts_strongest_first() -> None:
    app_rollups = [
        {
            "permission_audit_score_capped": 1.0,
            "permission_run_score": 1.0,
            "static_risk_load": 5.0,
            "static_findings_total": 8.0,
            "static_high": 1.0,
            "median_domain_count": 2.0,
            "median_unique_service_families": 1.0,
            "median_unique_ja4_count": 1.0,
            "median_third_party_share": 0.1,
            "median_adtech_share": 0.0,
            "runtime_breadth_score": -1.0,
            "median_top1_ja4_share": 0.9,
        },
        {
            "permission_audit_score_capped": 3.0,
            "permission_run_score": 2.0,
            "static_risk_load": 15.0,
            "static_findings_total": 18.0,
            "static_high": 4.0,
            "median_domain_count": 5.0,
            "median_unique_service_families": 2.0,
            "median_unique_ja4_count": 2.0,
            "median_third_party_share": 0.3,
            "median_adtech_share": 0.1,
            "runtime_breadth_score": 0.0,
            "median_top1_ja4_share": 0.7,
        },
        {
            "permission_audit_score_capped": 5.0,
            "permission_run_score": 4.0,
            "static_risk_load": 25.0,
            "static_findings_total": 30.0,
            "static_high": 9.0,
            "median_domain_count": 9.0,
            "median_unique_service_families": 4.0,
            "median_unique_ja4_count": 5.0,
            "median_third_party_share": 0.6,
            "median_adtech_share": 0.3,
            "runtime_breadth_score": 1.0,
            "median_top1_ja4_share": 0.4,
        },
        {
            "permission_audit_score_capped": 7.0,
            "permission_run_score": 6.0,
            "static_risk_load": 35.0,
            "static_findings_total": 42.0,
            "static_high": 11.0,
            "median_domain_count": 12.0,
            "median_unique_service_families": 5.0,
            "median_unique_ja4_count": 6.0,
            "median_third_party_share": 0.75,
            "median_adtech_share": 0.45,
            "runtime_breadth_score": 1.4,
            "median_top1_ja4_share": 0.25,
        },
    ]
    rows = report._build_correlation_rows(app_rollups)
    assert rows
    assert rows[0]["spearman_rho"] is not None
    assert rows[0]["rho_bootstrap_ci_low"] is not None
    assert rows[0]["rho_bootstrap_ci_high"] is not None
    assert rows[0]["permutation_p_value"] is not None
    assert rows[0]["stability_note"] != ""
    assert abs(float(rows[0]["spearman_rho"])) >= abs(float(rows[-1]["spearman_rho"] or 0.0))


def test_nearest_centroid_loocv_separates_simple_profile_classes() -> None:
    rows = [
        {
            "package_name": "news.a",
            "app_label": "News A",
            "profile_key": "NEWS",
            "permission_audit_score_capped": 0.1,
            "permission_run_score": 0.1,
            "static_risk_load": 10.0,
            "static_findings_total": 12.0,
            "median_domain_count": 20.0,
            "median_unique_service_families": 8.0,
            "median_unique_ja4_count": 10.0,
            "median_third_party_share": 0.8,
            "median_adtech_share": 0.4,
            "median_top1_ja4_share": 0.3,
            "median_pcap_bytes": 4_000_000.0,
            "median_packets_per_second": 12.0,
        },
        {
            "package_name": "news.b",
            "app_label": "News B",
            "profile_key": "NEWS",
            "permission_audit_score_capped": 0.2,
            "permission_run_score": 0.2,
            "static_risk_load": 12.0,
            "static_findings_total": 15.0,
            "median_domain_count": 18.0,
            "median_unique_service_families": 7.0,
            "median_unique_ja4_count": 9.0,
            "median_third_party_share": 0.7,
            "median_adtech_share": 0.3,
            "median_top1_ja4_share": 0.35,
            "median_pcap_bytes": 4_200_000.0,
            "median_packets_per_second": 11.0,
        },
        {
            "package_name": "social.a",
            "app_label": "Social A",
            "profile_key": "SOCIAL",
            "permission_audit_score_capped": 6.0,
            "permission_run_score": 5.8,
            "static_risk_load": 220.0,
            "static_findings_total": 120.0,
            "median_domain_count": 7.0,
            "median_unique_service_families": 2.0,
            "median_unique_ja4_count": 4.0,
            "median_third_party_share": 0.2,
            "median_adtech_share": 0.0,
            "median_top1_ja4_share": 0.7,
            "median_pcap_bytes": 900_000.0,
            "median_packets_per_second": 5.0,
        },
        {
            "package_name": "social.b",
            "app_label": "Social B",
            "profile_key": "SOCIAL",
            "permission_audit_score_capped": 5.5,
            "permission_run_score": 5.6,
            "static_risk_load": 210.0,
            "static_findings_total": 110.0,
            "median_domain_count": 8.0,
            "median_unique_service_families": 2.0,
            "median_unique_ja4_count": 5.0,
            "median_third_party_share": 0.25,
            "median_adtech_share": 0.0,
            "median_top1_ja4_share": 0.65,
            "median_pcap_bytes": 950_000.0,
            "median_packets_per_second": 4.0,
        },
    ]
    predictions, summary = report._nearest_centroid_loocv(
        rows,
        label_field="profile_key",
        target_name="profile_key_fused",
        features=report.FUSED_MODEL_FEATURES,
        feature_set_name="fused_static_runtime",
        note="test note",
    )
    assert len(predictions) == 4
    assert summary["accuracy"] is not None
    assert float(summary["accuracy"]) >= 0.75
    assert summary["accuracy_ci_low"] is not None
    assert summary["accuracy_ci_high"] is not None
    assert summary["feature_set"] == "fused_static_runtime"
    assert predictions[0]["feature_set"] == "fused_static_runtime"


def test_build_classification_outputs_emits_targets_and_feature_scores() -> None:
    rows = [
        {
            "app_label": "App 1",
            "package_name": "pkg.1",
            "profile_key": "NEWS",
            "permission_audit_grade": "A",
            "permission_audit_score_capped": 0.2,
            "permission_run_score": 0.2,
            "static_risk_load": 20.0,
            "static_findings_total": 20.0,
            "median_domain_count": 15.0,
            "median_unique_service_families": 5.0,
            "median_unique_ja4_count": 7.0,
            "median_third_party_share": 0.7,
            "median_adtech_share": 0.3,
            "median_top1_ja4_share": 0.4,
            "median_pcap_bytes": 4_000_000.0,
            "median_packets_per_second": 10.0,
        },
        {
            "app_label": "App 2",
            "package_name": "pkg.2",
            "profile_key": "NEWS",
            "permission_audit_grade": "A",
            "permission_audit_score_capped": 0.3,
            "permission_run_score": 0.3,
            "static_risk_load": 25.0,
            "static_findings_total": 25.0,
            "median_domain_count": 14.0,
            "median_unique_service_families": 5.0,
            "median_unique_ja4_count": 8.0,
            "median_third_party_share": 0.6,
            "median_adtech_share": 0.2,
            "median_top1_ja4_share": 0.45,
            "median_pcap_bytes": 4_100_000.0,
            "median_packets_per_second": 11.0,
        },
        {
            "app_label": "App 3",
            "package_name": "pkg.3",
            "profile_key": "SOCIAL",
            "permission_audit_grade": "D",
            "permission_audit_score_capped": 6.5,
            "permission_run_score": 6.0,
            "static_risk_load": 220.0,
            "static_findings_total": 150.0,
            "median_domain_count": 6.0,
            "median_unique_service_families": 2.0,
            "median_unique_ja4_count": 4.0,
            "median_third_party_share": 0.2,
            "median_adtech_share": 0.0,
            "median_top1_ja4_share": 0.7,
            "median_pcap_bytes": 1_000_000.0,
            "median_packets_per_second": 4.0,
        },
        {
            "app_label": "App 4",
            "package_name": "pkg.4",
            "profile_key": "SOCIAL",
            "permission_audit_grade": "D",
            "permission_audit_score_capped": 6.2,
            "permission_run_score": 5.9,
            "static_risk_load": 205.0,
            "static_findings_total": 145.0,
            "median_domain_count": 7.0,
            "median_unique_service_families": 2.0,
            "median_unique_ja4_count": 5.0,
            "median_third_party_share": 0.25,
            "median_adtech_share": 0.0,
            "median_top1_ja4_share": 0.68,
            "median_pcap_bytes": 980_000.0,
            "median_packets_per_second": 4.5,
        },
    ]
    summaries, predictions, feature_scores = report._build_classification_outputs(rows)
    assert {row["target"] for row in summaries} == {
        "profile_key_fused",
        "profile_key_runtime_only",
        "risk_bucket_runtime_only",
    }
    assert predictions
    assert feature_scores
    assert any(row["feature_name"] == "static_risk_load" for row in feature_scores)
    assert any(row["feature_set"] == "runtime_only" for row in summaries)
    assert all("accuracy_ci_low" in row for row in summaries)
    assert all("accuracy_ci_high" in row for row in summaries)


def test_build_strict_exact_app_rollups_filters_fallback_rows() -> None:
    fused_rows = [
        {
            "package_name": "pkg.mixed",
            "app_label": "Mixed",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "baseline",
            "static_match_mode": "exact_latest",
            "matched_static_surface_run_id": 1,
            "static_run_id": 1,
            "permission_audit_grade": "C",
            "permission_audit_score_capped": 4.0,
            "permission_run_grade": "C",
            "permission_run_score": 4.0,
            "static_high": 1.0,
            "static_med": 10.0,
            "static_low": 2.0,
            "static_info": 1.0,
            "static_findings_total": 13.0,
            "static_risk_load": 24.25,
            "domain_count": 5,
            "unique_service_families": 2,
            "unique_ja4_count": 3,
            "third_party_share": 0.4,
            "adtech_share": 0.1,
            "top1_ja4_share": 0.6,
            "pcap_bytes": 1000,
            "packets_per_second": 1.0,
            "service_families_observed": "publisher, analytics",
        },
        {
            "package_name": "pkg.mixed",
            "app_label": "Mixed",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "manual",
            "static_match_mode": "package_latest_fallback",
            "matched_static_surface_run_id": 2,
            "static_run_id": 2,
            "permission_audit_grade": "C",
            "permission_audit_score_capped": 4.0,
            "permission_run_grade": "C",
            "permission_run_score": 4.0,
            "static_high": 1.0,
            "static_med": 10.0,
            "static_low": 2.0,
            "static_info": 1.0,
            "static_findings_total": 13.0,
            "static_risk_load": 24.25,
            "domain_count": 8,
            "unique_service_families": 3,
            "unique_ja4_count": 4,
            "third_party_share": 0.6,
            "adtech_share": 0.2,
            "top1_ja4_share": 0.5,
            "pcap_bytes": 1200,
            "packets_per_second": 2.0,
            "service_families_observed": "publisher, analytics, adtech",
        },
    ]
    strict_rollups = report._build_strict_exact_app_rollups(fused_rows)
    assert len(strict_rollups) == 1
    row = strict_rollups[0]
    assert row["sample_scope"] == "strict_exact"
    assert row["runs_total"] == 1
    assert row["exact_match_runs"] == 1
    assert row["fallback_runs"] == 0
    assert row["sample_hygiene"] == "strict_exact_only"


def test_build_sample_hygiene_rows_and_fallback_details_flag_recapture() -> None:
    fused_rows = [
        {
            "dynamic_run_id": "run-1",
            "package_name": "pkg.fallback",
            "app_label": "Fallback App",
            "stats_eligible": 1,
            "countable": 1,
            "quota_state": "QUOTA_VALID",
            "interaction_mode": "baseline",
            "run_profile": "baseline_idle",
            "static_match_mode": "package_latest_fallback",
            "matched_static_surface_run_id": 77,
            "static_run_id": 42,
        },
        {
            "dynamic_run_id": "run-2",
            "package_name": "pkg.fallback",
            "app_label": "Fallback App",
            "stats_eligible": 1,
            "countable": 0,
            "quota_state": "SUPPLEMENTAL_VALID",
            "interaction_mode": "manual",
            "run_profile": "interaction_manual",
            "static_match_mode": "package_latest_fallback",
            "matched_static_surface_run_id": 77,
            "static_run_id": 42,
        },
    ]
    sample_rows = report._build_sample_hygiene_rows(fused_rows)
    assert len(sample_rows) == 1
    row = sample_rows[0]
    assert row["sample_hygiene"] == "fallback_only"
    assert row["recapture_needed"] == "yes"
    assert row["observed_dynamic_static_run_ids"] == "42"
    assert row["latest_static_surface_run_id"] == 77
    assert report._sample_hygiene_state(sample_rows) == "strict_exact_absent"

    fallback_rows = report._build_fallback_detail_rows(fused_rows)
    assert len(fallback_rows) == 2
    assert fallback_rows[0]["recommendation"] == "refresh runtime/static alignment before exact-fusion claims"
    assert report._fused_claim_posture("strict_exact_absent") == "descriptive_fallback_only"


def test_findings_markdown_includes_alignment_gap_section_when_recapture_needed() -> None:
    summary = {
        "fused_runs": 2,
        "stats_eligible_fused_runs": 2,
        "apps_with_fused_rollups": 1,
        "exact_static_matches": 0,
        "package_latest_static_fallbacks": 2,
        "strict_exact_apps_with_rollups": 0,
        "fused_claim_posture": "descriptive_fallback_only",
    }
    markdown = report._build_findings_markdown(
        summary,
        app_rollups=[],
        strict_exact_rollups=[],
        sample_hygiene_rows=[
            {
                "app_label": "Fallback App",
                "stats_eligible_runs": 2,
                "exact_match_runs": 0,
                "fallback_runs": 2,
                "observed_dynamic_static_run_ids": "42",
                "latest_static_surface_run_id": 77,
                "recapture_needed": "yes",
                "recommendation": "capture or reindex runtime evidence against the newest static surface before paper-grade fusion",
            }
        ],
        correlations=[],
        priority_rows=[],
        priority_stability_rows=[],
        classification_rows=[],
        feature_scores=[],
    )
    assert "## Current Sample Warning" in markdown
    assert "## Static / Runtime Alignment Gaps" in markdown
    assert "Fallback App" in markdown
    assert "Fused claim posture: descriptive_fallback_only" in markdown
