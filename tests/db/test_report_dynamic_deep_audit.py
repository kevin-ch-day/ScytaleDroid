from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_deep_audit as report
from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core.models import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_deep_audit.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "deep audit over dynamic evidence quality" in out


def test_quality_tier_boundaries() -> None:
    assert report._quality_tier(100) == "A+"
    assert report._quality_tier(95) == "A+"
    assert report._quality_tier(94) == "A"
    assert report._quality_tier(90) == "A"
    assert report._quality_tier(89) == "B+"
    assert report._quality_tier(85) == "B+"
    assert report._quality_tier(84) == "B"
    assert report._quality_tier(80) == "B"
    assert report._quality_tier(79) == "C+"
    assert report._quality_tier(70) == "C+"
    assert report._quality_tier(69) == "C"
    assert report._quality_tier(60) == "C"
    assert report._quality_tier(59) == "D"
    assert report._quality_tier(40) == "D"
    assert report._quality_tier(39) == "F"
    assert report._quality_tier(0) == "F"


def test_scripted_recommendation_precedes_static_enrichment_gap() -> None:
    top_gap = report._top_gap_for_app(
        baseline_valid_count=3,
        manual_valid_count=2,
        pcap_failure_count=0,
        static_endpoint_inventory_status="missing",
        static_plan_enriched=False,
        unresolved_service_total=0,
        provider_authority_status="join_gap",
        scripted_phase_available=False,
        template_label="news",
    )
    assert top_gap == "needs_scripted_validation"

    recommendation = report._recommend_for_app(
        package="bbc.mobile.news.ww",
        app_label="BBC News",
        join_row={},
        metrics={
            "valid_run_count": 5,
            "baseline_valid_count": 3,
            "manual_valid_count": 2,
            "scripted_valid_count": 0,
            "pcap_failure_count": 0,
            "unresolved_service_total": 0,
            "static_endpoint_inventory_status": "missing",
            "static_plan_enriched": False,
            "scripted_phase_available": False,
        },
    )
    assert recommendation["recommended_run_intent"] == "scripted_interaction"
    assert recommendation["recommended_template"] == "news_reader_basic_v1"
    assert recommendation["evidence_source"] == "phase_coverage_audit"


def _run(
    *,
    run_id: str,
    package: str,
    app_label: str,
    run_profile: str,
    interaction_mode: str,
    valid_pack: bool,
    pcap_present: bool = True,
    pcap_size_bytes: int = 125_000,
    pcap_failure_detail: str = "",
    netstats_observed_bytes: int = 2_000_000,
    unresolved_service_count: int = 0,
    unresolved_signal_count: int = 0,
    service_count: int = 2,
    signal_count: int = 2,
    timeline_available: bool = False,
    timeline_complete: bool = False,
    template_id: str | None = None,
    enriched_domains: bool = True,
    actionable_domains: int = 1,
    corroborated_actionable_domains: int = 1,
    report_status: str = "ok",
    protocol_compliance: str = "compliant",
    static_plan: bool = True,
    capture_ratio: float = 0.98,
    max_gap_s: float = 1.0,
    visibility_loss_flag: bool = False,
    unresolved_domains: list[dict[str, object]] | None = None,
    dynamic_domains: set[str] | None = None,
    service_rows_override: list[dict[str, object]] | None = None,
    signal_rows_override: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    unresolved_domains = unresolved_domains or []
    service_rows_value = service_rows_override or [{"service_key": "first_party_api", "owner_class": "first_party", "total_hits": 5}] * service_count
    signal_rows_value = signal_rows_override or [{"signal_key": "first_party_platform"}] * signal_count
    dynamic_domains_value = dynamic_domains or {"example.com"}
    phase_status = "transport_only" if timeline_available and pcap_present else "timeline_only" if timeline_available else "not_applicable"
    phase_action = "phase_service_attribution_not_supported" if timeline_available and pcap_present else "recollect_capture" if timeline_available else "none"
    return {
        "run_id": run_id,
        "package": package,
        "app_label": app_label,
        "run_profile": run_profile,
        "interaction_mode": interaction_mode,
        "evidence_status": "valid" if valid_pack else "invalid",
        "valid_pack": valid_pack,
        "report": {
            "report_status": report_status,
            "protocol_hierarchy": [{"protocol": "tcp", "frames": 10}],
            "tls_quic_visibility": {"quic_candidate_packets": 0, "tls_visible": True},
        },
        "features": {"proxies": {"privacy_signal_hits": signal_count}},
        "summary_payload": {},
        "manifest": {"observers": [{"status": "ok"}]},
        "dataset": {"protocol_compliance": protocol_compliance, "min_pcap_bytes": 50_000},
        "operator": {
            "actual_duration_s": 240,
            "script_timing_within_tolerance": True,
        },
        "plan": {"static_features": {"permissions_total": 4}} if static_plan else {},
        "pcap_info": {
            "pcap_present": pcap_present,
            "pcap_size_bytes": pcap_size_bytes,
            "pcap_failure_detail": pcap_failure_detail,
            "capinfos_parsed": pcap_present,
            "tshark_ok": pcap_present and report_status == "ok",
            "report_present": True,
        },
        "telemetry": {
            "netstats_available": True,
            "netstats_observed_bytes": netstats_observed_bytes,
            "netstats_rows": 10,
            "netstats_missing_rows": 0,
            "capture_ratio": capture_ratio,
            "max_gap_s": max_gap_s,
            "network_signal_quality": "strong",
        },
        "pcap_netstats_consistency": "consistent"
        if pcap_present and netstats_observed_bytes > 0
        else "netstats_seen_but_pcap_missing",
        "service_context": {
            "observed_domain_count": service_count + unresolved_service_count,
            "service_count": service_count,
            "unresolved_domain_count": unresolved_service_count,
            "services": service_rows_value,
            "unresolved_domains": unresolved_domains,
        },
        "service_signals": {
            "signal_count": signal_count,
            "services_without_signal_mappings": ["unmapped_service"] * unresolved_signal_count,
            "signals": signal_rows_value,
        },
        "service_rows": service_rows_value,
        "signal_rows": signal_rows_value,
        "unresolved_service_count": unresolved_service_count,
        "unresolved_signal_count": unresolved_signal_count,
        "service_count": service_count,
        "signal_count": signal_count,
        "dynamic_domains": dynamic_domains_value,
        "visibility_loss_flag": visibility_loss_flag,
        "http_observed": False,
        "corroboration": {
            "overlap_report_present": True,
            "enriched_domain_metadata_present": enriched_domains,
            "actionable_static_domain_rows": actionable_domains,
            "corroborated_actionable_domains": corroborated_actionable_domains,
        },
        "phase": report.RunPhaseCoverage(
            template_id=template_id,
            timeline_available=timeline_available,
            timeline_complete=timeline_complete,
            phase_count=6 if timeline_available else 0,
            transport_phase_rows=6 if timeline_available and pcap_present else 0,
            phase_attribution_status=phase_status,
            recommended_action=phase_action,
        ),
        "template_id": template_id,
        "verify_row": {"valid_dataset_run": valid_pack, "issues": []},
    }


def test_generate_report_scores_and_exports_expected_gaps(tmp_path: Path, monkeypatch) -> None:
    runs = [
        _run(
            run_id="baseline-1",
            package="com.example.baseline",
            app_label="Baseline App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="baseline-2",
            package="com.example.baseline",
            app_label="Baseline App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="manual-1",
            package="com.example.manual",
            app_label="Manual App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="manual-2",
            package="com.example.manual",
            app_label="Manual App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="manual-3",
            package="com.example.manual",
            app_label="Manual App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="scripted-base-1",
            package="bbc.mobile.news.ww",
            app_label="BBC News",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="scripted-base-2",
            package="bbc.mobile.news.ww",
            app_label="BBC News",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="scripted-base-3",
            package="bbc.mobile.news.ww",
            app_label="BBC News",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
        ),
        _run(
            run_id="scripted-manual-1",
            package="bbc.mobile.news.ww",
            app_label="BBC News",
            run_profile="interaction_manual",
            interaction_mode="manual",
            valid_pack=True,
            dynamic_domains={"example.com", "article.example.com"},
            service_rows_override=[
                {"service_key": "first_party_api", "owner_class": "first_party", "total_hits": 5},
                {"service_key": "analytics_sdk", "owner_class": "third_party", "total_hits": 2},
            ],
            signal_rows_override=[
                {"signal_key": "first_party_platform"},
                {"signal_key": "third_party_analytics_measurement"},
            ],
        ),
        _run(
            run_id="scripted-manual-2",
            package="bbc.mobile.news.ww",
            app_label="BBC News",
            run_profile="interaction_manual",
            interaction_mode="manual",
            valid_pack=True,
            dynamic_domains={"example.com", "article.example.com"},
            service_rows_override=[
                {"service_key": "first_party_api", "owner_class": "first_party", "total_hits": 5},
                {"service_key": "analytics_sdk", "owner_class": "third_party", "total_hits": 2},
            ],
            signal_rows_override=[
                {"signal_key": "first_party_platform"},
                {"signal_key": "third_party_analytics_measurement"},
            ],
        ),
        _run(
            run_id="capture-scripted-1",
            package="com.cnn.mobile.android.phone",
            app_label="CNN",
            run_profile="interaction_scripted",
            interaction_mode="scripted",
            valid_pack=False,
            pcap_present=False,
            pcap_size_bytes=0,
            pcap_failure_detail="PCAP_LOCAL_FILE_EMPTY",
            timeline_available=True,
            timeline_complete=True,
            template_id="news_reader_basic_v1",
            report_status="skip",
        ),
        _run(
            run_id="enrich-base-1",
            package="com.example.enrichment",
            app_label="Enrichment App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
            enriched_domains=False,
            actionable_domains=1,
            corroborated_actionable_domains=0,
        ),
        _run(
            run_id="enrich-base-2",
            package="com.example.enrichment",
            app_label="Enrichment App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
            enriched_domains=False,
            actionable_domains=1,
            corroborated_actionable_domains=0,
        ),
        _run(
            run_id="enrich-base-3",
            package="com.example.enrichment",
            app_label="Enrichment App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
            enriched_domains=False,
            actionable_domains=1,
            corroborated_actionable_domains=0,
        ),
        _run(
            run_id="enrich-manual-1",
            package="com.example.enrichment",
            app_label="Enrichment App",
            run_profile="interaction_manual",
            interaction_mode="manual",
            valid_pack=True,
            enriched_domains=False,
            actionable_domains=1,
            corroborated_actionable_domains=0,
        ),
        _run(
            run_id="enrich-manual-2",
            package="com.example.enrichment",
            app_label="Enrichment App",
            run_profile="interaction_manual",
            interaction_mode="manual",
            valid_pack=True,
            enriched_domains=False,
            actionable_domains=1,
            corroborated_actionable_domains=0,
        ),
        _run(
            run_id="service-base-1",
            package="com.example.servicegap",
            app_label="Service Gap App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
            unresolved_service_count=1,
            unresolved_domains=[{"domain": "unknown.example.net", "root_domain": "example.net", "total_hits": 7}],
        ),
        _run(
            run_id="service-base-2",
            package="com.example.servicegap",
            app_label="Service Gap App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
            unresolved_service_count=1,
            unresolved_domains=[{"domain": "unknown.example.net", "root_domain": "example.net", "total_hits": 7}],
        ),
        _run(
            run_id="service-base-3",
            package="com.example.servicegap",
            app_label="Service Gap App",
            run_profile="baseline_idle",
            interaction_mode="baseline",
            valid_pack=True,
            unresolved_service_count=1,
            unresolved_domains=[{"domain": "unknown.example.net", "root_domain": "example.net", "total_hits": 7}],
        ),
        _run(
            run_id="service-manual-1",
            package="com.example.servicegap",
            app_label="Service Gap App",
            run_profile="interaction_manual",
            interaction_mode="manual",
            valid_pack=True,
            unresolved_service_count=1,
            unresolved_domains=[{"domain": "unknown.example.net", "root_domain": "example.net", "total_hits": 7}],
        ),
        _run(
            run_id="service-manual-2",
            package="com.example.servicegap",
            app_label="Service Gap App",
            run_profile="interaction_manual",
            interaction_mode="manual",
            valid_pack=True,
            unresolved_service_count=1,
            unresolved_domains=[{"domain": "unknown.example.net", "root_domain": "example.net", "total_hits": 7}],
        ),
    ]

    join_rows = {
        "com.example.baseline": {
            "package": "com.example.baseline",
            "static_run_id": 1001,
            "static_endpoint_inventory_status": "present",
            "provider_authority_count": 1,
            "providers_exported": 0,
            "uses_cleartext_traffic": 0,
            "static_http_endpoint_root_count": 0,
            "sdk_tracker_overlap_count": 0,
            "dynamic_signal_count": 2,
        },
        "com.example.manual": {
            "package": "com.example.manual",
            "static_run_id": 1002,
            "static_endpoint_inventory_status": "present",
            "provider_authority_count": 1,
            "providers_exported": 0,
            "uses_cleartext_traffic": 0,
            "static_http_endpoint_root_count": 0,
            "sdk_tracker_overlap_count": 0,
            "dynamic_signal_count": 2,
        },
        "bbc.mobile.news.ww": {
            "package": "bbc.mobile.news.ww",
            "static_run_id": 1003,
            "static_endpoint_inventory_status": "present",
            "provider_authority_count": 1,
            "providers_exported": 0,
            "uses_cleartext_traffic": 0,
            "static_http_endpoint_root_count": 0,
            "sdk_tracker_overlap_count": 0,
            "dynamic_signal_count": 2,
        },
        "com.cnn.mobile.android.phone": {
            "package": "com.cnn.mobile.android.phone",
            "static_run_id": 1004,
            "static_endpoint_inventory_status": "present",
            "provider_authority_count": 1,
            "providers_exported": 0,
            "uses_cleartext_traffic": 0,
            "static_http_endpoint_root_count": 0,
            "sdk_tracker_overlap_count": 0,
            "dynamic_signal_count": 0,
        },
        "com.example.enrichment": {
            "package": "com.example.enrichment",
            "static_run_id": 1005,
            "static_endpoint_inventory_status": "missing",
            "provider_authority_count": 1,
            "providers_exported": 0,
            "uses_cleartext_traffic": 0,
            "static_http_endpoint_root_count": 0,
            "sdk_tracker_overlap_count": 0,
            "dynamic_signal_count": 2,
        },
        "com.example.servicegap": {
            "package": "com.example.servicegap",
            "static_run_id": 1006,
            "static_endpoint_inventory_status": "present",
            "provider_authority_count": 1,
            "providers_exported": 0,
            "uses_cleartext_traffic": 0,
            "static_http_endpoint_root_count": 0,
            "sdk_tracker_overlap_count": 0,
            "dynamic_signal_count": 2,
        },
    }

    monkeypatch.setattr(report, "_dynamic_root", lambda: tmp_path / "output" / "evidence" / "dynamic")
    monkeypatch.setattr(report, "_collect_run_records", lambda _root, overlay_latest_static=False: runs)
    monkeypatch.setattr(report, "_build_static_join_and_candidates", lambda _package_runs: (join_rows, {}))
    monkeypatch.setattr(
        report,
        "_load_app_profiles",
        lambda _packages: {
            "bbc.mobile.news.ww": {"display_name": "BBC News", "profile_key": "NEWS"},
            "com.cnn.mobile.android.phone": {"display_name": "CNN", "profile_key": "NEWS"},
            "com.espn.score_center": {"display_name": "ESPN", "profile_key": "NEWS"},
            "com.facebook.katana": {"display_name": "Facebook", "profile_key": "SOCIAL"},
            "com.twitter.android": {"display_name": "X (Twitter)", "profile_key": "SOCIAL"},
            "com.zhiliaoapp.musically": {"display_name": "TikTok", "profile_key": "SOCIAL"},
        },
    )
    monkeypatch.setattr(
        report,
        "_template_label",
        lambda package: {
            "bbc.mobile.news.ww": "news",
            "com.cnn.mobile.android.phone": "news",
        }.get(package, "none"),
    )

    out_dir = tmp_path / "audit"
    summary = report.generate_report(output_dir=out_dir)

    assert summary["runs_scanned"] == len(runs)
    assert summary["apps_scanned"] == 6
    assert summary["valid_runs"] == 20
    assert summary["invalid_or_skipped_runs"] == 1
    assert summary["readiness_tier_counts"]["needs_baseline_runs"] == 1
    assert summary["readiness_tier_counts"]["needs_manual_runs"] == 1
    assert summary["readiness_tier_counts"]["needs_scripted_validation"] == 1
    assert summary["readiness_tier_counts"]["capture_problem"] == 1
    assert summary["readiness_tier_counts"]["needs_static_enrichment"] == 1
    assert summary["readiness_tier_counts"]["needs_service_mapping"] == 1

    with (out_dir / "run_evidence_quality.csv").open(encoding="utf-8") as handle:
        run_rows = list(csv.DictReader(handle))
    cnn_row = next(row for row in run_rows if row["run_id"] == "capture-scripted-1")
    assert cnn_row["pcap_netstats_consistency"] == "netstats_seen_but_pcap_missing"
    assert cnn_row["timeline_available"] == "1"
    assert "netstats_seen_but_pcap_missing" in cnn_row["dynamic_evidence_limitations"]

    with (out_dir / "app_dynamic_readiness.csv").open(encoding="utf-8") as handle:
        app_rows = {row["package"]: row for row in csv.DictReader(handle)}
    assert app_rows["bbc.mobile.news.ww"]["app_label"] == "BBC News"
    assert app_rows["bbc.mobile.news.ww"]["app_profile"] == "NEWS"
    assert app_rows["com.example.baseline"]["research_readiness_tier"] == "needs_baseline_runs"
    assert app_rows["com.example.baseline"]["next_recommended_action"] == "baseline"
    assert app_rows["com.example.manual"]["research_readiness_tier"] == "needs_manual_runs"
    assert app_rows["com.example.manual"]["next_recommended_action"] == "manual_interaction"
    assert app_rows["bbc.mobile.news.ww"]["research_readiness_tier"] == "needs_scripted_validation"
    assert app_rows["bbc.mobile.news.ww"]["next_recommended_action"] == "scripted_interaction"
    assert app_rows["com.cnn.mobile.android.phone"]["research_readiness_tier"] == "capture_problem"
    assert app_rows["com.cnn.mobile.android.phone"]["next_recommended_action"] == "recollect_capture"
    assert app_rows["com.example.enrichment"]["research_readiness_tier"] == "needs_static_enrichment"
    assert app_rows["com.example.enrichment"]["next_recommended_action"] == "repair_static_enrichment"
    assert app_rows["com.example.servicegap"]["research_readiness_tier"] == "needs_service_mapping"
    assert app_rows["com.example.servicegap"]["next_recommended_action"] == "repair_service_mapping"
    assert app_rows["bbc.mobile.news.ww"]["baseline_domain_reproducibility"] == "1.0"
    assert app_rows["bbc.mobile.news.ww"]["manual_novel_service_count"] == "1"
    assert app_rows["bbc.mobile.news.ww"]["dynamic_activation_delta_score"] == "5"
    assert app_rows["com.example.manual"]["baseline_manual_domain_overlap"] == ""

    with (out_dir / "behavioral_stability_audit.csv").open(encoding="utf-8") as handle:
        stability_rows = {row["package"]: row for row in csv.DictReader(handle)}
    assert stability_rows["bbc.mobile.news.ww"]["baseline_service_reproducibility"] == "1.0"
    assert stability_rows["bbc.mobile.news.ww"]["manual_service_reproducibility"] == "1.0"
    assert stability_rows["bbc.mobile.news.ww"]["manual_novel_domain_count"] == "1"
    assert "manual_activation_expands_runtime_surface" in stability_rows["bbc.mobile.news.ww"]["reproducibility_note"]

    with (out_dir / "paper_pattern_matrix.csv").open(encoding="utf-8") as handle:
        pattern_rows = {row["package"]: row for row in csv.DictReader(handle)}
    assert pattern_rows["bbc.mobile.news.ww"]["scripted_gap_flag"] == "1"
    assert pattern_rows["bbc.mobile.news.ww"]["manual_activation_expansion_flag"] == "1"
    assert pattern_rows["bbc.mobile.news.ww"]["research_priority"] == "medium"
    assert pattern_rows["com.cnn.mobile.android.phone"]["capture_reliability_gap_flag"] == "1"
    assert pattern_rows["com.cnn.mobile.android.phone"]["research_priority"] == "high"

    with (out_dir / "paper_pattern_summary.csv").open(encoding="utf-8") as handle:
        pattern_summary_rows = {row["app_profile"]: row for row in csv.DictReader(handle)}
    assert pattern_summary_rows["NEWS"]["app_count"] == "2"
    assert pattern_summary_rows["NEWS"]["needs_scripted_validation_count"] == "1"
    assert pattern_summary_rows["unknown"]["app_count"] == "4"

    with (out_dir / "capture_failure_audit.csv").open(encoding="utf-8") as handle:
        failure_rows = list(csv.DictReader(handle))
    assert len(failure_rows) == 1
    assert failure_rows[0]["run_id"] == "capture-scripted-1"
    assert failure_rows[0]["recommended_action"] == "recollect_capture"

    with (out_dir / "service_mapping_gap_audit.csv").open(encoding="utf-8") as handle:
        service_gap_rows = list(csv.DictReader(handle))
    assert any(row["package"] == "com.example.servicegap" and row["domain"] == "unknown.example.net" for row in service_gap_rows)

    with (out_dir / "static_enrichment_gap_audit.csv").open(encoding="utf-8") as handle:
        enrichment_rows = list(csv.DictReader(handle))
    enrichment_row = next(row for row in enrichment_rows if row["package"] == "com.example.enrichment")
    assert enrichment_row["endpoint_inventory_status"] == "missing"
    assert enrichment_row["gap_type"] == "static_endpoint_inventory_missing"

    with (out_dir / "phase_coverage_audit.csv").open(encoding="utf-8") as handle:
        phase_rows = list(csv.DictReader(handle))
    phase_row = next(row for row in phase_rows if row["run_id"] == "capture-scripted-1")
    assert phase_row["timeline_available"] == "1"
    assert phase_row["timeline_complete"] == "1"
    assert phase_row["transport_phase_rows"] == "0"

    with (out_dir / "static_guided_dynamic_recommendations.csv").open(encoding="utf-8") as handle:
        recommendation_rows = {row["package"]: row for row in csv.DictReader(handle)}
    assert recommendation_rows["bbc.mobile.news.ww"]["recommended_template"] == "news_reader_basic_v1"
    assert recommendation_rows["bbc.mobile.news.ww"]["recommended_phase"] == "open_article"
    assert recommendation_rows["com.example.servicegap"]["recommended_run_intent"] == "repair_service_mapping"

    summary_json = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary_json["capture_failure_counts"]["PCAP_LOCAL_FILE_EMPTY"] == 1
    assert summary_json["tier_definitions"]["dynamic_evidence_quality"]["A+"] == "95-100 excellent / publication-grade"
    assert summary_json["row_counts"]["behavioral_stability_audit"] == 6
    assert summary_json["row_counts"]["paper_pattern_matrix"] == 6
    assert summary_json["row_counts"]["paper_pattern_summary"] >= 2
    assert summary_json["reproducibility_band_counts"]["manual_activation_delta_gt_0"] >= 1
    assert summary_json["pattern_flag_counts"]["scripted_gap"] >= 1
    assert summary_json["profile_group_counts"]["NEWS"] == 2
    assert summary_json["top_recommended_actions"]["baseline"] == 1
    assert summary_json["top_recommended_actions"]["manual_interaction"] == 1
    assert summary_json["top_recommended_actions"]["scripted_interaction"] == 1
    assert summary_json["top_recommended_actions"]["recollect_capture"] == 1
    assert summary_json["top_recommended_actions"]["repair_static_enrichment"] == 1
    assert summary_json["top_recommended_actions"]["repair_service_mapping"] == 1


def test_overlay_latest_static_reanalysis_adds_provenance_without_mutating_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))

    reports_dir = tmp_path / "data" / "static_analysis" / "reports" / "latest"
    reports_dir.mkdir(parents=True, exist_ok=True)
    static_report = StaticAnalysisReport(
        file_path="/tmp/base.apk",
        relative_path=None,
        file_name="base.apk",
        file_size=123,
        hashes={"sha256": "a" * 64},
        manifest=ManifestSummary(
            package_name="com.example.overlay",
            version_name="1.0",
            version_code="123",
            app_label="Example Overlay",
        ),
        manifest_flags=ManifestFlags(),
        permissions=PermissionSummary(),
        components=ComponentSummary(),
        exported_components=ComponentSummary(),
        metadata={
            "package": "com.example.overlay",
            "version_name": "1.0",
            "version_code": "123",
            "base_apk_sha256": "deadbeef" * 8,
            "artifact_set_hash": "feedface" * 8,
            "run_signature": "cafebabe" * 8,
            "session_stamp": "20260616-all-full",
            "post_run_string_payload": {
                "counts": {"api_keys": 1},
                "samples": {
                    "api_keys": [
                        {
                            "value": "AIzaSensitiveRawValueShouldNotSurface",
                            "value_masked": "AIzaSens…",
                            "src": "classes.dex",
                            "root_domain": "auth.example.com",
                            "source_type": "dex",
                            "api_context": "auth_flow",
                            "posture": "actionable",
                            "ownership_class": "third_party",
                            "pair_group": "google:token_endpoint_family",
                            "verification_status": "supported_opt_in",
                        }
                    ]
                },
                "selected_samples": {},
            },
        },
    )
    (reports_dir / ("b" * 64 + ".json")).write_text(
        json.dumps(static_report.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    output_root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = output_root / "run-overlay"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture").mkdir(parents=True, exist_ok=True)
    (run_dir / "artifacts" / "pcapdroid_capture" / "capture.pcap").write_bytes(b"pcap-bytes")
    (run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json").write_text(
        json.dumps({"pcap_size_bytes": 125000}),
        encoding="utf-8",
    )
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-overlay",
                "target": {"package_name": "com.example.overlay", "static_run_id": 99},
                "operator": {
                    "run_profile": "baseline_idle",
                    "interaction_level": "baseline",
                    "actual_duration_s": 240,
                    "telemetry_stats": {
                        "netstats_available": True,
                        "netstats_bytes_in_total": 2000000,
                        "netstats_bytes_out_total": 300000,
                        "netstats_rows": 10,
                        "netstats_missing_rows": 0,
                        "capture_ratio": 0.98,
                        "max_gap_s": 1.0,
                        "network_signal_quality": "strong",
                    },
                },
                "dataset": {"run_profile": "baseline_idle", "min_pcap_bytes": 50000},
                "artifacts": [
                    {
                        "type": "pcapdroid_capture",
                        "relative_path": "artifacts/pcapdroid_capture/capture.pcap",
                    }
                ],
                "observers": [{"status": "ok"}],
            }
        ),
        encoding="utf-8",
    )
    original_plan = {
        "run_identity": {
            "base_apk_sha256": "deadbeef" * 8,
            "artifact_set_hash": "feedface" * 8,
            "run_signature": "cafebabe" * 8,
            "static_handoff_hash": "b" * 64,
        },
        "network_targets": {
            "domains": ["auth.example.com"],
            "cleartext_domains": [],
            "domain_sources": [
                {
                    "domain": "auth.example.com",
                    "sources": ["strings"],
                    "buckets": ["api_keys"],
                    "postures": [],
                    "ownership_classes": [],
                    "api_contexts": [],
                    "pair_groups": [],
                    "verification_statuses": [],
                }
            ],
        },
    }
    plan_path = run_dir / "inputs" / "static_dynamic_plan.json"
    plan_path.write_text(json.dumps(original_plan, indent=2, sort_keys=True), encoding="utf-8")
    original_bytes = plan_path.read_bytes()
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {"parsed": True},
                "top_dns": [{"value": "auth.example.com", "count": 2}],
                "top_sni": [],
                "protocol_hierarchy": [{"protocol": "tcp", "frames": 10}],
                "tls_quic_visibility": {"quic_candidate_packets": 0, "tls_visible": True},
                "pcap_size_bytes": 125000,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({"proxies": {"privacy_signal_hits": 1}}), encoding="utf-8")
    (run_dir / "analysis" / "summary.json").write_text(json.dumps({}), encoding="utf-8")
    (run_dir / "analysis" / "static_dynamic_overlap.json").write_text(json.dumps({}), encoding="utf-8")

    monkeypatch.setattr(report, "_dynamic_root", lambda: output_root)
    monkeypatch.setattr(
        report,
        "_build_static_join_and_candidates",
        lambda _package_runs: (
            {
                "com.example.overlay": {
                    "package": "com.example.overlay",
                    "static_run_id": 99,
                    "static_endpoint_inventory_status": "present",
                    "provider_authority_count": 1,
                    "providers_exported": 0,
                    "uses_cleartext_traffic": 0,
                    "static_http_endpoint_root_count": 0,
                    "sdk_tracker_overlap_count": 0,
                    "dynamic_signal_count": 2,
                }
            },
            {},
        ),
    )
    monkeypatch.setattr(
        report,
        "_load_app_profiles",
        lambda _packages: {
            "com.example.overlay": {"display_name": "Example Overlay", "profile_key": "TEST"},
        },
    )
    monkeypatch.setattr(report, "_template_label", lambda _package: "none")

    out_dir = tmp_path / "audit-overlay"
    summary = report.generate_report(output_dir=out_dir, overlay_latest_static=True)

    assert summary["plan_analysis_mode"] == "overlay_latest_static"
    assert summary["runs_using_overlay_latest_static"] == 1
    assert summary["embedded_stale_plan_runs"] == 1
    assert summary["runs_with_enriched_domain_metadata_embedded"] == 0
    assert summary["runs_with_enriched_domain_metadata_overlay"] == 1
    assert summary["runs_with_actionable_corroboration_embedded"] == 0
    assert summary["runs_with_actionable_corroboration_overlay"] == 1
    assert summary["actionable_corroboration_rate_overlay"] == 1.0
    assert plan_path.read_bytes() == original_bytes

    with (out_dir / "run_evidence_quality.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    row = rows[0]
    assert row["plan_source"] == "overlay_latest_static"
    assert row["embedded_plan_stale"] == "1"
    assert row["embedded_domains_count"] == "1"
    assert row["overlay_domains_count"] == "1"
    assert row["embedded_enriched_metadata_present"] == "0"
    assert row["overlay_enriched_metadata_present"] == "1"
    assert row["overlay_static_report_path"]
    serialized = json.dumps(row, sort_keys=True)
    assert "AIzaSensitiveRawValueShouldNotSurface" not in serialized
