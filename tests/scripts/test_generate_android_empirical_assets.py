from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_generate_android_empirical_assets_fixture(tmp_path: Path) -> None:
    repo = Path.cwd()
    cutoff = tmp_path / "cutoff"
    audit = tmp_path / "audit"
    static_report = tmp_path / "static_report"
    out = tmp_path / "out"

    cutoff.mkdir(parents=True)
    (cutoff / "summary.json").write_text(json.dumps({"paper_usable": 2}), encoding="utf-8")
    _write_csv(
        cutoff / "paper_freeze_manifest.csv",
        [
            {
                "app": "BBC News",
                "package_name": "bbc.mobile.news.ww",
                "selected_version_code": "100",
                "selected_version_name": "1.0",
                "selected_static_run_ids": "10",
                "selected_dynamic_run_ids": "r1,r2",
                "selected_base_apk_sha256": "a" * 64,
                "strict_idle_count": "1",
                "quiescent_fg_count": "0",
                "baseline_count": "1",
                "interactive_count": "1",
                "valid_pcap_count": "2",
                "qa_valid_count": "2",
                "status": "ready",
                "selected_relation": "recent",
                "build_candidates_seen": "1",
            },
            {
                "app": "Signal",
                "package_name": "org.thoughtcrime.securesms",
                "selected_version_code": "200",
                "selected_version_name": "2.0",
                "selected_static_run_ids": "20",
                "selected_dynamic_run_ids": "r3",
                "selected_base_apk_sha256": "b" * 64,
                "strict_idle_count": "1",
                "quiescent_fg_count": "1",
                "baseline_count": "2",
                "interactive_count": "0",
                "valid_pcap_count": "1",
                "qa_valid_count": "1",
                "status": "ready",
                "selected_relation": "recent",
                "build_candidates_seen": "1",
            },
        ],
    )
    _write_csv(
        audit / "static_exposure" / "static_exposure_vectors.csv",
        [
            {
                "package_name": "bbc.mobile.news.ww",
                "display_name": "BBC News",
                "category": "News",
                "static_run_id": "10",
                "session_stamp": "fixture",
                "version_code": "100",
                "total_static_findings": "10",
                "high_or_critical_findings": "1",
                "network_findings": "2",
                "masvs_privacy_count": "3",
                "masvs_platform_count": "4",
                "masvs_network_count": "2",
                "masvs_storage_count": "1",
                "permission_total": "20",
                "dangerous_permission_count": "4",
                "fileprovider_count": "1",
                "provider_acl_findings": "1",
                "exported_provider_count": "1",
            },
            {
                "package_name": "org.thoughtcrime.securesms",
                "display_name": "Signal",
                "category": "Messaging",
                "static_run_id": "20",
                "session_stamp": "fixture",
                "version_code": "200",
                "total_static_findings": "5",
                "high_or_critical_findings": "0",
                "network_findings": "1",
                "masvs_privacy_count": "1",
                "masvs_platform_count": "1",
                "masvs_network_count": "1",
                "masvs_storage_count": "1",
                "permission_total": "10",
                "dangerous_permission_count": "2",
                "fileprovider_count": "1",
                "provider_acl_findings": "0",
                "exported_provider_count": "0",
            },
        ],
    )
    _write_csv(
        audit / "static_baseline_tables" / "per_app_explainability.csv",
        [
            {"run_id": "10", "package_name": "bbc.mobile.news.ww", "risk_score": "3.5", "risk_grade": "B"},
            {"run_id": "20", "package_name": "org.thoughtcrime.securesms", "risk_score": "1.5", "risk_grade": "A"},
        ],
    )
    _write_csv(
        static_report / "data" / "app_static_metrics.csv",
        [
            {
                "package_name": "bbc.mobile.news.ww",
                "static_run_ids": "10",
                "static_session_stamp": "fixture",
                "detector_findings": "10",
            },
            {
                "package_name": "org.thoughtcrime.securesms",
                "static_run_ids": "20",
                "static_session_stamp": "fixture",
                "detector_findings": "5",
            },
        ],
    )
    _write_csv(
        static_report / "tables" / "paper1_score_model_inputs.csv",
        [
            {
                "package_name": "bbc.mobile.news.ww",
                "severity_high_count": "1",
                "severity_medium_count": "2",
                "masvs_privacy_count": "3",
                "masvs_platform_non_alias_count": "4",
                "masvs_network_count": "2",
                "masvs_storage_count": "1",
                "total_declared_permissions": "20",
                "dangerous_permissions": "4",
                "special_access_permissions": "1",
                "custom_permissions": "3",
                "exported_non_alias_components_without_permission_guard": "6",
                "network_security_findings": "2",
                "storage_related_findings": "1",
                "api_key_indicators": "0",
                "high_entropy_indicators": "0",
                "score_status": "inputs_ready_formula_unapproved",
            },
            {
                "package_name": "org.thoughtcrime.securesms",
                "severity_high_count": "0",
                "severity_medium_count": "1",
                "masvs_privacy_count": "1",
                "masvs_platform_non_alias_count": "1",
                "masvs_network_count": "1",
                "masvs_storage_count": "1",
                "total_declared_permissions": "10",
                "dangerous_permissions": "2",
                "special_access_permissions": "0",
                "custom_permissions": "1",
                "exported_non_alias_components_without_permission_guard": "2",
                "network_security_findings": "1",
                "storage_related_findings": "1",
                "api_key_indicators": "0",
                "high_entropy_indicators": "0",
                "score_status": "inputs_ready_formula_unapproved",
            },
        ],
    )
    _write_csv(
        static_report / "tables" / "paper1_manifest_component_parity.csv",
        [
            {"package_name": "bbc.mobile.news.ww", "fileprovider_like_provider_count": "1"},
            {"package_name": "org.thoughtcrime.securesms", "fileprovider_like_provider_count": "1"},
        ],
    )
    _write_csv(
        static_report / "tables" / "paper1_network_storage_parity.csv",
        [
            {
                "package_name": "bbc.mobile.news.ww",
                "cleartext_traffic_permitted": "no",
                "legacy_external_storage_requested": "no",
                "android_backup_enabled": "no",
            },
            {
                "package_name": "org.thoughtcrime.securesms",
                "cleartext_traffic_permitted": "no",
                "legacy_external_storage_requested": "no",
                "android_backup_enabled": "no",
            },
        ],
    )
    _write_csv(
        audit / "dynamic_paper_exports" / "per_app_summary.csv",
        [
            {
                "package": "bbc.mobile.news.ww",
                "observed_domain_count": "12",
                "service_count": "4",
                "signal_count": "3",
                "unresolved_service_count": "0",
            },
            {
                "package": "org.thoughtcrime.securesms",
                "observed_domain_count": "6",
                "service_count": "2",
                "signal_count": "2",
                "unresolved_service_count": "0",
            },
        ],
    )
    _write_csv(
        audit / "dynamic_pcap_behavior_ml" / "app_feature_rollup.csv",
        [
            {
                "package_name": "bbc.mobile.news.ww",
                "median_unique_ja4_count": "4",
                "median_unique_ja3_count": "5",
                "baseline_stability": "2",
                "interactive_broadening": "3",
                "strongest_shift_metric": "pcap_bytes",
                "strongest_shift_p_value": "0.05",
                "strongest_shift_effect_band": "medium",
                "service_families_observed": "publisher",
                "inference_readiness": "paper_ready_signal",
            },
            {
                "package_name": "org.thoughtcrime.securesms",
                "median_unique_ja4_count": "2",
                "median_unique_ja3_count": "3",
                "baseline_stability": "1",
                "interactive_broadening": "1",
                "strongest_shift_metric": "unique_ja4_count",
                "strongest_shift_p_value": "0.10",
                "strongest_shift_effect_band": "small",
                "service_families_observed": "messaging",
                "inference_readiness": "descriptive",
            },
        ],
    )
    _write_csv(
        audit / "dynamic_pcap_behavior_ml" / "cross_app_metric_summary.csv",
        [
            {
                "metric": "pcap_bytes",
                "apps_compared": "2",
                "apps_positive_delta": "2",
                "apps_negative_delta": "0",
                "apps_zero_delta": "0",
                "apps_p_le_0_10": "1",
                "apps_p_le_0_05": "1",
                "apps_large_effect": "1",
                "median_delta": "1024",
                "median_abs_cliffs_delta": "0.75",
                "interpretation": "interactive broadening trend observed",
            }
        ],
    )
    (audit / "dynamic_pcap_behavior_ml" / "summary.json").write_text(
        json.dumps(
            {
                "total_runs": 3,
                "stats_eligible_runs": 3,
                "local_pcap_available_runs": 3,
                "apps_with_stats_eligible_runs": 2,
                "apps_with_interactive_comparison": 1,
                "apps_inference_ready": 1,
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(repo / "scripts" / "publication" / "generate_android_empirical_assets.py"),
            "--cutoff-dir",
            str(cutoff),
            "--audit-dir",
            str(audit),
            "--static-report-dir",
            str(static_report),
            "--output-dir",
            str(out),
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    summary = json.loads((out / "analysis_summary.json").read_text(encoding="utf-8"))
    assert summary["apps"] == 2
    dataset = (out / "data" / "analysis_dataset.csv").read_text(encoding="utf-8")
    assert "static_risk_score" not in dataset
    assert "static_priority_finding_count" in dataset
    assert (out / "figures" / "fig3_runtime_coverage_by_app.png").exists()
    assert (out / "latex" / "table_inputs.tex").exists()
    assert (out / "latex" / "paper2_dynamic_insert.tex").exists()
    assert (out / "tables" / "paper2_dynamic_method_bridge.csv").exists()
    assert (out / "tables" / "paper2_baseline_interactive_metric_summary.csv").exists()
    assert (out / "tables" / "paper2_app_runtime_deviation_proxy.csv").exists()
    assert (out / "tables" / "paper2_original_asset_alignment.csv").exists()
    assert (out / "report" / "paper2_publication_use_notes.md").exists()
    alignment_report = out / "report" / "paper2_original_asset_alignment.md"
    assert alignment_report.exists()
    assert "exact reproduction of the original RDI tables" in alignment_report.read_text(encoding="utf-8")
    latex = (out / "latex" / "results_insert.tex").read_text(encoding="utf-8")
    assert "static risk score" not in latex.lower()
    assert "No composite static scoring value is reported" in latex
    dynamic_latex = (out / "latex" / "paper2_dynamic_insert.tex").read_text(encoding="utf-8")
    assert "exact Runtime Deviation Index values" in dynamic_latex
    assert "dynamic-deviation proxy" in dynamic_latex
    summary = json.loads((out / "analysis_summary.json").read_text(encoding="utf-8"))
    assert summary["paper2_dynamic_bridge"]["metric_summary_rows"] == 1
    assert summary["paper2_original_asset_alignment"]["rows"] >= 10
    assert summary["paper2_original_asset_alignment"]["status_counts"]["proxy_available"] >= 1
