from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_static_string_dynamic_corroboration as report
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
    script = repo / "scripts" / "db" / "report_static_string_dynamic_corroboration.py"
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
    assert "corroboration" in out
    assert "--output-dir" in out
    assert "--overlay-latest-static" in out
    assert "--overlay-reanalyse-strings" in out


def test_summary_reports_actionable_corroboration_and_missing_enrichment() -> None:
    rows = [
        report.CorroborationRow(
            dynamic_run_id="run-1",
            package_name="com.example.one",
            static_run_id=1,
            static_handoff_hash="a" * 64,
            static_domains_total=2,
            static_domains_actionable=1,
            static_domains_exploratory=1,
            dynamic_domains_total=1,
            corroborated_domains_total=1,
            corroborated_actionable_domains=1,
            corroborated_exploratory_domains=0,
            corroborated_pair_groups=("google:token_endpoint_family",),
            enriched_domain_metadata_present=True,
            overlap_report_present=True,
            plan_path="output/evidence/dynamic/run-1/inputs/static_dynamic_plan.json",
            report_path="output/evidence/dynamic/run-1/analysis/pcap_report.json",
            overlap_path="output/evidence/dynamic/run-1/analysis/static_dynamic_overlap.json",
        ),
        report.CorroborationRow(
            dynamic_run_id="run-2",
            package_name="com.example.two",
            static_run_id=2,
            static_handoff_hash="b" * 64,
            static_domains_total=1,
            static_domains_actionable=0,
            static_domains_exploratory=1,
            dynamic_domains_total=1,
            corroborated_domains_total=0,
            corroborated_actionable_domains=0,
            corroborated_exploratory_domains=0,
            corroborated_pair_groups=(),
            enriched_domain_metadata_present=False,
            overlap_report_present=False,
            plan_path="output/evidence/dynamic/run-2/inputs/static_dynamic_plan.json",
            report_path="output/evidence/dynamic/run-2/analysis/pcap_report.json",
            overlap_path=None,
        ),
    ]

    summary = report._summary(rows)

    assert summary["dynamic_runs_scanned"] == 2
    assert summary["runs_with_any_corroboration"] == 1
    assert summary["runs_with_actionable_corroboration"] == 1
    assert summary["runs_with_enriched_domain_metadata"] == 1
    assert summary["packages_with_actionable_static_domains"] == 1
    assert summary["packages_with_actionable_corroboration"] == 1
    assert summary["actionable_corroboration_rate"] == 1.0
    assert summary["runs_missing_enriched_domain_metadata"] == 1
    assert summary["top_corroborated_pair_groups"][0]["pair_group"] == "google:token_endpoint_family"
    assert summary["no_db_writes"] is True
    assert summary["experimental_audit"] is True
    assert "repo_root" in summary
    assert "dynamic_evidence_root" in summary
    assert "filesystem_first_inputs" in summary["assumptions"]


def test_corroboration_row_extracts_domain_counts_from_files(tmp_path: Path) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-1"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {"package_name": "com.example.app", "static_run_id": 11},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "run_identity": {"static_handoff_hash": "c" * 64},
                "network_targets": {
                    "domains": ["google.com", "docs.example.org"],
                    "cleartext_domains": [],
                    "domain_sources": [
                        {
                            "domain": "google.com",
                            "sources": ["strings"],
                            "postures": ["actionable"],
                            "pair_groups": ["google:token_endpoint_family"],
                            "ownership_classes": ["unknown_third_party"],
                            "api_contexts": ["auth_flow"],
                        },
                        {
                            "domain": "docs.example.org",
                            "sources": ["strings", "nsc"],
                            "postures": ["exploratory"],
                            "ownership_classes": ["documentary"],
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [{"value": "google.com", "count": 3}],
                "top_sni": [{"value": "sni.example.net", "count": 1}],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "static_dynamic_overlap.json").write_text("{}", encoding="utf-8")

    row = report._corroboration_row(run_dir)

    assert row is not None
    assert row.package_name == "com.example.app"
    assert row.static_domains_total == 2
    assert row.static_domains_actionable == 1
    assert row.corroborated_domains_total == 1
    assert row.corroborated_actionable_domains == 1
    assert row.corroborated_pair_groups == ("google:token_endpoint_family",)
    assert row.enriched_domain_metadata_present is True


def test_corroboration_row_matches_static_root_domain_against_dynamic_host(tmp_path: Path) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-root-match"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-root-match",
                "target": {"package_name": "com.example.rootmatch", "static_run_id": 44},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "run_identity": {"static_handoff_hash": "e" * 64},
                "network_targets": {
                    "domains": ["cnn.com"],
                    "cleartext_domains": [],
                    "domain_sources": [
                        {
                            "domain": "cnn.com",
                            "sources": ["strings"],
                            "postures": ["actionable"],
                            "pair_groups": [],
                            "ownership_classes": ["unknown_third_party"],
                            "api_contexts": ["network_target"],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [{"value": "collector.cdp.cnn.com", "count": 6}],
                "top_sni": [{"value": "media.cnn.com", "count": 5}],
            }
        ),
        encoding="utf-8",
    )

    row = report._corroboration_row(run_dir)

    assert row is not None
    assert row.static_domains_total == 1
    assert row.corroborated_domains_total == 1
    assert row.corroborated_actionable_domains == 1


def test_detail_rows_distinguish_host_exact_from_root_match(tmp_path: Path) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-detail-match"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-detail-match",
                "target": {"package_name": "com.example.match", "static_run_id": 55},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "network_targets": {
                    "domain_sources": [
                        {
                            "domain": "api.example.com",
                            "sources": ["strings"],
                            "postures": ["actionable"],
                            "ownership_classes": ["third_party"],
                            "api_contexts": ["network_target"],
                        },
                        {
                            "domain": "example.com",
                            "sources": ["strings"],
                            "postures": ["exploratory"],
                            "ownership_classes": ["third_party"],
                            "api_contexts": ["network_target"],
                        },
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [{"value": "api.example.com", "count": 3}],
                "top_sni": [{"value": "cdn.example.com", "count": 2}],
            }
        ),
        encoding="utf-8",
    )

    row = report._corroboration_row(run_dir)
    assert row is not None
    details = report._detail_rows_for_run_dir(run_dir, row)
    host_exact = next(item for item in details if item["static_domain"] == "api.example.com")
    root_match = next(item for item in details if item["static_domain"] == "example.com")
    assert host_exact["corroboration_match_type"] == "host_exact_match"
    assert host_exact["host_level_exact_match"] == 1
    assert root_match["corroboration_match_type"] == "root_domain_match"
    assert root_match["host_level_exact_match"] == 0
    assert root_match["root_domain_match"] == 1


def test_detail_rows_mark_generic_adtech_overlap_as_weak(tmp_path: Path) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-generic"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-generic",
                "target": {"package_name": "com.example.ads", "static_run_id": 66},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "network_targets": {
                    "domain_sources": [
                        {
                            "domain": "doubleclick.net",
                            "sources": ["strings"],
                            "postures": ["actionable"],
                            "ownership_classes": ["third_party"],
                            "api_contexts": ["network_target"],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps({"top_dns": [{"value": "googleads.g.doubleclick.net", "count": 4}]}),
        encoding="utf-8",
    )

    row = report._corroboration_row(run_dir)
    assert row is not None
    details = report._detail_rows_for_run_dir(run_dir, row)
    detail = next(item for item in details if item["static_domain"] == "doubleclick.net")
    assert detail["corroboration_match_type"] == "weak_generic_match"
    assert detail["corroboration_strength"] in {"weak", "noisy"}
    assert detail["is_generic_infrastructure_match"] == 1


def test_detail_rows_emit_static_only_and_dynamic_only_rows(tmp_path: Path) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-only"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-only",
                "target": {"package_name": "com.example.only", "static_run_id": 77},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "network_targets": {
                    "domain_sources": [
                        {
                            "domain": "static-only.example",
                            "sources": ["strings"],
                            "postures": ["exploratory"],
                            "ownership_classes": ["third_party"],
                            "api_contexts": ["network_target"],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps({"top_dns": [{"value": "dynamic-only.example.net", "count": 2}]}),
        encoding="utf-8",
    )

    row = report._corroboration_row(run_dir)
    assert row is not None
    details = report._detail_rows_for_run_dir(run_dir, row)
    assert any(item["corroboration_match_type"] == "static_only" for item in details)
    assert any(item["corroboration_match_type"] == "dynamic_only" for item in details)


def test_fixture_summary_counts_enriched_domain_metadata_from_dynamic_plan(tmp_path: Path) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-enriched"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-enriched",
                "target": {"package_name": "com.example.enriched", "static_run_id": 22},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps(
            {
                "run_identity": {"static_handoff_hash": "d" * 64},
                "network_targets": {
                    "domains": ["auth.example.com"],
                    "cleartext_domains": [],
                    "domain_sources": [
                        {
                            "domain": "auth.example.com",
                            "sources": ["strings"],
                            "buckets": ["api_keys"],
                            "postures": ["actionable"],
                            "ownership_classes": ["third_party"],
                            "api_contexts": ["auth_flow"],
                            "pair_groups": ["google:token_endpoint_family"],
                            "verification_statuses": ["supported_opt_in"],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps({"top_dns": [{"value": "auth.example.com", "count": 2}]}),
        encoding="utf-8",
    )

    row = report._corroboration_row(run_dir)

    assert row is not None
    summary = report._summary([row])

    assert summary["dynamic_runs_scanned"] == 1
    assert summary["runs_with_enriched_domain_metadata"] == 1
    assert summary["runs_with_actionable_corroboration"] == 1
    assert summary["packages_with_actionable_corroboration"] == 1


def test_overlay_latest_static_reanalysis_uses_current_static_report_without_mutating_pack(
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
    report_path = reports_dir / ("a" * 64 + ".json")
    report_path.write_text(json.dumps(static_report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-overlay"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-overlay",
                "target": {"package_name": "com.example.overlay", "static_run_id": 99},
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
        json.dumps({"top_dns": [{"value": "auth.example.com", "count": 2}]}),
        encoding="utf-8",
    )

    row = report._corroboration_row(run_dir, overlay_latest_static=True)

    assert row is not None
    assert row.enriched_domain_metadata_present is True
    assert row.corroborated_actionable_domains == 1
    assert row.plan_source == "overlay_latest_static"
    assert row.overlay_static_report_path is not None
    assert plan_path.read_bytes() == original_bytes


def test_overlay_string_reanalysis_uses_current_apk_overlay_without_mutating_pack(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))

    reports_dir = tmp_path / "data" / "static_analysis" / "reports" / "latest"
    reports_dir.mkdir(parents=True, exist_ok=True)

    apk_path = tmp_path / "apk" / "cnn.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(b"placeholder")

    static_report = StaticAnalysisReport(
        file_path=str(apk_path),
        relative_path=None,
        file_name="cnn.apk",
        file_size=123,
        hashes={"sha256": "c" * 64},
        manifest=ManifestSummary(
            package_name="com.cnn.mobile.android.phone",
            version_name="1.0",
            version_code="123",
            app_label="CNN",
        ),
        manifest_flags=ManifestFlags(),
        permissions=PermissionSummary(),
        components=ComponentSummary(),
        exported_components=ComponentSummary(),
        metadata={
            "package": "com.cnn.mobile.android.phone",
            "apk_path": str(apk_path),
            "base_apk_sha256": "deadbeef" * 8,
            "artifact_set_hash": "feedface" * 8,
            "run_signature": "cafebabe" * 8,
            "session_stamp": "20260616-all-full",
            "post_run_string_payload": {
                "counts": {},
                "samples": {},
                "selected_samples": {},
            },
        },
    )
    report_path = reports_dir / ("c" * 64 + ".json")
    report_path.write_text(json.dumps(static_report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    def _fake_analyse_strings(*_args, **_kwargs):
        return {
            "counts": {"endpoints": 1},
            "samples": {
                "endpoints": [
                    {
                        "value": "https://cerebro.api.cnn.io/api/v1/config",
                        "src": "assets/json/environments.json",
                        "root_domain": "cnn.io",
                        "source_type": "asset",
                        "posture": "exploratory",
                        "ownership_class": "unknown_third_party",
                        "api_context": "config_endpoint",
                        "pair_group": None,
                        "verification_status": "static_only",
                    }
                ]
            },
            "selected_samples": {
                "endpoints": [
                    {
                        "value": "https://cerebro.api.cnn.io/api/v1/config",
                        "src": "assets/json/environments.json",
                        "root_domain": "cnn.io",
                        "source_type": "asset",
                        "posture": "exploratory",
                        "ownership_class": "unknown_third_party",
                        "api_context": "config_endpoint",
                        "pair_group": None,
                        "verification_status": "static_only",
                    }
                ]
            },
            "aggregates": {"endpoint_roots": []},
        }

    monkeypatch.setattr(report, "_reanalyse_string_payload_from_report", lambda *args, **kwargs: _fake_analyse_strings())

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-overlay-reanalyse"
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-overlay-reanalyse",
                "target": {"package_name": "com.cnn.mobile.android.phone", "static_run_id": 101},
            }
        ),
        encoding="utf-8",
    )
    original_plan = {
        "run_identity": {
            "base_apk_sha256": "deadbeef" * 8,
            "artifact_set_hash": "feedface" * 8,
            "run_signature": "cafebabe" * 8,
            "static_handoff_hash": "d" * 64,
        },
        "network_targets": {"domains": [], "cleartext_domains": [], "domain_sources": []},
    }
    plan_path = run_dir / "inputs" / "static_dynamic_plan.json"
    plan_path.write_text(json.dumps(original_plan, indent=2, sort_keys=True), encoding="utf-8")
    original_bytes = plan_path.read_bytes()
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps({"top_dns": [{"value": "cnn.io", "count": 2}]}),
        encoding="utf-8",
    )

    row = report._corroboration_row(
        run_dir,
        overlay_latest_static=True,
        overlay_reanalyse_strings=True,
    )

    assert row is not None
    assert row.enriched_domain_metadata_present is True
    assert row.static_domains_total == 1
    assert row.corroborated_domains_total == 1
    assert row.plan_source == "overlay_string_reanalysis"
    assert row.overlay_static_report_path is not None
    assert plan_path.read_bytes() == original_bytes
