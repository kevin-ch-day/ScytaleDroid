from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_static_string_dynamic_corroboration as report


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
