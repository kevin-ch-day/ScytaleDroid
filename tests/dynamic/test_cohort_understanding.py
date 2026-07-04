from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.cohort_understanding import build_cohort_understanding


def test_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_pcap_cohort_understanding.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage:")


def test_build_cohort_understanding_aggregates_surface(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    analysis = run_dir / "analysis"
    analysis.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {"package_name": "com.example.app", "display_name": "Example"},
                "operator": {"run_profile": "baseline_idle"},
                "dataset": {"valid_dataset_run": True, "pcap_size_bytes": 1000},
            }
        ),
        encoding="utf-8",
    )
    (analysis / "pcap_features.json").write_text(
        json.dumps({"proxies": {"tls_ratio": 0.9, "quic_ratio": 0.1}, "metrics": {}}),
        encoding="utf-8",
    )
    (analysis / "security_surface.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "finding_count": 2,
                "risk_flags": ["tls_alerts_observed"],
                "cleartext": {
                    "visibility_class": "encrypted_or_opaque_dominant",
                    "http_observed": False,
                    "plaintext_protocols_observed": [],
                    "decoded_protocols_observed": [],
                },
                "dns_anomalies": {"max_label_entropy": 3.8, "risk_flags": []},
                "tls_surface": {"tls_alert_count": 2, "risk_flags": ["tls_alerts_observed"]},
                "domain_inventory": {
                    "dns_names": ["api.example.com"],
                    "sni_names": ["api.example.com"],
                },
                "threat_heuristics": {"risk_flags": []},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    (analysis / "pcap_report.json").write_text("{}", encoding="utf-8")

    summary = build_cohort_understanding(tmp_path)

    assert summary.runs_scanned == 1
    assert summary.runs_with_surface == 1
    assert summary.tls_alert_runs == 1
    assert summary.top_cohort_domains_dns[0][0] == "api.example.com"
