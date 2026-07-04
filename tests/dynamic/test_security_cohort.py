from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.security_cohort import (
    analyze_security_cohort,
    build_app_security_rollup,
)
from scytaledroid.DynamicAnalysis.pcap.security_surface import rehydrate_security_surface


def test_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_pcap_security_cohort.py"
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


def test_rehydrate_security_surface_adds_xmpp_finding() -> None:
    surface = rehydrate_security_surface(
        {
            "status": "ok",
            "cleartext": {
                "visibility_class": "cleartext_surface_present",
                "plaintext_protocol_frames": 1,
                "plaintext_protocols_observed": ["xmpp"],
                "decoded_streams": [{"protocol": "xmpp", "transport": "tcp", "frames": 1}],
                "decoded_stream_count": 1,
                "http_observed": False,
                "risk_flags": ["decoded_cleartext_application_protocol_observed"],
            },
            "dns_anomalies": {"risk_flags": []},
            "tls_surface": {"risk_flags": []},
            "domain_inventory": {"dns_unique_count": 1},
            "threat_heuristics": {"risk_flags": []},
        }
    )
    titles = [
        str(item.get("title") or "")
        for item in surface.get("findings") or []
        if isinstance(item, dict)
    ]
    assert any("XMPP" in title for title in titles)
    assert surface["cleartext"]["cleartext_protocol_observed"] is True


def test_analyze_security_cohort_reads_cached_surface(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    analysis = run_dir / "analysis"
    analysis.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {"package_name": "com.example.app", "display_name": "Example"},
                "operator": {"run_profile": "baseline_idle"},
                "dataset": {"valid_dataset_run": True},
            }
        ),
        encoding="utf-8",
    )
    (analysis / "security_surface.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "finding_count": 2,
                "risk_flags": ["high_entropy_dns_labels"],
                "cleartext": {
                    "visibility_class": "encrypted_or_opaque_dominant",
                    "http_observed": False,
                    "cleartext_protocol_observed": False,
                    "plaintext_protocols_observed": [],
                    "decoded_protocols_observed": [],
                    "decoded_stream_count": 0,
                },
                "dns_anomalies": {"risk_flags": ["high_entropy_dns_labels"]},
                "tls_surface": {"risk_flags": []},
                "domain_inventory": {},
                "threat_heuristics": {"risk_flags": []},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "inputs").mkdir()
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(
        json.dumps({"static_features": {"uses_cleartext_traffic": False}}),
        encoding="utf-8",
    )
    (analysis / "pcap_report.json").write_text("{}", encoding="utf-8")

    summary = analyze_security_cohort(tmp_path)
    rollup = build_app_security_rollup(summary.rows)

    assert summary.runs_scanned == 1
    assert summary.surface_ok == 1
    assert rollup[0]["package"] == "com.example.app"
