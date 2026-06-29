from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.dynamic import refresh_analysis_summaries as refresh


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "dynamic" / "refresh_analysis_summaries.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "usage:" in (proc.stdout or "").lower()
    assert "refresh derived dynamic run analysis artifacts" in (proc.stdout or "").lower()


def test_refresh_summaries_dry_run_reports_destination_changes_and_skips(tmp_path: Path) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = root / "run-1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "run_manifest_version": 1,
            "dynamic_run_id": "run-1",
            "created_at": "2026-06-28T00:00:00Z",
            "status": "success",
            "target": {"package_name": "com.facebook.katana"},
            "artifacts": [],
            "outputs": [],
            "operator": {
                "telemetry_stats": {
                    "netstats_bytes_in_total": 100,
                    "netstats_bytes_out_total": 50,
                    "netstats_rows": 1,
                    "netstats_missing_rows": 0,
                }
            },
        },
    )
    _write_json(
        run_dir / "analysis" / "summary.json",
        {
            "destinations_observed": [],
            "flags": {"network_capture_present": True},
            "capture": {"pcap_valid": True},
        },
    )
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "top_dns": [{"value": "graph.facebook.com", "count": 8}],
            "top_sni": [{"value": "edge-mqtt.facebook.com", "count": 4}],
            "service_context": {
                "services": [{"domains": [{"domain": "lookaside.facebook.com"}]}],
                "unresolved_domains": [],
            },
        },
    )
    in_progress = root / "run-in-progress"
    (in_progress / "notes").mkdir(parents=True, exist_ok=True)
    (in_progress / "notes" / ".scytaledroid_in_progress").write_text("", encoding="utf-8")
    ghost = root / "run-ghost"
    (ghost / "notes").mkdir(parents=True, exist_ok=True)
    (ghost / "notes" / "run_events.jsonl").write_text("", encoding="utf-8")

    summary = refresh.refresh_summaries(root=root, apply=False)

    assert summary["runs_scanned"] == 1
    assert summary["runs_matched"] == 1
    assert summary["runs_updated"] == 0
    assert summary["runs_with_destination_changes"] == 1
    assert summary["in_progress_dirs_skipped"] == ["run-in-progress"]
    assert summary["ghost_dirs_skipped"] == ["run-ghost"]
    assert summary["rows"][0]["new_destinations_count"] == 3
    current_summary = json.loads((run_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))
    assert current_summary["destinations_observed"] == []


def test_refresh_summaries_apply_rewrites_summary(tmp_path: Path) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = root / "run-1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "run_manifest_version": 1,
            "dynamic_run_id": "run-1",
            "created_at": "2026-06-28T00:00:00Z",
            "status": "success",
            "target": {"package_name": "com.cnn.mobile.android.phone"},
            "artifacts": [],
            "outputs": [],
            "operator": {
                "telemetry_stats": {
                    "netstats_bytes_in_total": 1000,
                    "netstats_bytes_out_total": 250,
                    "netstats_rows": 2,
                    "netstats_missing_rows": 0,
                }
            },
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {"destinations_observed": []})
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "top_dns": [{"value": "collector.cdp.cnn.com", "count": 3}],
            "top_sni": [{"value": "media.cnn.com", "count": 2}],
        },
    )

    summary = refresh.refresh_summaries(root=root, apply=True)

    assert summary["runs_updated"] == 1
    refreshed = json.loads((run_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))
    assert refreshed["destinations_observed"] == ["collector.cdp.cnn.com", "media.cnn.com"]
    assert (run_dir / "analysis" / "summary.md").exists()


def test_refresh_summaries_apply_all_derived_invokes_rewriters(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = root / "run-1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "run_manifest_version": 1,
            "dynamic_run_id": "run-1",
            "created_at": "2026-06-28T00:00:00Z",
            "status": "success",
            "target": {"package_name": "bbc.mobile.news.ww"},
            "artifacts": [],
            "outputs": [],
            "operator": {},
        },
    )
    _write_json(run_dir / "analysis" / "summary.json", {"destinations_observed": []})
    _write_json(
        run_dir / "analysis" / "pcap_report.json",
        {
            "top_dns": [{"value": "www.bbc.com", "count": 2}],
            "top_sni": [],
        },
    )

    calls: list[dict[str, object]] = []

    def _fake_rewrite(**kwargs):
        calls.append(kwargs)
        return {
            "pcap_report": True,
            "pcap_features": True,
            "overlap": True,
            "summary": True,
        }

    monkeypatch.setattr(refresh, "_rewrite_derived_artifacts", _fake_rewrite)

    summary = refresh.refresh_summaries(
        root=root,
        apply=True,
        refresh_pcap_report=True,
        refresh_pcap_features=True,
        refresh_overlap=True,
    )

    assert summary["runs_updated"] == 1
    assert summary["pcap_report_refreshed"] == 1
    assert summary["pcap_features_refreshed"] == 1
    assert summary["overlap_refreshed"] == 1
    assert len(calls) == 1
    assert calls[0]["refresh_pcap_report"] is True
    assert calls[0]["refresh_pcap_features"] is True
    assert calls[0]["refresh_overlap"] is True


def test_refresh_summaries_apply_rewrites_summary_even_when_summary_json_is_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    run_dir = root / "run-1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "run_manifest_version": 1,
            "dynamic_run_id": "run-1",
            "created_at": "2026-06-28T00:00:00Z",
            "status": "success",
            "dataset": {
                "valid_dataset_run": True,
                "countable": False,
                "cohort_eligibility": "EXTRA",
                "invalid_reason_code": None,
            },
            "target": {"package_name": "com.example.app"},
            "artifacts": [],
            "outputs": [],
            "operator": {"run_profile": "interaction_manual"},
        },
    )
    expected_summary = {
        "dynamic_run_id": "run-1",
        "status": "success",
        "tier": None,
        "run_profile": "interaction_manual",
        "dataset_verdict": "VALID",
        "counts_toward_quota": False,
        "quota_detail": {
            "countable": False,
            "countability_label": "NO (extra run)",
            "cohort_eligibility": "EXTRA",
            "invalid_reason_code": None,
        },
        "verdicts": {
            "technical": "VALID",
            "protocol": "COMPLIANT",
            "cohort": "EXTRA",
        },
        "dataset": {
            "valid_dataset_run": True,
            "countable": False,
            "cohort_eligibility": "EXTRA",
            "invalid_reason_code": None,
        },
        "target": {"package_name": "com.example.app"},
        "environment": {},
        "scenario": {},
        "observers": [],
        "destinations_observed": [],
        "indicators": {
            "top_dns": [],
            "top_sni": [],
            "service_context": {},
            "service_signals": {},
        },
        "telemetry": {
            "schema_version": None,
            "counts": None,
            "stats": None,
            "quality": {},
            "network_signal_quality": "none",
            "network_signal_quality_stored": None,
            "network_signal_quality_computed": "none",
            "network_quality_mismatch": False,
        },
        "flags": {
            "network_capture_present": "unknown",
            "cleartext_http_detected": "unknown",
            "tls_mitm_suspected": "false",
            "notable_log_signals": [],
            "static_watchlist_used": False,
            "capture_sources": [],
        },
        "static_watchlist": None,
        "capture": {
            "sources": [],
            "total_bytes": 0,
            "pcap_available": None,
            "pcap_size_bytes": None,
            "pcap_valid": None,
            "capture_mode": None,
            "network_signal_quality": "none",
            "evidence_sizes": {},
        },
        "evidence": [],
    }
    _write_json(run_dir / "analysis" / "summary.json", expected_summary)
    (run_dir / "analysis" / "summary.md").parent.mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "summary.md").write_text("stale markdown", encoding="utf-8")

    summary = refresh.refresh_summaries(root=root, apply=True)

    assert summary["runs_updated"] == 1
    rendered = (run_dir / "analysis" / "summary.md").read_text(encoding="utf-8")
    assert "Counts toward quota: NO (extra run)." in rendered
    assert "Invalid reason: —." in rendered
