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
    assert "refresh derived dynamic run summaries" in (proc.stdout or "").lower()


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
