from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.db import report_dynamic_retained_evidence_reuse as report
from scytaledroid.DynamicAnalysis.services import paper_freeze_readiness as freeze


def _write_manifest(
    run_dir: Path,
    *,
    run_id: str,
    package_name: str,
    version_code: str,
    ended_at: str,
    valid: bool = True,
    countable: bool = False,
    paper_eligible: bool = True,
    pcap: bool = True,
) -> None:
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    capture_dir.mkdir(parents=True)
    if pcap:
        (capture_dir / f"{run_id}.pcap").write_bytes(b"pcap")
    payload = {
        "dynamic_run_id": run_id,
        "status": "success",
        "ended_at": ended_at,
        "target": {
            "package_name": package_name,
            "version_code": version_code,
            "version_name": "1.0",
            "base_apk_sha256": f"sha-{version_code}",
        },
        "operator": {"run_profile": "interaction_manual"},
        "scenario": {"interaction_level": "manual", "ended_at": ended_at},
        "dataset": {
            "valid_dataset_run": valid,
            "countable": countable,
            "paper_eligible": paper_eligible,
            "low_signal": False,
            "pcap_size_bytes": 1234,
        },
        "artifacts": [
            {
                "path": f"artifacts/pcapdroid_capture/{run_id}.pcap",
                "artifact_type": "pcap",
            }
        ]
        if pcap
        else [],
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def test_reuse_policy_boundaries() -> None:
    assert report._reuse_policy(
        tier="STRICT_CURRENT_BUILD_COMPLETE",
        relation="current",
        selected_missing_artifacts=0,
        recent_context_runs=0,
    )[0] == "PRIMARY_CURRENT_BUILD"
    assert report._reuse_policy(
        tier="CURRENT_BUILD_MIXED_BASELINE",
        relation="current",
        selected_missing_artifacts=0,
        recent_context_runs=0,
    )[0] == "PRIMARY_CURRENT_BUILD_WITH_CAVEAT"
    assert report._reuse_policy(
        tier="PRIOR_BUILD_PAPER_EVIDENCE",
        relation="prior-build",
        selected_missing_artifacts=0,
        recent_context_runs=0,
    )[0] == "PRIMARY_PRIOR_BUILD_WITH_PROVENANCE"
    assert report._reuse_policy(
        tier="PRIOR_BUILD_PAPER_EVIDENCE",
        relation="prior-build",
        selected_missing_artifacts=1,
        recent_context_runs=0,
    )[0] == "REPAIR_BEFORE_USE"


def test_main_accepts_json_alias(monkeypatch, capsys) -> None:
    def fake_generate_report(**kwargs):
        return {
            "apps_total": 1,
            "output_files": {"summary_json": "/tmp/summary.json"},
            "paper_usable_apps": 1,
        }

    monkeypatch.setattr(report, "generate_report", fake_generate_report)

    assert report.main(["--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["apps_total"] == 1
    assert payload["paper_usable_apps"] == 1


def test_generate_report_writes_retained_reuse_outputs(tmp_path: Path, monkeypatch) -> None:
    dynamic_root = tmp_path / "evidence" / "dynamic"
    selected = dynamic_root / "run-selected"
    recent = dynamic_root / "run-recent"
    old_missing = dynamic_root / "run-old-missing"
    selected.mkdir(parents=True)
    recent.mkdir(parents=True)
    old_missing.mkdir(parents=True)
    _write_manifest(
        selected,
        run_id="run-selected",
        package_name="com.example.app",
        version_code="100",
        ended_at="2026-07-08T12:00:00+00:00",
        countable=True,
    )
    _write_manifest(
        recent,
        run_id="run-recent",
        package_name="com.example.app",
        version_code="99",
        ended_at="2026-07-07T12:00:00+00:00",
    )
    _write_manifest(
        old_missing,
        run_id="run-old-missing",
        package_name="com.example.other",
        version_code="50",
        ended_at="2026-07-01T12:00:00+00:00",
        pcap=False,
    )
    monkeypatch.setattr(report, "_dynamic_root", lambda: dynamic_root)
    monkeypatch.setattr(
        report,
        "_load_app_labels",
        lambda packages: {"com.example.app": "Example Label", "com.example.other": "Other Label"},
    )
    monkeypatch.setattr(
        freeze,
        "build_paper_freeze_manifest",
        lambda package_filter=None: {
            "apps": [
                {
                    "app": "Example",
                    "package_name": "com.example.app",
                    "selected_relation": "current",
                    "selected_version_code": "100",
                    "installed_target_version_code": "100",
                    "selected_dynamic_run_ids": "run-selected",
                    "baseline_count": 3,
                    "interactive_count": 1,
                    "missing_baseline_runs": 0,
                    "missing_interactive_runs": 3,
                },
                {
                    "app": "Other",
                    "package_name": "com.example.other",
                    "selected_relation": "prior-build",
                    "selected_version_code": "50",
                    "installed_target_version_code": "55",
                    "selected_dynamic_run_ids": "run-old-missing",
                    "baseline_count": 1,
                    "interactive_count": 0,
                    "missing_baseline_runs": 2,
                    "missing_interactive_runs": 4,
                },
            ]
        },
    )
    monkeypatch.setattr(
        freeze,
        "build_paper_evidence_tier_report",
        lambda package_filter=None: {
            "rows": [
                {
                    "app": "Example",
                    "package_name": "com.example.app",
                    "evidence_tier": "CURRENT_BUILD_MIXED_BASELINE",
                    "paper_usable": "yes",
                    "retained_prior_build_count": 1,
                    "caveat": "baseline usable with caveat",
                    "recommended_final_run_tonight": "interactive if easy",
                    "future_work": "finish interactive later",
                },
                {
                    "app": "Other",
                    "package_name": "com.example.other",
                    "evidence_tier": "PRIOR_BUILD_PAPER_EVIDENCE",
                    "paper_usable": "yes",
                    "retained_prior_build_count": 1,
                },
            ]
        },
    )

    summary = report.generate_report(output_dir=tmp_path / "out", recent_days=14)

    assert summary["apps_total"] == 2
    assert summary["paper_usable_apps"] == 2
    assert summary["repair_before_use_apps"] == 1
    app_rows = list(csv.DictReader((tmp_path / "out" / "app_reuse_policy.csv").open()))
    by_pkg = {row["package_name"]: row for row in app_rows}
    assert by_pkg["com.example.app"]["app"] == "Example Label"
    assert by_pkg["com.example.app"]["reuse_policy"] == "PRIMARY_CURRENT_BUILD_WITH_CAVEAT"
    assert by_pkg["com.example.app"]["recent_context_runs"] == "1"
    assert by_pkg["com.example.other"]["reuse_policy"] == "REPAIR_BEFORE_USE"
    repair_rows = list(csv.DictReader((tmp_path / "out" / "repair_candidates.csv").open()))
    assert [row["package_name"] for row in repair_rows] == ["com.example.other"]
    context_rows = list(csv.DictReader((tmp_path / "out" / "recent_context_runs.csv").open()))
    assert [row["run_id"] for row in context_rows] == ["run-recent"]
