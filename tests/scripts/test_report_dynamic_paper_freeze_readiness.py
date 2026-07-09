from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_paper_freeze_readiness as report
from scytaledroid.DynamicAnalysis.services import paper_freeze_readiness as freeze


def test_help_exits_zero() -> None:
    repo = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "db" / "report_dynamic_paper_freeze_readiness.py"), "--help"],
        cwd=str(repo),
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = ((proc.stdout or "") + (proc.stderr or "")).lower()
    assert "paper-freeze readiness report" in out


def test_main_writes_manifest_plan_and_decision_board_exports(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        freeze,
        "build_paper_freeze_manifest",
        lambda package_filter=None: {
            "cohort_label": "Research Dataset Beta",
            "summary": {
                "apps_total": 1,
                "ready": 0,
                "ready_current": 0,
                "ready_prior": 0,
                "needs_baseline": 1,
                "needs_interactive": 0,
                "insufficient": 0,
                "refresh_candidates": 0,
            },
            "apps": [
                {
                    "app": "TikTok",
                    "package_name": "com.zhiliaoapp.musically",
                    "selected_version_code": "2024507030",
                    "selected_version_name": "45.7.3",
                    "selected_relation": "current",
                    "strict_idle_count": 0,
                    "quiescent_fg_count": 7,
                    "interactive_count": 2,
                    "baseline_count": 0,
                    "missing_baseline_runs": 3,
                    "missing_interactive_runs": 2,
                    "status": "needs baseline",
                    "baseline_class_note": "Quiescent FG evidence is retained and analysis-included, but strict idle is incomplete.",
                    "build_candidates": [],
                }
            ],
            "paper_minimal_run_plan": [
                {
                    "app": "TikTok",
                    "package_name": "com.zhiliaoapp.musically",
                    "strict_idle_count": 0,
                    "quiescent_fg_count": 7,
                    "strict_idle_ready": "no",
                    "baseline_class_note": "Quiescent FG evidence is retained and analysis-included, but strict idle is incomplete.",
                    "recommended_next_action": "strict idle retry",
                }
            ],
        },
    )
    monkeypatch.setattr(
        freeze,
        "build_paper_evidence_tier_report",
        lambda package_filter=None, live_drift_map=None: {
            "cohort_label": "Research Dataset Beta",
            "summary": {
                "apps_total": 1,
                "paper_usable": 1,
                "drifted_but_paper_usable": 1,
                "context_only": 0,
                "true_evidence_holes": 0,
                "tier_counts": {"CURRENT_BUILD_MIXED_BASELINE": 1},
            },
            "rows": [
                {
                    "app": "TikTok",
                    "package_name": "com.zhiliaoapp.musically",
                    "evidence_tier": "CURRENT_BUILD_MIXED_BASELINE",
                    "paper_usable": "yes",
                    "selected_relation": "current",
                    "selected_version_code": "2024507030",
                    "operational_installed_version_code": "2024509040",
                    "operational_live_drifted": "yes",
                    "operational_drift_detail": "live installed build changed after cutoff",
                    "strict_idle_count": 0,
                    "quiescent_fg_count": 7,
                    "caveat": "QFG reported separately.",
                    "recommended_final_run_tonight": "interactive only if easy",
                }
            ],
        },
    )
    monkeypatch.setattr(
        freeze,
        "build_paper_freeze_decision_board",
        lambda package_filter=None: {
            "cohort_label": "Research Dataset Beta",
            "rows": [
                {
                    "app": "TikTok",
                    "package_name": "com.zhiliaoapp.musically",
                    "selected_version_code": "2024507030",
                    "installed_version_code": "2024507030",
                    "relation": "current",
                    "strict_idle_count": 0,
                    "quiescent_fg_count": 7,
                    "interactive_count": 2,
                    "baseline_count": 0,
                    "missing_baseline_runs": 3,
                    "missing_interactive_runs": 2,
                    "valid_pcap_count": 9,
                    "baseline_class_note": "Quiescent FG evidence is retained and analysis-included, but strict idle is incomplete.",
                    "draft_role": "current_gap",
                    "collectability": "collectable_now",
                    "action": "strict idle retry",
                    "rough_draft_blocker": "yes",
                    "reason": "Selected current build is collectable now; quiescent foreground evidence exists, but strict-idle baseline quota is still incomplete.",
                    "bucket": "MUST_RUN_NOW",
                }
            ],
            "sections": {"MUST_RUN_NOW": []},
            "summary": {"needs_baseline": 1},
        },
    )
    monkeypatch.setattr(
        report,
        "_load_app_labels",
        lambda packages: {"com.zhiliaoapp.musically": "TikTok"},
    )
    monkeypatch.setattr(
        report,
        "_load_live_drift_map",
        lambda packages: (
            {"com.zhiliaoapp.musically": {"observed_version_code": "2024509040"}},
            "ZY22",
            "moto g",
        ),
    )

    rc = report.main(["--output-dir", str(tmp_path), "--stdout-json"])
    assert rc == 0

    manifest_json = tmp_path / "paper_freeze_manifest.json"
    manifest_csv = tmp_path / "paper_freeze_manifest.csv"
    plan_csv = tmp_path / "paper_minimal_run_plan.csv"
    board_json = tmp_path / "paper_freeze_decision_board.json"
    board_csv = tmp_path / "paper_freeze_decision_board.csv"
    tier_json = tmp_path / "paper_evidence_tiers.json"
    tier_csv = tmp_path / "paper_evidence_tiers.csv"
    summary_json = tmp_path / "summary.json"

    assert manifest_json.exists()
    assert manifest_csv.exists()
    assert plan_csv.exists()
    assert board_json.exists()
    assert board_csv.exists()
    assert tier_json.exists()
    assert tier_csv.exists()
    assert summary_json.exists()

    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    assert manifest["apps"][0]["strict_idle_count"] == 0
    assert manifest["apps"][0]["quiescent_fg_count"] == 7

    board = json.loads(board_json.read_text(encoding="utf-8"))
    assert board["rows"][0]["action"] == "strict idle retry"
    assert board["rows"][0]["baseline_class_note"].startswith("Quiescent FG evidence")
    tier = json.loads(tier_json.read_text(encoding="utf-8"))
    assert tier["rows"][0]["evidence_tier"] == "CURRENT_BUILD_MIXED_BASELINE"

    board_csv_text = board_csv.read_text(encoding="utf-8")
    assert "strict_idle_count" in board_csv_text
    assert "quiescent_fg_count" in board_csv_text
    assert "baseline_class_note" in board_csv_text

    plan_csv_text = plan_csv.read_text(encoding="utf-8")
    assert "recommended_next_action" in plan_csv_text
    assert "strict_idle_count" in plan_csv_text
    assert "quiescent_fg_count" in plan_csv_text
    assert "strict idle retry" in plan_csv_text
    tier_csv_text = tier_csv.read_text(encoding="utf-8")
    assert "evidence_tier" in tier_csv_text
    assert "CURRENT_BUILD_MIXED_BASELINE" in tier_csv_text
    assert "operational_live_drifted" in tier_csv_text

    out = capsys.readouterr().out
    summary = json.loads(out)
    written_summary = json.loads(summary_json.read_text(encoding="utf-8"))
    assert written_summary == summary
    assert summary["live_drift_checked"] is True
    assert summary["live_drifted_package_count"] == 1
    assert summary["paper_freeze_decision_board_json"].endswith("paper_freeze_decision_board.json")
    assert summary["paper_freeze_decision_board_csv"].endswith("paper_freeze_decision_board.csv")
    assert summary["paper_evidence_tiers_json"].endswith("paper_evidence_tiers.json")
    assert summary["paper_evidence_tiers_csv"].endswith("paper_evidence_tiers.csv")
    assert summary["summary_json"].endswith("summary.json")
    assert summary["evidence_tier_summary"]["paper_usable"] == 1
    assert summary["evidence_tier_summary"]["drifted_but_paper_usable"] == 1

    alias_dir = tmp_path / "alias"
    rc = report.main(["--output-dir", str(alias_dir), "--json", "--skip-live-drift"])
    assert rc == 0
    alias_summary = json.loads(capsys.readouterr().out)
    assert alias_summary["paper_freeze_manifest_json"].endswith("paper_freeze_manifest.json")
    assert alias_summary["live_drift_checked"] is False


def test_tier_summary_separates_live_drift_from_retained_prior_build(monkeypatch) -> None:
    candidate = freeze.PaperFreezeBuildCandidate(
        package_name="com.example.app",
        version_code="100",
        version_name="1.0",
        static_run_id="10",
        base_apk_sha256="a" * 64,
        strict_idle_runs=3,
        quiescent_fg_runs=0,
        baseline_valid_runs=3,
        interactive_valid_runs=4,
        valid_pcap_count=7,
        qa_valid_count=7,
        first_capture_at="2026-07-09T00:00:00Z",
        last_capture_at="2026-07-09T01:00:00Z",
        relation_to_active_target="prior-build",
        missing_baseline_runs=0,
        missing_interactive_runs=0,
        status="ready",
        static_run_ids=("10",),
        run_ids=("r1",),
    )
    recommendation = freeze.PaperFreezeRecommendation(
        package_name="com.example.app",
        installed_target_version_code="200",
        installed_target_version_name="2.0",
        installed_target_static_run_id="20",
        installed_target_base_apk_sha256="b" * 64,
        selected_build=candidate,
        build_candidates=(candidate,),
        refresh_candidate=True,
        retained_prior_build_selected=True,
    )

    monkeypatch.setattr(freeze, "_load_tracker_payload", lambda cfg: ("ok", {"apps": {"com.example.app": {"runs": []}}}, {}))
    monkeypatch.setattr(freeze, "active_research_cohort_packages", lambda: ("com.example.app",))
    monkeypatch.setattr(freeze, "active_research_cohort_label", lambda: "Research Dataset Beta")
    monkeypatch.setattr(freeze, "recommend_paper_freeze_for_runs", lambda package_name, runs, cfg: recommendation)

    report_no_live_drift = freeze.build_paper_evidence_tier_report(live_drift_map={})
    summary = report_no_live_drift["summary"]

    assert summary["paper_usable"] == 1
    assert summary["prior_build_paper_usable"] == 1
    assert summary["non_strict_current_paper_usable"] == 1
    assert summary["live_drift_detected_paper_usable"] == 0
    assert summary["drifted_but_paper_usable"] == 1

    report_with_live_drift = freeze.build_paper_evidence_tier_report(
        live_drift_map={"com.example.app": {"observed_version_code": "300"}}
    )
    assert report_with_live_drift["summary"]["live_drift_detected_paper_usable"] == 1
