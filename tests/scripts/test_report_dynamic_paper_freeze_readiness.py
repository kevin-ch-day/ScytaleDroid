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

    rc = report.main(["--output-dir", str(tmp_path), "--stdout-json"])
    assert rc == 0

    manifest_json = tmp_path / "paper_freeze_manifest.json"
    manifest_csv = tmp_path / "paper_freeze_manifest.csv"
    plan_csv = tmp_path / "paper_minimal_run_plan.csv"
    board_json = tmp_path / "paper_freeze_decision_board.json"
    board_csv = tmp_path / "paper_freeze_decision_board.csv"

    assert manifest_json.exists()
    assert manifest_csv.exists()
    assert plan_csv.exists()
    assert board_json.exists()
    assert board_csv.exists()

    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    assert manifest["apps"][0]["strict_idle_count"] == 0
    assert manifest["apps"][0]["quiescent_fg_count"] == 7

    board = json.loads(board_json.read_text(encoding="utf-8"))
    assert board["rows"][0]["action"] == "strict idle retry"
    assert board["rows"][0]["baseline_class_note"].startswith("Quiescent FG evidence")

    board_csv_text = board_csv.read_text(encoding="utf-8")
    assert "strict_idle_count" in board_csv_text
    assert "quiescent_fg_count" in board_csv_text
    assert "baseline_class_note" in board_csv_text

    plan_csv_text = plan_csv.read_text(encoding="utf-8")
    assert "recommended_next_action" in plan_csv_text
    assert "strict_idle_count" in plan_csv_text
    assert "quiescent_fg_count" in plan_csv_text
    assert "strict idle retry" in plan_csv_text

    out = capsys.readouterr().out
    summary = json.loads(out)
    assert summary["paper_freeze_decision_board_json"].endswith("paper_freeze_decision_board.json")
    assert summary["paper_freeze_decision_board_csv"].endswith("paper_freeze_decision_board.csv")
