from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_paper3_writing_package as report


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _make_cutoff_fixture(root: Path) -> Path:
    cutoff = root / "dynamic_paper_freeze_fixture"
    summary = {
        "apps_total": 2,
        "evidence_tier_summary": {
            "apps_total": 2,
            "paper_usable": 2,
            "true_evidence_holes": 0,
            "tier_counts": {
                "STRICT_CURRENT_BUILD_COMPLETE": 1,
                "PRIOR_BUILD_PAPER_EVIDENCE": 1,
            },
        },
    }
    tiers = {
        "cohort_label": "Research Dataset Beta",
        "summary": summary["evidence_tier_summary"],
        "rows": [
            {
                "app": "BBC News",
                "package_name": "bbc.mobile.news.ww",
                "evidence_tier": "STRICT_CURRENT_BUILD_COMPLETE",
                "paper_usable": "yes",
                "selected_relation": "current",
                "selected_version_code": "100",
                "selected_version_name": "1.0",
                "installed_version_code": "100",
                "strict_idle_count": "3",
                "quiescent_fg_count": "0",
                "interactive_count": "4",
                "pcap_available_count": "7",
                "caveat": "Strict current-build complete.",
            },
            {
                "app": "X",
                "package_name": "com.twitter.android",
                "evidence_tier": "PRIOR_BUILD_PAPER_EVIDENCE",
                "paper_usable": "yes",
                "selected_relation": "prior-build",
                "selected_version_code": "200",
                "selected_version_name": "2.0",
                "installed_version_code": "201",
                "strict_idle_count": "3",
                "quiescent_fg_count": "1",
                "interactive_count": "4",
                "pcap_available_count": "8",
                "caveat": "Prior-build evidence remains labeled.",
            },
        ],
    }
    manifest = {
        "cohort_label": "Research Dataset Beta",
        "summary": {
            "apps_total": 2,
            "ready": 2,
            "ready_current": 1,
            "ready_prior": 1,
            "needs_baseline": 0,
            "needs_interactive": 0,
            "insufficient": 0,
        },
        "apps": tiers["rows"],
    }
    board = {
        "cohort_label": "Research Dataset Beta",
        "summary": manifest["summary"],
        "rows": [
            {
                "app": "BBC News",
                "package_name": "bbc.mobile.news.ww",
                "relation": "current",
                "strict_idle_count": "3",
                "quiescent_fg_count": "0",
                "interactive_count": "4",
                "action": "none",
                "reason": "Already complete.",
            },
            {
                "app": "X",
                "package_name": "com.twitter.android",
                "relation": "prior-build",
                "strict_idle_count": "3",
                "quiescent_fg_count": "1",
                "interactive_count": "4",
                "action": "future refresh only",
                "reason": "Paper evidence is usable.",
            },
        ],
    }
    _write_json(cutoff / "summary.json", summary)
    _write_json(cutoff / "paper_evidence_tiers.json", tiers)
    _write_csv(cutoff / "paper_evidence_tiers.csv", tiers["rows"])
    _write_json(cutoff / "paper_freeze_manifest.json", manifest)
    _write_csv(cutoff / "paper_freeze_manifest.csv", manifest["apps"])
    _write_json(cutoff / "paper_freeze_decision_board.json", board)
    _write_csv(cutoff / "paper_freeze_decision_board.csv", board["rows"])
    _write_csv(
        cutoff / "paper_minimal_run_plan.csv",
        [
            {
                "app": "BBC News",
                "package_name": "bbc.mobile.news.ww",
                "paper_target_relation": "current",
                "missing_baseline_runs": "0",
                "missing_interactive_runs": "0",
                "refresh_candidate": "no",
                "recommended_next_action": "none",
            },
            {
                "app": "X",
                "package_name": "com.twitter.android",
                "paper_target_relation": "prior-build",
                "missing_baseline_runs": "0",
                "missing_interactive_runs": "1",
                "refresh_candidate": "yes",
                "recommended_next_action": "interactive",
            }
        ],
    )
    return cutoff


def _make_bridge_fixture(root: Path) -> Path:
    bridge = root / "paper3_bridge_fixture"
    bridge.mkdir(parents=True, exist_ok=True)
    (bridge / "paper3_bridge_summary.md").write_text("# Bridge\n\nExisting bridge summary.\n", encoding="utf-8")
    (bridge / "paper3_recommended_tables.md").write_text("# Tables\n\nExisting table plan.\n", encoding="utf-8")
    _write_csv(
        bridge / "paper3_claims_matrix.csv",
        [
            {
                "claim_id": "C01",
                "claim_text": "Paper 1 studied six apps.",
                "source": "Paper 1",
                "claim_status": "reuse",
                "evidence_source": "paper1.pdf",
                "affected_apps": "six apps",
                "required_caveat": "lineage only",
                "suggested_paper3_wording": "Paper 1 provides the static predecessor snapshot.",
            },
            {
                "claim_id": "C02",
                "claim_text": "QFG equals strict idle.",
                "source": "Paper 3",
                "claim_status": "not_safe",
                "evidence_source": "cutoff",
                "affected_apps": "all",
                "required_caveat": "never say this",
                "suggested_paper3_wording": "QFG is reported separately from strict idle.",
            },
            {
                "claim_id": "C03",
                "claim_text": "Static evidence is clean.",
                "source": "Paper 3",
                "claim_status": "not_safe_without_rewording",
                "evidence_source": "static audit",
                "affected_apps": "all",
                "required_caveat": "report detector/resource caveats",
                "suggested_paper3_wording": "Static evidence is auditable with caveats.",
            },
        ],
    )
    return bridge


def test_help_exits_zero() -> None:
    repo = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "db" / "report_paper3_writing_package.py"), "--help"],
        cwd=str(repo),
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "integrated-study writing workspace" in (proc.stdout + proc.stderr).lower()


def test_missing_cutoff_dir_fails_clearly(tmp_path: Path, capsys) -> None:
    rc = report.main(["--cutoff-dir", str(tmp_path / "missing"), "--output-dir", str(tmp_path / "out")])
    assert rc == 2
    captured = capsys.readouterr()
    assert "cutoff directory does not exist" in captured.err


def test_missing_required_run_plan_fails_clearly(tmp_path: Path, capsys) -> None:
    cutoff = _make_cutoff_fixture(tmp_path)
    (cutoff / "paper_minimal_run_plan.csv").unlink()

    rc = report.main(["--cutoff-dir", str(cutoff), "--output-dir", str(tmp_path / "out")])

    assert rc == 2
    captured = capsys.readouterr()
    assert "paper_minimal_run_plan.csv" in captured.err


def test_valid_fixture_generates_workspace_manifest_claims_and_tables(tmp_path: Path) -> None:
    cutoff = _make_cutoff_fixture(tmp_path)
    bridge = _make_bridge_fixture(tmp_path)
    output = tmp_path / "workspace"

    manifest = report.generate_package(cutoff_dir=cutoff, bridge_dir=bridge, output_dir=output)

    expected_files = {
        "paper3_outline.md",
        "paper3_submission_context.md",
        "paper3_working_outline.md",
        "paper3_section_plan.md",
        "paper3_introduction_draft.md",
        "paper3_background_draft.md",
        "paper3_methodology_draft.md",
        "paper3_results_draft.md",
        "paper3_discussion_draft.md",
        "paper3_limitations_draft.md",
        "paper3_conclusion_draft.md",
        "paper3_tables_latex.tex",
        "paper3_tables_markdown.md",
        "paper3_claims_control.md",
        "paper3_next_revision_items.md",
        "paper3_open_questions.md",
        "paper3_source_manifest.json",
        "paper3_bridge_notes_used.md",
    }
    assert expected_files <= {path.name for path in output.iterdir()}

    written_manifest = json.loads((output / "paper3_source_manifest.json").read_text(encoding="utf-8"))
    assert written_manifest["paper_usable_count"] == 2
    assert written_manifest["apps_total"] == 2
    assert written_manifest["true_evidence_holes"] == 0
    assert written_manifest["tier_counts"]["STRICT_CURRENT_BUILD_COMPLETE"] == 1
    assert written_manifest["tier_counts"]["PRIOR_BUILD_PAPER_EVIDENCE"] == 1
    assert written_manifest["evidence_mutated"] is False
    assert written_manifest["db_rows_mutated"] is False
    assert written_manifest["quota_math_mutated"] is False
    assert written_manifest["tracker_countability_mutated"] is False
    assert written_manifest["writing_package_generator"] == "scripts/db/report_paper3_writing_package.py"
    assert written_manifest["generated_from_current_source"] is True
    assert written_manifest["manual_bridge_artifacts_supplied"] is True
    assert written_manifest["publication_target"] == {
        "submission_id": "IEEE-CARS-2026",
        "paper_label": "ScytaleDroid Paper #3",
        "generation_label": "ScytaleDroid Paper #3 | IEEE CARS 2026",
        "venue": "IEEE Cyber Awareness and Research Symposium (IEEE CARS 2026)",
        "venue_short_label": "IEEE CARS 2026",
        "target_format": "IEEE conference format",
    }
    assert written_manifest["last_run_recommendation_source"] == "paper_minimal_run_plan.csv"
    assert written_manifest["last_run_recommendation"]["required"] == "none"
    assert written_manifest["last_run_recommendation"]["optional_final_polish"] == (
        "none; collection paused; start writing"
    )
    assert written_manifest["last_run_recommendation"]["optional_candidates"] == []
    assert written_manifest["last_run_recommendation"]["future_work_candidates"][0]["app"] == "X"
    assert written_manifest["last_run_recommendation"]["future_work_candidates"][0]["missing_interactive_runs"] == 1
    assert any(row["path"].endswith("paper_evidence_tiers.csv") for row in written_manifest["source_files_used"])
    assert all(row.get("sha256") for row in written_manifest["source_files_used"])
    assert all(row.get("sha256") for row in written_manifest["generated_files"])
    assert manifest["output_dir"] == str(output)

    claims = (output / "paper3_claims_control.md").read_text(encoding="utf-8")
    assert "## Safe Claims" in claims
    assert "## Claims Needing Caveats" in claims
    assert "## Claims To Avoid" in claims
    assert "Paper 1 provides the static predecessor snapshot." in claims
    assert "QFG is reported separately from strict idle." in claims

    tables = (output / "paper3_tables_markdown.md").read_text(encoding="utf-8")
    assert "Evidence Tier Summary" in tables
    assert "Publication-usable apps | 2/2" in tables
    assert "PRIOR_BUILD_PAPER_EVIDENCE" in tables

    outline = (output / "paper3_working_outline.md").read_text(encoding="utf-8")
    assert "Collection is paused; use the cutoff bundle and start writing" in outline
    final_outline = (output / "paper3_outline.md").read_text(encoding="utf-8")
    assert "# Integrated Study Outline" in final_outline
    assert "Generation target:** ScytaleDroid Paper #3 | IEEE CARS 2026" in final_outline
    assert "\\n**Submission package ID" not in final_outline
    assert "Non-blocking run-plan rows are retained only as future-work provenance" in final_outline
    submission_context = (output / "paper3_submission_context.md").read_text(encoding="utf-8")
    assert "IEEE Cyber Awareness and Research Symposium (IEEE CARS 2026)" in submission_context
    assert "not a submission package" in submission_context
    next_items = (output / "paper3_next_revision_items.md").read_text(encoding="utf-8")
    assert "# Next Revision Items" in next_items

    latex = (output / "paper3_tables_latex.tex").read_text(encoding="utf-8")
    assert "Selected 15-app evidence bundles at cutoff" in latex
    assert "Research Dataset Beta evidence bundles at cutoff" not in latex
    assert "com.twitter.android" in latex

    introduction = (output / "paper3_introduction_draft.md").read_text(encoding="utf-8")
    manifest_warnings = "\n".join(written_manifest["warnings"])
    public_generated_text = "\n".join(
        [
            tables,
            final_outline,
            introduction,
            latex,
            (output / "paper3_limitations_draft.md").read_text(encoding="utf-8"),
            manifest_warnings,
        ]
    )
    assert "ScytaleDroid Paper #3 | IEEE CARS 2026" in public_generated_text


def test_main_stdout_json_reports_manifest(tmp_path: Path, capsys) -> None:
    cutoff = _make_cutoff_fixture(tmp_path)
    out = tmp_path / "out"
    rc = report.main(["--cutoff-dir", str(cutoff), "--output-dir", str(out), "--stdout-json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["output_dir"] == str(out)
    assert payload["paper_usable_count"] == 2
    assert (out / "paper3_source_manifest.json").exists()


def test_default_workspace_name_uses_submission_identifier(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(report, "_REPO_ROOT", tmp_path)
    assert report._default_output_dir().parent == tmp_path / "output" / "paper"
    assert report._default_output_dir().name.startswith("IEEE-CARS-2026_draft_workspace_")


def test_current_manuscript_is_hashed_as_an_explicit_source(tmp_path: Path) -> None:
    cutoff = _make_cutoff_fixture(tmp_path)
    manuscript = tmp_path / "IEEE_CARS_2026_Paper.pdf"
    manuscript.write_bytes(b"paper-pdf-bytes")

    manifest = report.generate_package(
        cutoff_dir=cutoff,
        output_dir=tmp_path / "workspace",
        manuscript_pdf=manuscript,
    )

    assert manifest["manuscript_pdf"] == str(manuscript)
    assert any(row["path"] == str(manuscript) and row["sha256"] for row in manifest["source_files_used"])
    context = (tmp_path / "workspace" / "paper3_submission_context.md").read_text(encoding="utf-8")
    assert f"Current manuscript PDF: `{manuscript}`" in context
    assert "\\n**Submission package ID" not in context
