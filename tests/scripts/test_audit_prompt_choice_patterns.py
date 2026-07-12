from __future__ import annotations

from pathlib import Path

from scripts.ux import audit_prompt_choice_patterns as audit


def test_collect_prompt_choice_rows_classifies_prompt_patterns(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    module = repo / "pkg" / "menu.py"
    module.parent.mkdir(parents=True)
    module.write_text(
        "\n".join(
            [
                "from scytaledroid.Utils.DisplayUtils import prompt_utils, menu_utils",
                "menu_utils.print_menu([])",
                "prompt_utils.menu_choice(['1', '0'])",
                "prompt_utils.get_choice(['1', '0'], default='0')",
                "prompt_utils.get_choice(['1'], prompt='Enter choice: ')",
                "prompt_utils.get_choice(['1'], default='1')",
                "prompt_utils.prompt_yes_no('Apply changes?', default=False)",
                "prompt_utils.prompt_yes_no('Apply migration now?', default=True)",
                "input('raw prompt')",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(audit, "REPO_ROOT", repo)

    rows = audit.collect_prompt_choice_rows(["pkg"])
    classes = {row["finding_class"] for row in rows}

    assert "menu_render" in classes
    assert "standard_menu_choice_helper" in classes
    assert "menu_choice_enter_defaults_back" in classes
    assert "custom_choice_prompt_text" in classes
    assert "menu_choice_enter_selects_action" in classes
    assert "yes_no_prompt" in classes
    assert "yes_no_mutation_default_yes" in classes
    assert "direct_input_outside_prompt_utils" in classes


def test_generate_audit_writes_summary_and_review_candidates(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    module = repo / "pkg" / "menu.py"
    module.parent.mkdir(parents=True)
    module.write_text("input('raw prompt')\n", encoding="utf-8")
    monkeypatch.setattr(audit, "REPO_ROOT", repo)

    out_dir = tmp_path / "out"
    summary = audit.generate_audit(scan_roots=["pkg"], output_dir=out_dir)

    assert summary["row_count"] == 1
    assert summary["finding_counts"] == {"direct_input_outside_prompt_utils": 1}
    assert (out_dir / "summary.json").exists()
    assert "raw prompt" in (out_dir / "review_candidates.csv").read_text(encoding="utf-8")
