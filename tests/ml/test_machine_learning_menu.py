from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml import menu as ml_menu


def test_machine_learning_menu_exposes_paper2_and_static_dynamic_workflows(monkeypatch) -> None:
    rendered: list[list[str]] = []

    monkeypatch.setattr(ml_menu, "_print_ml_status", lambda *, compact=False: None)

    def _capture_menu(items, **_kwargs):
        rendered.append([item.label for item in items])

    monkeypatch.setattr(ml_menu.menu_utils, "print_menu", _capture_menu)
    monkeypatch.setattr(ml_menu.prompt_utils, "menu_choice", lambda *_a, **_k: "0")

    ml_menu.machine_learning_menu()

    assert rendered == [
        [
            "Show ML readiness and output paths",
            "Build dataset freeze anchor",
            "Run freeze-anchored unsupervised ML scoring",
            "Generate Paper 2 ML deliverable bundle",
            "Run ML QA audit",
            "Generate runtime behavior ML report",
            "Generate static + dynamic ML score report",
            "Show commands and output map",
        ]
    ]


def test_run_action_handles_system_exit_message(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ml_menu.prompt_utils, "press_enter_to_continue", lambda: None)

    def _raises_message():
        raise SystemExit("Missing freeze anchor")

    ml_menu._run_action(title="ML QA Audit", action=_raises_message)

    out = capsys.readouterr().out
    assert "ML QA Audit failed: Missing freeze anchor" in out


def test_display_freeze_anchor_uses_active_path_when_missing(monkeypatch, tmp_path) -> None:
    active = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    legacy = tmp_path / "archive" / "dataset_freeze.json"

    monkeypatch.setattr(ml_menu, "default_freeze_manifest_path", lambda: legacy)
    monkeypatch.setattr(ml_menu, "active_dataset_freeze_path", lambda: active)

    assert ml_menu._display_freeze_anchor_path() == active


def test_display_freeze_anchor_keeps_existing_resolved_path(monkeypatch, tmp_path) -> None:
    active = tmp_path / "archive" / "research_cohorts" / "research_dataset_beta" / "dataset_freeze.json"
    legacy = tmp_path / "archive" / "dataset_freeze.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(ml_menu, "default_freeze_manifest_path", lambda: legacy)
    monkeypatch.setattr(ml_menu, "active_dataset_freeze_path", lambda: active)

    assert ml_menu._display_freeze_anchor_path() == legacy
