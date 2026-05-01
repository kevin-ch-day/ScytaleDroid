from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.menus import actions


def test_ask_run_controls_supports_test_options(monkeypatch) -> None:
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "2")

    assert actions.ask_run_controls() == "advanced"


def test_ask_run_controls_defaults_to_run(monkeypatch) -> None:
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    assert actions.ask_run_controls() == "run"
