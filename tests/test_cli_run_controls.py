from collections import deque

import pytest

import importlib

menu = importlib.import_module("scytaledroid.StaticAnalysis.cli.static_analysis_menu")


@pytest.mark.parametrize(
    "responses, expected",
    [
        ([""], "run"),
        (["__default__"], "run"),
        (["r"], "run"),
        (["R"], "run"),
        (["run"], "run"),
        (["1"], "run"),
        (["a"], "advanced"),
        (["A"], "advanced"),
        (["adv"], "advanced"),
        (["advanced"], "advanced"),
        (["2"], "advanced"),
        (["0"], "back"),
        (["back"], "back"),
        (["b"], "back"),
    ],
)
def test_ask_run_controls_accepts_shortcuts(monkeypatch, capsys, responses, expected):
    answers = deque(responses)

    def fake_prompt(prompt, *, default=None, required=True, error_message=None):
        if not answers:
            raise AssertionError("Prompt called more times than expected")
        value = answers.popleft()
        if value == "__default__":
            return default or ""
        return value

    monkeypatch.setattr(menu.prompt_utils, "prompt_text", fake_prompt)
    monkeypatch.setattr(menu.menu_utils, "print_section", lambda title: print(title))

    result = menu.ask_run_controls()
    captured = capsys.readouterr().out

    assert result == expected
    assert "Invalid choice" not in captured


def test_ask_run_controls_reprompts_on_invalid(monkeypatch, capsys):
    answers = deque(["zzz", "r"])

    def fake_prompt(prompt, *, default=None, required=True, error_message=None):
        if not answers:
            raise AssertionError("Prompt called more times than expected")
        value = answers.popleft()
        if value == "__default__":
            return default or ""
        return value

    monkeypatch.setattr(menu.prompt_utils, "prompt_text", fake_prompt)
    monkeypatch.setattr(menu.menu_utils, "print_section", lambda title: print(title))

    result = menu.ask_run_controls()
    captured = capsys.readouterr().out

    assert result == "run"
    assert captured.count("Invalid choice. Please try again.") == 1
