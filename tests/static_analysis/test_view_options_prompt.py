from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.commands.models import Command
from scytaledroid.StaticAnalysis.cli.menus import static_analysis_menu_helpers as helpers


def _command() -> Command:
    return Command(
        id="full",
        title="Full analysis",
        description="Run full static profile.",
        kind="scan",
        profile="full",
    )


def test_collect_view_options_defaults_to_summary(monkeypatch):
    captured: dict[str, object] = {}

    def _choice(valid, default="1", prompt=""):
        captured["valid"] = list(valid)
        captured["default"] = default
        captured["prompt"] = prompt
        return "1"

    monkeypatch.setattr(helpers.prompt_utils, "get_choice", _choice)
    result = helpers.collect_view_options(_command())
    assert result == (True, False, False, False)
    assert captured["valid"] == ["1", "2", "3", "0"]
    assert captured["default"] == "1"
    assert captured["prompt"] == "Select option [1]: "


def test_collect_view_options_return_to_menu(monkeypatch):
    monkeypatch.setattr(helpers.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    assert helpers.collect_view_options(_command()) == (False, False, False, True)
