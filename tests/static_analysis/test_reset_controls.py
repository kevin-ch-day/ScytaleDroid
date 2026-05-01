from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.menus import actions
from scytaledroid.StaticAnalysis.cli.commands.models import Command


def test_confirm_reset_allows_session_only(monkeypatch):
    captured: dict[str, object] = {}

    def _choice(valid, default="1", prompt="Choice: "):
        captured["valid"] = list(valid)
        return "1"

    monkeypatch.setattr(actions.prompt_utils, "get_choice", _choice)
    mode = actions.confirm_reset("20260428-all-full-rerun1")
    assert mode == "session"
    assert captured["valid"] == ["1", "0"]


def test_confirm_reset_cancel(monkeypatch):
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    assert actions.confirm_reset() is None


def test_render_run_preflight_shows_session_strategy_and_retention(capsys):
    params = actions.RunParameters(
        profile="full",
        scope="all",
        scope_label="All harvested apps",
        session_stamp="20260428-all-full-rerun1",
    )
    selection = SimpleNamespace(
        label="All harvested apps",
        groups=(
            SimpleNamespace(artifacts=("a.apk", "b.apk")),
            SimpleNamespace(artifacts=("c.apk",)),
        ),
    )
    command = Command(
        id="scan-full",
        title="Full analysis",
        description="Run full analysis",
        kind="scan",
        profile="full",
        persist=True,
    )

    actions.render_run_preflight(params, selection, command, reset_mode="session")
    out = capsys.readouterr().out
    assert "Run preflight" in out
    assert "Session label   : 20260428-all-full-rerun1" in out
    assert "Packages        : 2" in out
    assert "Artifacts est.  : 3" in out
    assert "Mode            : Full | workers=auto" in out
    assert "Reset           : session" in out
