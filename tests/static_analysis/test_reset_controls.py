from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.menus import actions


def test_confirm_reset_allows_session_only(monkeypatch):
    captured: dict[str, object] = {}

    def _choice(valid, default="1", prompt="Choice: "):
        captured["valid"] = list(valid)
        return "1"

    monkeypatch.setattr(actions.prompt_utils, "get_choice", _choice)
    mode = actions.confirm_reset()
    assert mode == "session"
    assert captured["valid"] == ["1", "0"]


def test_confirm_reset_cancel(monkeypatch):
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    assert actions.confirm_reset() is None

