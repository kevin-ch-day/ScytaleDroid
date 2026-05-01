from __future__ import annotations

import builtins

from scytaledroid.Utils.DisplayUtils import prompt_utils


def test_get_choice_prefers_back_on_eof_when_zero_is_available(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: (_ for _ in ()).throw(EOFError()))

    assert prompt_utils.get_choice(["1", "0"], default="1") == "0"


def test_get_choice_returns_back_when_zero_available_and_eof(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: (_ for _ in ()).throw(EOFError()))

    assert prompt_utils.get_choice(["1", "0"]) == "0"


def test_get_choice_returns_default_on_eof_without_back_option(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: (_ for _ in ()).throw(EOFError()))

    assert prompt_utils.get_choice(["1", "2"], default="1") == "1"


def test_prompt_text_returns_default_on_eof(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: (_ for _ in ()).throw(EOFError()))

    assert prompt_utils.prompt_text("Session label", default="default-session") == "default-session"
