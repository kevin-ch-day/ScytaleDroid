import builtins

from scytaledroid.Utils.DisplayUtils import prompt_utils


def test_get_choice_normalises_casefold_default(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda _: "")

    result = prompt_utils.get_choice(["alpha"], default="ALPHA", casefold=True)

    assert result == "alpha"


def test_get_choice_falls_back_to_first_option(monkeypatch):
    calls = iter([""])
    monkeypatch.setattr(builtins, "input", lambda _: next(calls))

    result = prompt_utils.get_choice(["first", "second"], default="missing")

    assert result == "first"
