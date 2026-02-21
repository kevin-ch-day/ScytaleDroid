from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.menus import actions


def test_suggest_session_label_for_profile_scope():
    params = RunParameters(
        profile="full",
        scope="profile",
        scope_label="Research Dataset Alpha",
        session_stamp="20260221",
    )
    suggested = actions._suggest_session_label(params)
    assert suggested.startswith("20260221-")
    assert suggested.endswith("-full")
    assert "rda" in suggested


def test_suggest_session_label_keeps_custom_value():
    params = RunParameters(
        profile="full",
        scope="profile",
        scope_label="Research Dataset Alpha",
        session_stamp="20260221-gatefix3",
    )
    assert actions._suggest_session_label(params) == "20260221-gatefix3"


def test_prompt_session_label_uses_suggested_default(monkeypatch):
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="20260221",
    )
    seen: dict[str, str] = {}

    def _prompt(_label, *, default=None, **_kwargs):
        seen["default"] = default or ""
        return ""

    monkeypatch.setattr(actions.prompt_utils, "prompt_text", _prompt)
    updated = actions.prompt_session_label(params)
    assert seen["default"] == "20260221-all-full"
    assert updated.session_stamp == "20260221-all-full"
