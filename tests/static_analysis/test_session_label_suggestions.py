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
        session_label="20260221-gatefix3",
        session_stamp="20260221-gatefix3",
    )
    assert actions._suggest_session_label(params) == "20260221-gatefix3"


def test_suggest_session_label_rebuilds_generated_default_for_smoke_batch():
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="Smoke batch (10 apps)",
        session_stamp="20260428-all-full",
    )

    assert actions._suggest_session_label(params) == "20260428-all-smoke10-full"


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


def test_prompt_session_label_detects_existing_db_session_on_default(monkeypatch, tmp_path):
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="20260428-all-full",
    )

    monkeypatch.setattr(actions.app_config, "DATA_DIR", str(tmp_path))

    def _prompt(_label, *, default=None, **_kwargs):
        assert default == "20260428-all-full"
        return ""

    def _run_sql(query, params=None, fetch=None):
        sql = " ".join(str(query).split()).lower()
        if "count(*) from static_analysis_runs where session_label=%s" in sql:
            return (120,)
        if "where session_label=%s and is_canonical=1" in sql:
            return (582,)
        raise AssertionError(f"unexpected sql: {sql}")

    monkeypatch.setattr(actions.prompt_utils, "prompt_text", _prompt)
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "2")
    monkeypatch.setattr(actions, "core_q", type("_DB", (), {"run_sql": staticmethod(_run_sql)})())

    updated = actions.prompt_session_label(params)

    assert updated.canonical_action == "append"
    assert updated.session_stamp == "20260428-all-full-121"


def test_prompt_session_label_defaults_to_append_for_smoke_batch(monkeypatch, tmp_path):
    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="Smoke batch (10 apps)",
        session_stamp="20260428-all-full",
    )

    monkeypatch.setattr(actions.app_config, "DATA_DIR", str(tmp_path))

    seen: dict[str, str] = {}

    def _prompt(_label, *, default=None, **_kwargs):
        seen["default"] = default or ""
        return ""

    def _run_sql(query, params=None, fetch=None):
        sql = " ".join(str(query).split()).lower()
        if "count(*) from static_analysis_runs where session_label=%s" in sql:
            return (10,)
        if "where session_label=%s and is_canonical=1" in sql:
            return (1076,)
        raise AssertionError(f"unexpected sql: {sql}")

    def _get_choice(_choices, default=None, prompt=None, **_kwargs):
        seen["strategy_default"] = str(default or "")
        return "2"

    monkeypatch.setattr(actions.prompt_utils, "prompt_text", _prompt)
    monkeypatch.setattr(actions.prompt_utils, "get_choice", _get_choice)
    monkeypatch.setattr(actions, "core_q", type("_DB", (), {"run_sql": staticmethod(_run_sql)})())

    updated = actions.prompt_session_label(params)

    assert seen["default"] == "20260428-all-smoke10-full"
    assert seen["strategy_default"] == "2"
    assert updated.canonical_action == "append"
    assert updated.session_stamp == "20260428-all-smoke10-full-11"
