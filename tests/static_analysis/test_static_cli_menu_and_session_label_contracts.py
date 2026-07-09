from __future__ import annotations

import importlib
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.commands import COMMANDS, get_command, iter_commands
from scytaledroid.StaticAnalysis.cli.commands.models import SelectionMode
from scytaledroid.StaticAnalysis.cli.core import run_prompts
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.menus import actions
from scytaledroid.StaticAnalysis.core import repository
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def _group(package_name: str) -> ArtifactGroup:
    artifact = RepositoryArtifact(
        path=Path(f"/tmp/{package_name}.apk"),
        display_path=f"{package_name}.apk",
        metadata={"package_name": package_name},
    )
    return ArtifactGroup(
        group_key=package_name,
        package_name=package_name,
        version_display="1.0.0",
        session_stamp="20260427",
        capture_id="20260427",
        artifacts=(artifact,),
    )


# =============================================================================
# Former tests/static_analysis/test_command_registry.py
# =============================================================================


def test_command_registry_contains_only_scan_commands_with_unique_ids():
    ids = [cmd.id for cmd in COMMANDS]

    assert len(ids) == len(set(ids))
    assert {cmd.kind for cmd in COMMANDS} == {"scan", "readonly"}


def test_static_menu_command_layout_reflects_pruned_contract():
    commands = tuple(iter_commands("scan"))
    by_id = {cmd.id: cmd for cmd in commands}

    assert set(by_id) == {"1", "2", "3", "4"}
    assert by_id["4"].section == "history"
    assert by_id["4"].selection_mode is SelectionMode.DIFF_LAST
    drilldown = get_command("D")
    assert drilldown is not None
    assert drilldown.kind == "readonly"
    assert drilldown.section == "tools"
    assert get_command("5") is None
    assert get_command("6") is None


def test_search_app_scope_prioritizes_exact_package_match(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")

    kindle = _group("com.amazon.kindle")
    shopping = _group("com.amazon.mshop.android.shopping")
    groups = (kindle, shopping)

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.list_packages",
        lambda _groups: [
            ("com.amazon.kindle", "1", 1, "Amazon Kindle"),
            ("com.amazon.mshop.android.shopping", "1", 1, "Amazon Shopping"),
        ],
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.selection.select_latest_groups",
        lambda selected: tuple(selected),
    )
    monkeypatch.setattr(
        menu_module.prompt_utils,
        "prompt_text",
        lambda *_a, **_k: "com.amazon.mshop.android.shopping",
    )
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    selection = menu_module._search_app_scope(groups)

    assert isinstance(selection, ScopeSelection)
    assert selection.scope == "app"
    assert selection.label == "Amazon Shopping | com.amazon.mshop.android.shopping"
    assert selection.groups == (shopping,)


# =============================================================================
# Former tests/static_analysis/test_run_controls_prompt.py
# =============================================================================


def test_ask_run_controls_supports_advanced_options(monkeypatch) -> None:
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "2")

    assert actions.ask_run_controls() == "advanced"


def test_ask_run_controls_defaults_to_run(monkeypatch) -> None:
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    assert actions.ask_run_controls() == "run"


def test_prompt_advanced_options_can_disable_split_scan(monkeypatch) -> None:
    params = RunParameters(
        profile="full",
        scope="profile",
        scope_label="Research Dataset Alpha",
        scan_splits=True,
    )

    monkeypatch.setattr(run_prompts, "prompt_int", lambda _label, default, **_kwargs: default)
    monkeypatch.setattr(run_prompts, "prompt_float", lambda _label, default, **_kwargs: default)
    monkeypatch.setattr(run_prompts, "prompt_choice", lambda _label, _options, *, default: default)
    monkeypatch.setattr(
        run_prompts.prompt_utils,
        "prompt_text",
        lambda _label, default="", **_kwargs: default,
    )

    yes_no_answers = {
        "Modify advanced options?": True,
        "Reuse disk cache": params.reuse_cache,
        "Verbose output": params.verbose_output,
        "Artifact detail output": params.artifact_detail,
        "Split APK scan (scan base + split APKs)": False,
        "Dry-run (no persistence)": params.dry_run,
        "Refresh permission snapshot after detector run": params.permission_snapshot_refresh,
    }
    monkeypatch.setattr(
        run_prompts.prompt_utils,
        "prompt_yes_no",
        lambda label, default=False: yes_no_answers.get(label, default),
    )

    updated = run_prompts.prompt_advanced_options(params)

    assert updated.scan_splits is False
    summary = dict(run_prompts._summarise_params(updated))
    assert summary["Split APK scan"] == "No"


# =============================================================================
# Former tests/static_analysis/test_profile_label_normalization.py
# =============================================================================


def test_normalise_profile_label_strips_legacy_paper_suffix() -> None:
    assert (
        repository._normalise_profile_label("Research Dataset Alpha (Paper #12)")
        == "Research Dataset Alpha"
    )


def test_normalise_profile_label_keeps_non_legacy_label() -> None:
    assert repository._normalise_profile_label("Messaging") == "Messaging"


# =============================================================================
# Former tests/static_analysis/test_session_label_suggestions.py
# =============================================================================


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
        if "select distinct coalesce" in sql:
            return [("20260428-all-full",)]
        if "count(*) from static_analysis_runs where session_label=%s or session_stamp=%s" in sql:
            return (120,)
        if "where (session_label=%s or session_stamp=%s) and is_canonical=1" in sql:
            return (582,)
        raise AssertionError(f"unexpected sql: {sql}")

    monkeypatch.setattr(actions.prompt_utils, "prompt_text", _prompt)
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "2")
    monkeypatch.setattr(actions, "core_q", type("_DB", (), {"run_sql": staticmethod(_run_sql)})())

    updated = actions.prompt_session_label(params)

    assert updated.canonical_action == "append"
    assert updated.session_stamp == "20260428-all-full-2"


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
        if "select distinct coalesce" in sql:
            return [("20260428-all-smoke10-full",), ("20260428-all-smoke10-full-2",)]
        if "count(*) from static_analysis_runs where session_label=%s or session_stamp=%s" in sql:
            return (10,)
        if "where (session_label=%s or session_stamp=%s) and is_canonical=1" in sql:
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
    assert updated.session_stamp == "20260428-all-smoke10-full-3"


# =============================================================================
# Former tests/static_analysis/test_strict_selection_determinism.py
# =============================================================================


def test_strict_disables_multi_group_latest_selection(monkeypatch):
    # Even if an operator sets the env var, strict/paper mode must force deterministic selection.
    monkeypatch.setenv("SCYTALEDROID_STATIC_ALLOW_MULTI_GROUPS", "1")
    monkeypatch.setenv("SCYTALEDROID_PAPER_STRICT", "1")

    from scytaledroid.StaticAnalysis.cli.flows import selection as sel

    assert sel._allow_multiple_latest() is False
