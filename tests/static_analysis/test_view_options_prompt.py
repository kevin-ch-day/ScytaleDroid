from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.core.run_specs import StaticRunSpec
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch
from scytaledroid.StaticAnalysis.cli.commands.models import Command
from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
from scytaledroid.StaticAnalysis.cli.menus import static_analysis_menu as menu
from scytaledroid.StaticAnalysis.cli.menus import static_analysis_menu_helpers as helpers
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


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


def test_render_reset_outcome_forwards_session_label(monkeypatch):
    captured: dict[str, object] = {}

    class _Actions:
        @staticmethod
        def render_reset_outcome(outcome, *, session_label=None):
            captured["outcome"] = outcome
            captured["session_label"] = session_label

    monkeypatch.setattr(helpers, "_load_menu_actions", lambda: _Actions())

    marker = object()
    helpers.render_reset_outcome(marker, session_label="20260328-all-full")

    assert captured == {
        "outcome": marker,
        "session_label": "20260328-all-full",
    }


def _dummy_group() -> ArtifactGroup:
    artifact = RepositoryArtifact(
        path=Path("/tmp/example.apk"),
        display_path="example.apk",
        metadata={"package_name": "org.thoughtcrime.securesms", "version_code": "167501"},
    )
    return ArtifactGroup(
        group_key="signal",
        package_name="org.thoughtcrime.securesms",
        version_display="8.6.2",
        session_stamp="20260427",
        capture_id="20260427",
        artifacts=(artifact,),
    )


def test_run_command_for_selection_scan_bypasses_view_options(monkeypatch):
    command = Command(
        id="1",
        title="Run Static Pipeline (Full)",
        description="Run full static profile.",
        kind="scan",
        profile="full",
        auto_verify=False,
    )
    selection = ScopeSelection("app", "Signal", (_dummy_group(),))
    called: dict[str, object] = {}

    monkeypatch.setattr(menu, "collect_view_options", lambda _command: (_ for _ in ()).throw(AssertionError("unexpected view prompt")))
    monkeypatch.setattr(menu, "ask_run_controls", lambda: (_ for _ in ()).throw(AssertionError("unexpected run-options prompt")))
    monkeypatch.setattr(menu, "apply_command_overrides", lambda params, _command: params)
    monkeypatch.setattr(menu, "prompt_run_setup", lambda params, _selection, _command: ("run", params, None))
    monkeypatch.setattr(
        menu,
        "build_static_run_spec",
        lambda **kwargs: called.setdefault("spec", kwargs) or kwargs,
        raising=False,
    )
    monkeypatch.setattr(menu.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    def _execute(spec):
        called["executed"] = spec
        return SimpleNamespace(session_stamp="20260427-test")

    menu._run_command_for_selection(
        command,
        selection,
        analysis_root=Path("/tmp"),
        persistence_gate_status=lambda: (True, None),
        query_runner=SimpleNamespace(render_session_digest=lambda *_a, **_k: None),
        prompt_advanced_options=lambda params: params,
        reset_static_analysis_data=lambda **_kwargs: None,
        build_static_run_spec=lambda **kwargs: kwargs,
        execute_run_spec=_execute,
        static_service=SimpleNamespace(StaticServiceError=RuntimeError),
    )

    assert "executed" in called


def test_run_command_for_selection_cancelled_setup_aborts_run(monkeypatch, capsys):
    command = Command(
        id="1",
        title="Run Static Pipeline (Full)",
        description="Run full static profile.",
        kind="scan",
        profile="full",
        auto_verify=False,
        prompt_reset=True,
    )
    selection = ScopeSelection("app", "Signal", (_dummy_group(),))
    called: dict[str, object] = {}

    monkeypatch.setattr(menu, "ask_run_controls", lambda: (_ for _ in ()).throw(AssertionError("unexpected run-options prompt")))
    monkeypatch.setattr(menu, "apply_command_overrides", lambda params, _command: params)
    monkeypatch.setattr(menu, "prompt_run_setup", lambda params, _selection, _command: ("cancel", params, None))
    monkeypatch.setattr(menu.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    menu._run_command_for_selection(
        command,
        selection,
        analysis_root=Path("/tmp"),
        persistence_gate_status=lambda: (True, None),
        query_runner=SimpleNamespace(render_session_digest=lambda *_a, **_k: None),
        prompt_advanced_options=lambda params: params,
        reset_static_analysis_data=lambda **_kwargs: called.setdefault("reset", True),
        build_static_run_spec=lambda **kwargs: called.setdefault("spec", kwargs),
        execute_run_spec=lambda _spec: called.setdefault("executed", True),
        static_service=SimpleNamespace(StaticServiceError=RuntimeError),
    )

    capsys.readouterr()
    assert "spec" not in called
    assert "executed" not in called


def test_run_command_for_selection_aborted_run_skips_auto_verify(monkeypatch):
    command = Command(
        id="1",
        title="Run Static Pipeline (Full)",
        description="Run full static profile.",
        kind="scan",
        profile="full",
        auto_verify=True,
    )
    selection = ScopeSelection("app", "Signal", (_dummy_group(),))
    calls = {"verify": 0}

    monkeypatch.setattr(menu, "ask_run_controls", lambda: (_ for _ in ()).throw(AssertionError("unexpected run-options prompt")))
    monkeypatch.setattr(menu, "apply_command_overrides", lambda params, _command: params)
    monkeypatch.setattr(menu, "prompt_run_setup", lambda params, _selection, _command: ("run", params, None))
    monkeypatch.setattr(menu.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    menu._run_command_for_selection(
        command,
        selection,
        analysis_root=Path("/tmp"),
        persistence_gate_status=lambda: (True, None),
        query_runner=SimpleNamespace(render_session_digest=lambda *_a, **_k: calls.__setitem__("verify", calls["verify"] + 1)),
        prompt_advanced_options=lambda params: params,
        reset_static_analysis_data=lambda **_kwargs: None,
        build_static_run_spec=lambda **kwargs: kwargs,
        execute_run_spec=lambda _spec: SimpleNamespace(session_stamp="20260427-test", aborted=True),
        static_service=SimpleNamespace(StaticServiceError=RuntimeError),
    )

    assert calls["verify"] == 0


def test_execute_run_spec_detailed_refreshes_run_context_after_session_resolution(monkeypatch):
    selection = ScopeSelection("app", "Signal", (_dummy_group(),))
    params = RunParameters(profile="full", scope="app", scope_label="Signal", session_stamp="base-session")
    spec = StaticRunSpec(selection=selection, params=params, base_dir=Path("/tmp"))
    captured: dict[str, object] = {}

    def _resolved(*_a, **_k):
        return SimpleNamespace(**{**params.__dict__, "session_stamp": "base-session-2"}), None

    monkeypatch.setattr(run_dispatch, "_resolve_effective_run_params", _resolved)
    monkeypatch.setattr(run_dispatch, "_acquire_static_run_lock", lambda _params: None)
    monkeypatch.setattr(run_dispatch, "_release_static_run_lock", lambda _lock_path: None)

    def _launch(_selection, effective_params, _base_dir):
        ctx = run_dispatch.output_prefs.get_run_context()
        captured["ctx_session"] = getattr(ctx, "session_stamp", None)
        captured["param_session"] = effective_params.session_stamp
        return None

    monkeypatch.setattr(run_dispatch, "_launch_scan_flow_resolved", _launch)

    result = run_dispatch.execute_run_spec_detailed(spec)

    assert result.completed is True
    assert captured == {
        "ctx_session": "base-session-2",
        "param_session": "base-session-2",
    }


def test_select_distinct_report_pair_skips_latest_duplicate_version():
    def _stored(name: str, version_code: int, version_name: str, generated_at: str, sha256: str):
        report = SimpleNamespace(
            manifest=SimpleNamespace(version_code=version_code, version_name=version_name),
            hashes={"sha256": sha256},
            generated_at=generated_at,
        )
        return SimpleNamespace(path=Path(name), report=report)

    reports = [
        _stored("older.json", 167001, "8.4.1", "2026-03-28T01:00:00Z", "sha-old"),
        _stored("current-canonical.json", 167501, "8.6.2", "2026-04-15T01:00:00Z", "sha-new-a"),
        _stored("current-light.json", 167501, "8.6.2", "2026-04-26T01:00:00Z", "sha-new-b"),
    ]

    previous, current = helpers._select_distinct_report_pair(reports)
    assert previous.manifest.version_code == 167001
    assert current.manifest.version_code == 167501
