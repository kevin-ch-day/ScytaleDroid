import re
from pathlib import Path

from scytaledroid.StaticAnalysis.cli import runner
from scytaledroid.StaticAnalysis.cli.models import RunParameters, ScopeSelection

STAMP_PATTERN = re.compile(r"^\d{8}-\d{6}$")


def test_run_parameters_session_stamp_format():
    params = RunParameters(profile="full", scope="app", scope_label="pkg")
    assert STAMP_PATTERN.match(params.session_stamp)


def test_launch_scan_flow_preserves_original_params(monkeypatch):
    selection = ScopeSelection("app", "pkg", tuple())
    params = RunParameters(
        profile="permissions",
        scope=selection.scope,
        scope_label=selection.label,
        reuse_cache=True,
    )
    original_stamp = params.session_stamp
    captured = {}

    def fake_execute_permission_scan(sel, new_params, persist_detections=True):
        captured["params"] = new_params

    monkeypatch.setattr(runner, "configure_logging_for_cli", lambda *_: None)
    monkeypatch.setattr(runner, "execute_permission_scan", fake_execute_permission_scan)
    monkeypatch.setattr(runner, "run_modules_for_profile", lambda profile: ("perm",))

    runner.launch_scan_flow(selection, params, Path("/tmp"))

    assert params.session_stamp == original_stamp
    run_params = captured["params"]
    assert run_params is not params
    assert STAMP_PATTERN.match(run_params.session_stamp)
    assert run_params.session_stamp != original_stamp
