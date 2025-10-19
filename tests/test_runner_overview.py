import re
from pathlib import Path

from scytaledroid.StaticAnalysis.cli import runner
from scytaledroid.StaticAnalysis.cli.models import RunParameters, ScopeSelection

SESSION_LINE_PATTERN = re.compile(r"Session\s+:\s+(\d{8}-\d{6})")


def test_run_overview_outputs_expected_lines(monkeypatch, capsys):
    selection = ScopeSelection("app", "pkg", tuple())
    params = RunParameters(
        profile="full",
        scope=selection.scope,
        scope_label=selection.label,
        reuse_cache=True,
    )

    monkeypatch.setattr(runner, "configure_logging_for_cli", lambda *_: None)
    monkeypatch.setattr(runner, "execute_scan", lambda sel, prm, base: object())
    monkeypatch.setattr(runner, "render_run_results", lambda outcome, prm: None)
    monkeypatch.setattr(runner, "run_modules_for_profile", lambda profile: ("alpha", "beta"))
    monkeypatch.setattr(runner, "execute_permission_scan", lambda *args, **kwargs: None)

    runner.launch_scan_flow(selection, params, Path("/tmp"))
    output = capsys.readouterr().out

    assert f"Scope    : App={selection.label}" in output
    match = SESSION_LINE_PATTERN.search(output)
    assert match, "Session line missing timestamp"
    assert re.fullmatch(r"\d{8}-\d{6}", match.group(1))
    assert "Workers  : auto (" in output
    assert "Cache    : reuse" in output
    assert "Detectors: alpha, beta" in output
