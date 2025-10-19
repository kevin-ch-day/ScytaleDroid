from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.detail import app_detail_loop
from scytaledroid.StaticAnalysis.cli.models import AppRunResult


def test_detail_viewer_handles_blank_and_help(monkeypatch, capsys):
    app_result = AppRunResult("com.example", "Category", artifacts=[])

    inputs = iter(["?", "f", "e", ""])

    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.detail.prompt_severity_filter",
        lambda levels: levels,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.detail.cycle_evidence_lines",
        lambda current: current,
    )

    render_calls: list[tuple] = []

    def fake_renderer(*args, **kwargs):
        render_calls.append(args)

    app_detail_loop(
        app_result,
        evidence_lines=1,
        active_levels=set("HMLI"),
        finding_limit=5,
        detail_renderer=fake_renderer,
    )

    output = capsys.readouterr().out
    assert "Unknown command" not in output
    assert "Commands:" in output
    assert render_calls
