from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution.scan_flow import _print_artifact_progress
from scytaledroid.Utils.System import output_prefs


def test_print_artifact_progress_sums_timings(capsys):
    prefs = output_prefs.get()
    prefs.verbose = False

    summary = SimpleNamespace(duration_seconds=0.0)
    timings = [
        ("det1", 0.005),
        ("det2", 0.01),
        ("det3", 0.02),
    ]

    _print_artifact_progress("label", summary, timings)
    captured = capsys.readouterr().out
    assert "detectors=3 total=35 ms" in captured
