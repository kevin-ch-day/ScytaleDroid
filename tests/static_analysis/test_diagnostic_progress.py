from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution import scan_flow


def test_diagnostic_verbose_suppresses_checkpoint_lines(capsys):
    progress = scan_flow._PipelineProgress(
        total=10,
        show_splits=False,
        show_artifacts=True,
        show_checkpoints=False,
    )

    progress.finish(5, "Example • base")
    captured = capsys.readouterr()
    assert captured.out == ""
