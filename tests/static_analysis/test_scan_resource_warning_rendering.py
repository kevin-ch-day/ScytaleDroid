from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.run_context import StaticRunContext
from scytaledroid.StaticAnalysis.cli.execution.scan_report import _append_resource_warning
from scytaledroid.StaticAnalysis.cli.execution.scan_view import render_resource_warnings


def _run_ctx() -> StaticRunContext:
    return StaticRunContext(
        run_mode="interactive",
        quiet=False,
        batch=False,
        noninteractive=False,
        show_splits=False,
        scan_splits_enabled=True,
        session_stamp="session-1",
        persistence_ready=True,
        paper_grade_requested=True,
        resolved_worker_count=1,
    )


def _report_with_bounds_warning(line: str):
    return SimpleNamespace(
        metadata={
            "app_label": "Tinder",
            "resource_bounds_warnings": [line],
        }
    )


def test_minor_complex_entry_warning_renders_as_info_note(capsys) -> None:
    lines = _append_resource_warning(
        [],
        _report_with_bounds_warning("We are out of bound with this complex entry. Count: 262"),
        "com.tinder",
        "artifact.apk",
    )

    assert lines[0] == ("info", "Resource table parser note (minor complex-entry warning).")

    render_resource_warnings(lines, run_ctx=_run_ctx())
    output = capsys.readouterr().out

    assert "[INFO]" in output
    assert "minor complex-entry warning" in output
    assert "re-run only if this APK needs deep string/resource review" in output


def test_large_bounds_warning_stays_warn(capsys) -> None:
    report = _report_with_bounds_warning("We are out of bound with this complex entry. Count: 65536")
    report.metadata["parse_error_resources"] = True
    report.metadata["string_index_resource_strings"] = 0

    lines = _append_resource_warning([], report, "com.example.app", "artifact.apk")

    assert lines[0] == ("warn", "Resource table parse appears partial (string/resource parsing).")

    render_resource_warnings(lines, run_ctx=_run_ctx())
    output = capsys.readouterr().out

    assert "[WARN]" in output
    assert "String/resource results may be materially incomplete" in output
