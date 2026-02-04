from __future__ import annotations

from datetime import UTC

from scytaledroid.StaticAnalysis.cli.execution import diagnostics, results_formatters


def test_hash_prefix_short_value():
    assert results_formatters._hash_prefix("abcd") == "abcd"


def test_hash_prefix_long_value():
    assert results_formatters._hash_prefix("0123456789abcdef") == "0123…cdef"


def test_group_diagnostic_warnings_dedupes():
    warnings = [
        ("Linkage", "pkg.alpha", "UNAVAILABLE: no run_map; no db link"),
        ("Linkage", "pkg.beta", "UNAVAILABLE: no run_map; no db link"),
        ("Identity", "pkg.alpha", "missing split"),
        ("Identity", "pkg.alpha", "missing split"),
    ]
    lines = diagnostics._group_diagnostic_warnings(warnings, max_packages=3)
    assert any("Linkage UNAVAILABLE: no run_map; no db link" in line for line in lines)
    assert any("Identity missing split" in line for line in lines)


def test_plan_provenance_requires_runids():
    lines = diagnostics._plan_provenance_lines(
        run_id_states=[True, False, True],
        run_signature_ok=True,
        artifact_set_ok=True,
    )
    assert lines[0].startswith("FAIL static_run_id present")
    assert any("resolve linkage" in line for line in lines)


def test_diagnostic_summary_populates_runid_for_db_lookup(monkeypatch):
    from datetime import datetime
    from pathlib import Path

    from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection

    app = AppRunResult(package_name="com.example.app", category="test")
    app.app_label = "Example"
    app.run_signature = "sig"
    app.run_signature_version = "v1"
    app.identity_valid = True
    app.base_apk_sha256 = "a" * 64
    app.artifact_set_hash = "b" * 64
    app.discovered_artifacts = 1
    app.executed_artifacts = 1
    app.persisted_artifacts = 0

    outcome = RunOutcome(
        results=[app],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        scope=ScopeSelection("profile", "Test", tuple()),
        base_dir=Path("."),
    )

    monkeypatch.setattr(diagnostics, "load_run_map", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(diagnostics, "_fetch_db_linkage", lambda *_args, **_kwargs: (None, None))
    monkeypatch.setattr(
        diagnostics,
        "_fetch_db_linkage_by_signature",
        lambda *_args, **_kwargs: (
            {
                "static_run_id": 42,
                "pipeline_version": "2.0.0-alpha",
                "run_signature": "sig",
                "run_signature_version": "v1",
            },
            None,
        ),
    )

    captured: list[tuple[list[str], list[list[str]]]] = []

    def fake_render_table(headers, rows, *args, **kwargs):
        captured.append((headers, rows))

    monkeypatch.setattr(diagnostics.table_utils, "render_table", fake_render_table)

    diagnostics._render_diagnostic_app_summary(
        outcome,
        session_stamp="20260130-000000",
        compact_mode=True,
    )

    assert captured
    headers, rows = captured[0]
    assert headers[-2:] == ["RunID", "Sig"]
    assert rows[0][-2] == "42"
    assert rows[0][-1] == "sig"
