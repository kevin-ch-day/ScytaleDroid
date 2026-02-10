from __future__ import annotations


def test_persist_static_sections_no_samples_does_not_crash(monkeypatch):
    # Regression test for a bug where persist_string_summary() was called inside the
    # samples loop, leaving string_errors unbound when there were 0 samples.
    from scytaledroid.StaticAnalysis.cli.persistence import static_sections

    calls = {"count": 0}

    def _fake_require_schema():
        return None

    def _fake_persist_findings(**kwargs):
        return []

    def _fake_persist_string_summary(**kwargs):
        calls["count"] += 1
        return []

    monkeypatch.setattr(static_sections, "require_canonical_schema", _fake_require_schema)
    monkeypatch.setattr(static_sections, "persist_static_findings", _fake_persist_findings)
    monkeypatch.setattr(static_sections, "persist_string_summary", _fake_persist_string_summary)

    errors, baseline_written, sample_total = static_sections.persist_static_sections(
        package_name="com.example.app",
        session_stamp="20260210",
        scope_label="All apps",
        finding_totals={"total": 0},
        baseline_section={"findings": []},
        string_payload={"counts": {}, "samples": {}, "selected_samples": {}},
        manifest=None,
        app_metadata={},
        static_run_id=123,
    )

    assert errors == []
    assert baseline_written is True
    assert sample_total == 0
    assert calls["count"] == 1

