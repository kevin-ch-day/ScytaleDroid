from __future__ import annotations

import pytest

from scytaledroid.StaticAnalysis.cli.persistence import (
    findings_writer,
    static_findings_writer,
    strings_writer,
)


# Retire with the remaining legacy findings/string writer compatibility seams
# once the old write paths are fully removed.
pytestmark = [pytest.mark.legacy_contract, pytest.mark.retire_with_code, pytest.mark.tier3]


def test_static_findings_requires_static_run_id(monkeypatch):
    monkeypatch.setattr(static_findings_writer._sf, "ensure_tables", lambda: True)
    errors = static_findings_writer.persist_static_findings(
        package_name="com.example.app",
        session_stamp="20260130-000000",
        scope_label="test",
        severity_counts={"High": 1},
        details={},
        findings=None,
        static_run_id=None,
    )
    assert errors
    assert "static_run_id missing" in errors[0]


def test_findings_writer_blocks_legacy_schema(monkeypatch):
    monkeypatch.setattr(findings_writer, "_has_column", lambda *_args, **_kwargs: False)
    result = findings_writer.persist_findings(1, (), static_run_id=1)
    assert result is False


def test_string_writer_requires_static_run_id(monkeypatch):
    monkeypatch.setattr(strings_writer._sa, "ensure_tables", lambda: True)
    errors = strings_writer.persist_string_summary(
        package_name="com.example.app",
        session_stamp="20260130-000000",
        scope_label="test",
        counts={"endpoints": 1},
        samples={},
        static_run_id=None,
    )
    assert errors
    assert "static_run_id missing" in errors[0]
