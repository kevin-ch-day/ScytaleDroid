from __future__ import annotations

import pytest
from scytaledroid.StaticAnalysis.cli.persistence.static_sections import persist_static_sections


class DummyManifest:
    def __init__(self, app_label: str) -> None:
        self.app_label = app_label
        self.version_name = "1.0"
        self.version_code = 100
        self.target_sdk = 33
        self.min_sdk = 24
        self.flags = type("F", (), {"allow_backup": False})()


@pytest.fixture(autouse=True)
def clear_tables():
    from scytaledroid.Database.db_core import db_queries as core_q

    core_q.run_sql("DELETE FROM static_findings")
    core_q.run_sql("DELETE FROM static_findings_summary")
    core_q.run_sql("DELETE FROM static_string_samples")
    core_q.run_sql("DELETE FROM static_string_summary")
    yield
    core_q.run_sql("DELETE FROM static_findings")
    core_q.run_sql("DELETE FROM static_findings_summary")
    core_q.run_sql("DELETE FROM static_string_samples")
    core_q.run_sql("DELETE FROM static_string_summary")


def _summary_counts(session_stamp: str):
    from scytaledroid.Database.db_core import db_queries as core_q

    return core_q.run_sql(
        "SELECT high, med, low, info FROM static_findings_summary WHERE session_stamp=%s",
        (session_stamp,),
        fetch="one",
    )


def test_persist_static_sections_persists_baseline_and_strings():
    session = "20250101-010101"
    errors, baseline_written, sample_total = persist_static_sections(
        package_name="com.example.section",
        session_stamp=session,
        scope_label="Test",
        finding_totals={"High": 1, "Medium": 0, "Low": 0, "Info": 0},
        baseline_section={
            "findings": [
                {
                    "finding_id": "BASE-TEST",
                    "severity": "High",
                    "title": "Test finding",
                    "evidence": {"path": "AndroidManifest.xml"},
                }
            ]
        },
        string_payload={
            "counts": {"endpoints": 1},
            "samples": {"endpoints": [{"value_masked": "http://example.com", "src": "AndroidManifest.xml"}]},
        },
        manifest=DummyManifest("Example App"),
        app_metadata={},
        run_id=1,
        static_run_id=1,
    )

    assert errors == []
    assert baseline_written is True
    assert sample_total == 1
    row = _summary_counts(session)
    assert row is not None
    assert tuple(row) == (1, 0, 0, 0)
