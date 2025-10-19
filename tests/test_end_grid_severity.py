from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution.results import _render_db_severity_table
from scytaledroid.Database.db_core import db_queries as core_q


def test_render_db_severity_table_uses_session_counts(monkeypatch, capsys):
    def fake_run_sql(sql, params=(), fetch="one", dictionary=False):
        if "FROM static_findings_summary" in sql and "LEFT JOIN runs" in sql:
            return [
                {
                    "package_name": "com.example",
                    "target_sdk": 33,
                    "high": 1,
                    "med": 2,
                    "low": 3,
                    "info": 4,
                }
            ]
        return []

    monkeypatch.setattr(core_q, "run_sql", fake_run_sql)

    rendered = _render_db_severity_table("session")
    assert rendered is True
    output = capsys.readouterr().out
    assert "com.example" in output
    assert "1" in output
    assert "2" in output
