"""Tests for DEP static profile view SQL builder."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import dep_view


def test_build_dep_view_sql_uses_table_presence(monkeypatch) -> None:
    """Regression: ``presence`` must be defined (optional joins use diagnostics)."""

    calls: list[list[str]] = []

    def fake_check(tables: list[str]) -> dict[str, bool]:
        calls.append(list(tables))
        return {name: name == "static_permission_matrix" for name in tables}

    monkeypatch.setattr(dep_view.diagnostics, "check_required_tables", fake_check)

    sql = dep_view._build_dep_view_sql()
    assert "CREATE OR REPLACE VIEW v_dep_static_profile" in sql
    assert "FROM static_analysis_runs sar" in sql
    assert calls and calls[0] == list(dep_view._DEP_OPTIONAL_SOURCES)
    assert "FROM static_permission_matrix" in sql
