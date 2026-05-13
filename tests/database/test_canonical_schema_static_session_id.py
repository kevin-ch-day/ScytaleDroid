from __future__ import annotations

from scytaledroid.Database.db_queries.canonical import schema as canonical_schema


def test_canonical_schema_includes_static_session_id_on_runs():
    blob = "\n".join(getattr(canonical_schema, "_DDL_STATEMENTS", []))
    assert "static_session_id" in blob
    assert "ix_static_analysis_runs_static_session_id" in blob
