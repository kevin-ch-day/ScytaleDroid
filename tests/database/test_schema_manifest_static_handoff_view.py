from __future__ import annotations

from scytaledroid.Database.db_queries import schema_manifest


def test_schema_manifest_includes_static_handoff_view():
    statements = schema_manifest.ordered_schema_statements()
    found = any(
        "CREATE OR REPLACE VIEW v_static_handoff_v1" in stmt
        for stmt in statements
    )
    assert found

