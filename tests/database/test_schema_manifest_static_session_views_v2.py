from __future__ import annotations

from scripts.db.view_repair_support import views_from_ordered_schema_manifest
from scytaledroid.Database.db_queries import schema_manifest


def test_schema_manifest_orders_session_v2_views_after_sessions_table():
    statements = schema_manifest.ordered_schema_statements()
    idx_tbl = next(
        i for i, stmt in enumerate(statements) if "CREATE TABLE IF NOT EXISTS static_analysis_sessions" in stmt
    )
    markers = [
        "CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_health_v2",
        "CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_web_static_session_index_v2",
        "CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_web_static_latest_session_by_scope_v2",
        "CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_cleanup_candidates_v2",
        "CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_supersession_candidates_v1",
    ]
    idxs = [
        next(i for i, stmt in enumerate(statements) if m in stmt) for m in markers
    ]
    assert idx_tbl < idxs[0]
    assert idxs == sorted(idxs)


def test_schema_manifest_includes_static_session_v2_view_ddls():
    statements = schema_manifest.ordered_schema_statements()
    required = [
        "v_static_session_health_v2",
        "v_web_static_session_index_v2",
        "v_web_static_latest_session_by_scope_v2",
        "v_static_session_cleanup_candidates_v2",
        "v_static_session_supersession_candidates_v1",
    ]
    blob = "\n".join(statements)
    for name in required:
        assert f"VIEW {name}" in blob or f"VIEW `{name}`" in blob, name


def test_manifest_extractor_includes_ordered_session_v2_views():
    ordered, by_name = views_from_ordered_schema_manifest()
    manifest_names = [n.lower() for n, _ in ordered]
    for name in (
        "v_static_session_health_v2",
        "v_web_static_session_index_v2",
        "v_web_static_latest_session_by_scope_v2",
        "v_static_session_cleanup_candidates_v2",
        "v_static_session_supersession_candidates_v1",
    ):
        assert name in manifest_names, name
        assert name in by_name


def test_manifest_extractor_orders_session_health_before_dependents():
    ordered, _ = views_from_ordered_schema_manifest()
    names = [n.lower() for n, _ in ordered]
    h = names.index("v_static_session_health_v2")
    assert names.index("v_web_static_session_index_v2") > h
    assert names.index("v_static_session_cleanup_candidates_v2") > h
    assert names.index("v_static_session_supersession_candidates_v1") > names.index(
        "v_static_session_cleanup_candidates_v2"
    )
