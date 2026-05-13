"""Contract tests for scripts/db DDL parsing helpers (manifest view extraction)."""

from __future__ import annotations

from scripts.db.view_repair_support import ddl_view_name


def test_ddl_view_name_plain_create_or_replace() -> None:
    assert ddl_view_name("CREATE OR REPLACE VIEW v_run_overview AS SELECT 1") == "v_run_overview"


def test_ddl_view_name_sql_security_invoker_before_view_kw() -> None:
    ddl = """
    CREATE OR REPLACE SQL SECURITY INVOKER VIEW v_static_session_health_v2 AS
    SELECT 1;
    """.strip()
    assert ddl_view_name(ddl) == "v_static_session_health_v2"
