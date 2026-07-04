from __future__ import annotations

import pathlib


def _summary_source() -> str:
    repo = pathlib.Path(__file__).resolve().parents[2]
    return (
        repo / "scytaledroid/StaticAnalysis/cli/persistence/static_session_summary.py"
    ).read_text(encoding="utf-8")


def test_refresh_summary_update_omits_operator_owned_columns():
    text = _summary_source()
    u = text.find("UPDATE static_analysis_sessions")
    w = text.find("WHERE static_session_id", u)
    assert u != -1 and w != -1
    stmt = text[u:w]
    for col in ("web_visibility_default", "cleanup_status", "superseded_by_session_id"):
        assert col not in stmt


def test_refresh_summary_update_propagates_runtime_provenance():
    text = _summary_source()
    u = text.find("UPDATE static_analysis_sessions")
    w = text.find("WHERE static_session_id", u)
    assert u != -1 and w != -1
    stmt = text[u:w]
    assert "tool_semver = COALESCE(%s, tool_semver)" in stmt
    assert "tool_git_commit = COALESCE(%s, tool_git_commit)" in stmt
    assert "schema_version = COALESCE(%s, schema_version)" in stmt


def test_refresh_queries_normalize_scope_with_trim_and_alias_child_counts():
    text = _summary_source()
    assert "COALESCE(TRIM(BOTH FROM sar.scope_label), '')" in text
    assert "COALESCE(TRIM(BOTH FROM r.scope_label), '')" in text
    assert "COALESCE(TRIM(BOTH FROM ss.scope_label), '')" in text
    assert "COALESCE(TRIM(BOTH FROM u.scope_label), '')" in text
    assert "AS child_cnt" in text


def test_ensure_shell_duplicate_clause_avoids_aggregate_resets():
    text = _summary_source()
    ix = text.find("ON DUPLICATE KEY UPDATE")
    assert ix != -1
    dup = text[ix : ix + 450]
    assert "web_visibility_default" not in dup
    assert "cleanup_status" not in dup
    assert "superseded_by_session_id" not in dup
    assert "total_run_count" not in dup
    assert "session_disposition = VALUES(session_disposition)" not in dup
