"""Tests for read-only artifact registry integrity report."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from scripts.db.report_artifact_registry_integrity import collect_report, format_text_report


def test_format_text_report_includes_sections() -> None:
    data = {
        "summary_counts": {
            "total_rows": 13,
            "linked_rows": 10,
            "dangling_static_run_rows": 3,
            "dangling_dynamic_run_rows": 0,
            "unknown_run_type_rows": 0,
        },
        "totals_by_run_type_link_state": [
            {"run_type": "static", "link_state": "linked", "count": 10},
            {"run_type": "static", "link_state": "dangling_static_run", "count": 3},
        ],
        "dangling_by_artifact_type": [
            {
                "run_type": "static",
                "artifact_type": "dep_snapshot",
                "link_state": "dangling_static_run",
                "count": 3,
            }
        ],
        "dangling_by_age_bucket": [
            {
                "run_type": "static",
                "link_state": "dangling_static_run",
                "age_bucket": "90d+",
                "count": 3,
            }
        ],
        "top_dangling_static_run_ids": [{"run_id": "999001", "count": 3}],
        "top_dangling_dynamic_run_ids": [{"run_id": "dyn-old", "count": 2}],
        "static_rows_nonnumeric_run_id": 1,
        "static_numeric_run_id_rows_missing_sar": 2,
        "host_path_probe": None,
    }
    text = format_text_report(data)
    assert "## summary" in text
    assert "dangling_static_run_rows=3" in text
    assert "totals by run_type" in text
    assert "static\tdangling_static_run\tdep_snapshot\t3" in text
    assert "999001\t3" in text
    assert "dyn-old\t2" in text
    assert "Interpretation:" in text
    assert "prune_artifact_registry_dangling.py" in text


def test_collect_report_queries_core_q(monkeypatch: pytest.MonkeyPatch) -> None:
    returns: list[list[tuple]] = [
        [("static", "linked", 5)],
        [],
        [],
        [],
        [],
        [(0,)],
        [(0,)],
    ]

    seen_sql: list[str] = []

    def fake_run_sql(sql: str, params=None, **_kw):
        seen_sql.append(sql)
        if not returns:
            return []
        return returns.pop(0)

    core = MagicMock()
    core.run_sql = fake_run_sql
    out = collect_report(core, top_n=5, path_sample_limit=0)
    assert out["summary_counts"]["total_rows"] == 5
    assert out["summary_counts"]["linked_rows"] == 5
    assert out["totals_by_run_type_link_state"][0]["count"] == 5
    assert out["host_path_probe"] is None
    assert all("LIKE 'dangling%'" not in sql for sql in seen_sql)
    assert any("LIKE _utf8mb4'dangling%%'" in sql for sql in seen_sql)


def test_collect_report_uses_explicit_collation_for_dangling_predicates() -> None:
    queries: list[str] = []

    def run_sql(sql, params=None, *, fetch="all", **_kwargs):  # type: ignore[no-untyped-def]
        normalized = " ".join(str(sql).split())
        queries.append(normalized)
        if "SELECT run_type, link_state, COUNT(*)" in normalized:
            return [("static", "linked", 2), ("static", "dangling_static_run", 1)]
        if "SELECT run_type, artifact_type, link_state" in normalized:
            return [("static", "report", "dangling_static_run", 1)]
        if "END AS age_bucket" in normalized:
            return [("static", "dangling_static_run", "90d+", 1)]
        if "WHERE run_type = 'static'" in normalized and "GROUP BY run_id" in normalized:
            return [("42", 1)]
        if "WHERE run_type = 'dynamic'" in normalized and "GROUP BY run_id" in normalized:
            return []
        if "run_id NOT REGEXP" in normalized:
            return [(0,)]
        if "WHERE ar.run_type = 'static'" in normalized:
            return [(1,)]
        raise AssertionError(normalized)

    data = collect_report(type("CoreQueries", (), {"run_sql": staticmethod(run_sql)})(), top_n=10, path_sample_limit=0)

    assert data["summary_counts"]["dangling_static_run_rows"] == 1
    dangling_queries = [query for query in queries if "LIKE _utf8mb4'dangling%%'" in query]
    assert len(dangling_queries) == 2
    assert all("CONVERT(link_state USING utf8mb4) COLLATE utf8mb4_unicode_ci" in query for query in dangling_queries)
    assert all(
        "_utf8mb4'unknown_run_type' COLLATE utf8mb4_unicode_ci" in query for query in dangling_queries
    )
    assert any("_utf8mb4'dangling_static_run' COLLATE utf8mb4_unicode_ci" in query for query in queries)
    assert any("_utf8mb4'dangling_dynamic_run' COLLATE utf8mb4_unicode_ci" in query for query in queries)


def test_script_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/report_artifact_registry_integrity.py", timeout=15)
