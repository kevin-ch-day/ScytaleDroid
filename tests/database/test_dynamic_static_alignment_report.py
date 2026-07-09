"""Unit tests for dynamic/static alignment SQL helpers (no live DB)."""

from __future__ import annotations

from scripts.db import report_dynamic_static_alignment as report
from scytaledroid.Database.db_scripts import dynamic_static_alignment_report as m


class _FakeCoreQ:
    def run_sql(self, sql, params=(), **kwargs):  # noqa: ANN001, ANN201
        table = params[0]
        if table == "dynamic_sessions":
            return [
                {
                    "index_name": "ix_dynamic_sessions_base_apk_sha256",
                    "column_name": "base_apk_sha256",
                }
            ]
        if table == "static_analysis_runs":
            return [
                {
                    "index_name": "ix_static_runs_base_hash_contract",
                    "column_name": "base_apk_sha256",
                },
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "status"},
                {"index_name": "ix_static_runs_base_hash_contract", "column_name": "run_class"},
                {
                    "index_name": "ix_static_runs_base_hash_contract",
                    "column_name": "identity_valid",
                },
            ]
        return []


def test_hash_join_uses_unicode_ci_convert() -> None:
    assert "COLLATE utf8mb4_unicode_ci" in m.HASH_EQ_DS_REPO
    assert "ds.base_apk_sha256" in m.HASH_EQ_DS_REPO
    assert "r.sha256" in m.HASH_EQ_DS_REPO


def test_qualifying_static_predicate_aliases_sar() -> None:
    s = m.SAR_QUALIFYING_SQL.lower()
    assert "sar.status" in s
    assert "canonical" in s
    assert "identity_valid" in s


def test_bucket_queries_reference_dynamic_sessions() -> None:
    for fn in (
        m.bucket_sql_exact_static_run_linked,
        m.bucket_sql_static_run_id_points_to_bad_static_run,
        m.bucket_sql_dynamic_missing_base_apk_hash,
        m.bucket_sql_dynamic_hash_missing_from_repository,
        m.bucket_sql_static_run_id_missing_exact_hash_exists,
        m.bucket_sql_package_exists_but_hash_differs,
        m.bucket_sql_repository_hash_known_static_run_missing,
    ):
        sql = fn().lower()
        assert "dynamic_sessions" in sql
        assert "select count(*)" in sql
        assert "static_run_id_u" in sql or "cast(ds.static_run_id as unsigned)" in sql


def test_worklist_sql_distinct_and_limits() -> None:
    sql = m.sql_worklist(17).lower()
    assert "group by ds.package_name" in sql
    assert "limit 17" in sql
    assert "analyze_exact_dynamic_apk_hash" in sql
    assert "harvest_artifact_paths" in sql
    assert "harvest_source_paths" in sql
    assert "static_run_id_u" in sql or "cast(ds.static_run_id as unsigned)" in sql


def test_worklist_distinct_count_subquery() -> None:
    sql = m.sql_worklist_distinct_hash_count().lower()
    assert "select distinct ds.package_name" in sql


def test_index_posture_accepts_static_composite_as_base_hash_coverage() -> None:
    posture = report._index_posture(_FakeCoreQ())
    assert posture["dynamic_sessions_base_apk_sha256_index_present"] == 1
    assert posture["static_runs_base_hash_contract_index_present"] == 1
    assert posture["static_runs_base_apk_sha256_index_covered"] == 1
