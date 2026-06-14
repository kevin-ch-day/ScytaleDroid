"""Unit tests for dynamic/static alignment SQL helpers (no live DB)."""

from __future__ import annotations

from scytaledroid.Database.db_scripts import dynamic_static_alignment_report as m


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
