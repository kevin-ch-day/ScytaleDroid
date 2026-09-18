from __future__ import annotations

import pytest
from scytaledroid.Database.db_utils.install_set_hash_version_propagation import (
    IDENTITY_CONFLICT,
    SCHEMA_VERSION_AFTER,
    VERSION_UNKNOWN_LEGACY,
    IsolatedIdentityRehearsal,
    apply_install_set_hash_version_propagation,
    apply_missing_ddl,
    build_preflight,
    decide_static_version,
    dynamic_legacy_classification,
    is_production_database,
    summarize_static_backfill,
)


def row(**kw):
    return {
        "id": 1,
        "apk_set_id": 4,
        "artifact_set_hash": "a" * 64,
        "linked_artifact_set_hash": "a" * 64,
        "linked_artifact_set_hash_version": "v1",
        **kw,
    }


def test_safe_v1_and_v2_backfill_decisions():
    assert decide_static_version(row()).version == "v1"
    assert decide_static_version(row(linked_artifact_set_hash_version="v2")).version == "v2"


def test_conflict_and_unknown_fail_closed():
    assert decide_static_version(row(linked_artifact_set_hash="b" * 64)).classification == IDENTITY_CONFLICT
    assert decide_static_version(row(apk_set_id=None)).classification == VERSION_UNKNOWN_LEGACY
    assert dynamic_legacy_classification({"artifact_set_hash": "a" * 64}) == VERSION_UNKNOWN_LEGACY


def test_summary_separates_safe_conflict_and_unknown():
    got = summarize_static_backfill(
        [row(), row(id=2, linked_artifact_set_hash="b" * 64), row(id=3, apk_set_id=None)]
    )
    assert got == {
        "static_total": 3,
        "static_safe_candidates": 1,
        "static_conflicts": 1,
        "static_insufficient_proof": 1,
    }


def test_production_catalog_detection():
    assert is_production_database("scytaledroid_core_prod") is True
    assert is_production_database("scytaledroid_core_rehearsal") is False


def _store(*, conflict: bool = False) -> IsolatedIdentityRehearsal:
    linked_hash = "b" * 64 if conflict else "a" * 64
    return IsolatedIdentityRehearsal(
        static_rows=[
            {
                "id": 11,
                "apk_set_id": 843,
                "artifact_set_hash": "a" * 64,
                "stored_artifact_set_hash_version": None,
                "linked_artifact_set_hash": linked_hash,
                "linked_artifact_set_hash_version": "v1",
            },
            {
                "id": 12,
                "apk_set_id": None,
                "artifact_set_hash": "c" * 64,
                "stored_artifact_set_hash_version": None,
                "linked_artifact_set_hash": None,
                "linked_artifact_set_hash_version": None,
            },
        ],
        dynamic_rows=[
            {
                "dynamic_run_id": "dyn-1",
                "apk_set_id": 843,
                "artifact_set_hash": "a" * 64,
                "artifact_set_hash_version": None,
            }
        ],
    )


def test_isolated_rehearsal_resumes_after_implicit_commit_interrupt():
    store = _store()
    with pytest.raises(RuntimeError, match="implicit-commit interrupt"):
        apply_missing_ddl(store.run_sql, crash_after=1)
    assert store.columns["static_analysis_runs"]
    assert not store.columns["dynamic_sessions"]

    result = apply_install_set_hash_version_propagation(
        store.run_sql,
        database_name="scytaledroid_core_rehearsal",
        allow_production=False,
    )
    assert result["verification"]["ok"] is True
    assert result["ddl"]["schema_posture_after"] == "complete"
    assert result["static"]["static_safe_candidates"] == 1
    assert result["static"]["static_insufficient_proof"] == 1
    assert result["static"]["static_conflicts"] == 0
    assert result["dynamic"]["dynamic_version_unknown_legacy"] == 1
    assert result["dynamic"]["dynamic_automatic_version_backfill"] == 0
    assert store.static_rows[0]["stored_artifact_set_hash_version"] == "v1"
    assert store.static_rows[1]["stored_artifact_set_hash_version"] is None
    assert store.dynamic_rows[0]["artifact_set_hash_version"] is None
    assert SCHEMA_VERSION_AFTER in store.schema_versions
    assert result["verification"]["static_updated"] == 1


def test_identity_conflict_blocks_apply():
    store = _store(conflict=True)
    preflight = build_preflight(store.run_sql, database_name="scytaledroid_core_rehearsal")
    assert preflight["apply_blocked_reason"] == "unexplained_static_identity_conflict"
    with pytest.raises(RuntimeError, match="unexplained_static_identity_conflict"):
        apply_install_set_hash_version_propagation(
            store.run_sql,
            database_name="scytaledroid_core_rehearsal",
            allow_production=False,
        )
    assert not store.columns["static_analysis_runs"]


def test_rehearsal_refuses_production_catalog():
    store = _store()
    with pytest.raises(RuntimeError, match="production catalog"):
        apply_install_set_hash_version_propagation(
            store.run_sql,
            database_name="scytaledroid_core_prod",
            allow_production=False,
        )


def test_apply_is_idempotent_after_successful_rehearsal():
    store = _store()
    first = apply_install_set_hash_version_propagation(
        store.run_sql,
        database_name="scytaledroid_core_rehearsal",
        allow_production=False,
    )
    second = apply_install_set_hash_version_propagation(
        store.run_sql,
        database_name="scytaledroid_core_rehearsal",
        allow_production=False,
    )
    assert first["verification"]["ok"] is True
    assert second["verification"]["ok"] is True
    assert store.static_rows[0]["stored_artifact_set_hash_version"] == "v1"
    assert store.applied_migrations.count(
        "20260918_install_set_hash_version_propagation_v1"
    ) == 1


def test_migration_script_help_is_side_effect_free(assert_safe_script_help) -> None:
    output = assert_safe_script_help("scripts/db/migrate_install_set_hash_version_propagation.py")
    assert "--apply" in output
    assert "--confirm" in output
    assert "--rehearse" in output
    assert "--rehearse-offline" in output
