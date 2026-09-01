from __future__ import annotations

import pytest
from scytaledroid.Database.db_queries.dynamic import schema
from scytaledroid.Database.db_utils import dynamic_domain_normalization as migration
from scytaledroid.Database.db_utils.schema_migration_registry import registered_migrations
from scytaledroid.DynamicAnalysis.storage import domain_context_index
from scytaledroid.Utils.domain_identity import (
    IP_CONTEXT_NORMALIZATION_KEY,
    build_root_domain_identity,
    registrable_domain_resolver_metadata,
)


def test_migration_script_help_is_side_effect_free(assert_safe_script_help) -> None:
    output = assert_safe_script_help("scripts/db/migrate_dynamic_domain_normalization.py")

    assert "--apply" in output
    assert "--confirm" in output


def test_pinned_psl_identity_is_parallel_to_legacy_aggregation_root() -> None:
    identity = build_root_domain_identity(
        "firebaseinstallations.googleapis.com",
        "googleapis.com",
    )

    assert identity.root_domain == "googleapis.com"
    assert identity.registrable_domain_psl == "firebaseinstallations.googleapis.com"
    assert identity.normalization_key == "psl:publicsuffixlist:1.0.2.20260625"
    assert (
        identity.reference_sha256
        == registrable_domain_resolver_metadata()["public_suffix_list_sha256"]
    )


def test_ip_identity_does_not_apply_psl() -> None:
    identity = build_root_domain_identity(
        "149.154.175.51",
        "149.154.160.0/20",
        is_ip=True,
    )

    assert identity.root_domain == "149.154.160.0/20"
    assert identity.registrable_domain_psl == "149.154.160.0/20"
    assert identity.normalization_key == IP_CONTEXT_NORMALIZATION_KEY
    assert identity.reference_sha256 is None


def test_candidate_worklist_distinguishes_root_changes_from_provenance_only() -> None:
    candidates = migration.build_candidates(
        [
            {
                "observation_id": 1,
                "dynamic_run_id": "run-1",
                "package_name": "com.example.one",
                "indicator_type": "dns",
                "observed_domain": "firebaseinstallations.googleapis.com",
                "root_domain": "googleapis.com",
            },
            {
                "observation_id": 2,
                "dynamic_run_id": "run-2",
                "package_name": "org.telegram.messenger",
                "indicator_type": "ip_dst",
                "observed_domain": "149.154.175.51",
                "root_domain": "149.154.160.0/20",
            },
        ]
    )

    summary = migration.summarize_candidates(candidates)
    assert summary == {
        "candidate_rows": 2,
        "rows_needing_update": 2,
        "psl_boundary_difference_rows": 1,
        "same_boundary_provenance_rows": 1,
        "packages_affected": 2,
        "runs_affected": 2,
        "root_domain_boundary_difference_counts": {"googleapis.com": 1},
    }


def test_candidate_worklist_is_idempotent_after_provenance_is_stored() -> None:
    identity = build_root_domain_identity(
        "firebaseinstallations.googleapis.com",
        "googleapis.com",
    )
    candidate = migration.build_candidates(
        [
            {
                "observation_id": 1,
                "dynamic_run_id": "run-1",
                "package_name": "com.example.one",
                "indicator_type": "dns",
                "observed_domain": "firebaseinstallations.googleapis.com",
                "root_domain": identity.root_domain,
                "registrable_domain_psl": identity.registrable_domain_psl,
                "registrable_domain_normalization": identity.normalization_key,
                "registrable_domain_reference_sha256": identity.reference_sha256,
            }
        ]
    )[0]

    assert candidate.needs_update is False
    assert candidate.psl_boundary_differs is True


def test_provenance_column_detection_requires_complete_column_set() -> None:
    def complete_run_sql(*_args, **_kwargs):
        return [{"column_name": name} for name in sorted(migration._PROVENANCE_COLUMNS)]

    def incomplete_run_sql(*_args, **_kwargs):
        return [{"column_name": "registrable_domain_psl"}]

    assert migration.normalization_columns_available(complete_run_sql, dialect="mysql") is True
    with pytest.raises(RuntimeError, match="partial registrable-domain schema"):
        migration.normalization_columns_available(incomplete_run_sql, dialect="mysql")


def test_provenance_probe_failure_is_not_downgraded_to_legacy_mode() -> None:
    class ProbeFailure(RuntimeError):
        pass

    def failed_run_sql(*_args, **_kwargs):
        raise ProbeFailure("database unavailable")

    with pytest.raises(ProbeFailure, match="database unavailable"):
        migration.normalization_columns_available(failed_run_sql, dialect="mysql")


def test_recorded_migration_rejects_missing_physical_schema() -> None:
    def fake_run_sql(_sql, _params=(), *, query_name=None, **_kwargs):
        if query_name is None:
            return {"migration_entry_id": 4}
        if query_name == "dynamic_domain_normalization.provenance_columns":
            return []
        raise AssertionError(query_name)

    with pytest.raises(RuntimeError, match="recorded as applied"):
        migration.apply_dynamic_domain_normalization_schema(fake_run_sql)


def test_worklist_hash_detects_changed_rows_and_order() -> None:
    candidates = migration.build_candidates(
        [
            {
                "observation_id": observation_id,
                "dynamic_run_id": f"run-{observation_id}",
                "package_name": "com.example",
                "indicator_type": "dns",
                "observed_domain": domain,
                "root_domain": "googleapis.com",
            }
            for observation_id, domain in (
                (1, "a.googleapis.com"),
                (2, "b.googleapis.com"),
            )
        ]
    )

    original = migration.candidate_worklist_sha256(candidates)
    assert original != migration.candidate_worklist_sha256(list(reversed(candidates)))
    changed = migration.build_candidates(
        [
            {
                "observation_id": 1,
                "dynamic_run_id": "run-1",
                "package_name": "com.example",
                "indicator_type": "dns",
                "observed_domain": "changed.googleapis.com",
                "root_domain": "googleapis.com",
            },
            candidates[1].as_dict(),
        ]
    )
    assert original != migration.candidate_worklist_sha256(changed)


def test_locked_observation_load_uses_for_update() -> None:
    statements: list[str] = []

    def fake_run_sql(sql, *_args, **_kwargs):
        statements.append(sql)
        return []

    migration.load_observation_rows(
        fake_run_sql,
        include_provenance=True,
        for_update=True,
    )
    assert statements and statements[0].rstrip().endswith("FOR UPDATE")


def test_writer_schema_probe_failure_prevents_unprovenanced_insert(monkeypatch) -> None:
    inserted: list[object] = []
    monkeypatch.setattr(
        domain_context_index,
        "_normalization_columns_available",
        lambda _run_sql: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_many",
        lambda *_args, **_kwargs: inserted.append(object()),
    )
    rows = domain_context_index.build_domain_observation_rows_from_network_indicators(
        [
            {
                "indicator_type": "dns",
                "indicator_value": "firebaseinstallations.googleapis.com",
            }
        ],
        dynamic_run_id="run-1",
        package_name="com.example",
    )

    with pytest.raises(RuntimeError, match="probe failed"):
        domain_context_index._insert_domain_observation_rows(rows, query_name="test")
    assert inserted == []


def test_candidate_updates_are_bounded_by_observation_and_run_ids() -> None:
    candidate = migration.build_candidates(
        [
            {
                "observation_id": 7,
                "dynamic_run_id": "run-7",
                "package_name": "com.example",
                "indicator_type": "dns",
                "observed_domain": "whoami.akamai.net",
                "root_domain": "akamai.net",
            }
        ]
    )[0]
    calls: list[tuple[str, tuple[object, ...]]] = []

    def fake_run_sql(sql, params=(), **_kwargs):  # noqa: ANN001
        calls.append((sql, tuple(params)))

    assert migration.apply_candidate_updates(fake_run_sql, [candidate]) == 1
    assert len(calls) == 1
    assert "WHERE observation_id = %s" in calls[0][0]
    assert "AND dynamic_run_id = %s" in calls[0][0]
    assert calls[0][1][-2:] == (7, "run-7")


def test_verification_reports_missing_or_mismatched_rows() -> None:
    candidates = migration.build_candidates(
        [
            {
                "observation_id": 3,
                "dynamic_run_id": "run-3",
                "package_name": "com.example",
                "indicator_type": "dns",
                "observed_domain": "x.azure-api.net",
                "root_domain": "azure-api.net",
            }
        ]
    )

    result = migration.verify_candidates([], candidates)
    assert result["ok"] is False
    assert result["missing_observation_ids"] == [3]


def test_writer_preserves_aggregation_root_before_provenance_columns_exist(monkeypatch) -> None:
    inserted: list[tuple[object, ...]] = []
    monkeypatch.setattr(domain_context_index, "_has_normalization_columns", lambda: False)
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_many",
        lambda _sql, data, **_kwargs: inserted.extend(tuple(row) for row in data),
    )
    rows = domain_context_index.build_domain_observation_rows_from_network_indicators(
        [
            {
                "indicator_type": "dns",
                "indicator_value": "firebaseinstallations.googleapis.com",
                "indicator_count": 3,
            }
        ],
        dynamic_run_id="run-1",
        package_name="com.example",
    )

    domain_context_index._insert_domain_observation_rows(rows, query_name="test")
    assert rows[0]["root_domain"] == "googleapis.com"
    assert rows[0]["registrable_domain_psl"] == "firebaseinstallations.googleapis.com"
    assert inserted[0][4] == "googleapis.com"
    assert len(inserted[0]) == 14


def test_writer_persists_parallel_psl_identity_after_migration(monkeypatch) -> None:
    inserted: list[tuple[object, ...]] = []
    monkeypatch.setattr(domain_context_index, "_has_normalization_columns", lambda: True)
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_many",
        lambda _sql, data, **_kwargs: inserted.extend(tuple(row) for row in data),
    )
    rows = domain_context_index.build_domain_observation_rows_from_network_indicators(
        [
            {
                "indicator_type": "dns",
                "indicator_value": "firebaseinstallations.googleapis.com",
                "indicator_count": 3,
            }
        ],
        dynamic_run_id="run-1",
        package_name="com.example",
    )

    domain_context_index._insert_domain_observation_rows(rows, query_name="test")
    assert inserted[0][4:8] == (
        "googleapis.com",
        "firebaseinstallations.googleapis.com",
        "psl:publicsuffixlist:1.0.2.20260625",
        "92a4b903fb95dea2535baf30dc7892c4151574c7c021e3591395fe02901b387c",
    )
    assert len(inserted[0]) == 17


def test_schema_and_registry_share_the_same_migration_contract() -> None:
    registered = next(
        spec for spec in registered_migrations() if spec.migration_id == migration.MIGRATION_ID
    )
    assert registered.checksum == migration.DYNAMIC_DOMAIN_NORMALIZATION_MIGRATION.checksum
    assert registered.schema_version_after == migration.SCHEMA_VERSION_AFTER
    ddl = "\n".join(schema._DDL_STATEMENTS)
    assert "registrable_domain_psl" in ddl
    assert "registrable_domain_normalization" in ddl
    assert "registrable_domain_reference_sha256" in ddl
