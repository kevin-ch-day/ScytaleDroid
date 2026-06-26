from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from scytaledroid.Database.db_utils.phase_a_typed_replacements import backfill_typed_replacement_columns
from scytaledroid.Database.db_queries import canonical as canonical_queries
from scytaledroid.Database.db_queries import dynamic as dynamic_queries
from scytaledroid.Database.db_utils.schema_migration_registry import (
    build_schema_migration_report,
    attach_receipt_path_to_latest_migration,
    duplicate_registry_ids,
    latest_registered_schema_version,
    latest_schema_version,
    registry_version_chain_issues,
    registered_migrations,
    schema_version_gte,
    write_schema_migration_report_bundle,
)
from scytaledroid.Database.db_utils.type_normalization_preflight import (
    collect_type_normalization_preflight,
    write_type_normalization_preflight_bundle,
)


def test_schema_migration_registry_has_no_duplicate_ids() -> None:
    assert duplicate_registry_ids() == {}
    assert len(registered_migrations()) >= 3
    assert registry_version_chain_issues() == []
    assert latest_registered_schema_version() == "0.3.14-static-finding-evidence-payload-schema"


def test_runtime_schema_version_ddl_matches_live_hotfix_contract() -> None:
    canonical_schema_text = canonical_queries.schema.__file__
    dynamic_schema_text = dynamic_queries.schema.__file__
    assert canonical_schema_text
    assert dynamic_schema_text
    canonical_source = Path(canonical_schema_text).read_text(encoding="utf-8")
    dynamic_source = Path(dynamic_schema_text).read_text(encoding="utf-8")
    assert "schema_version VARCHAR(64) DEFAULT NULL" in canonical_source
    assert "schema_version     VARCHAR(64)  DEFAULT NULL" in dynamic_source
    assert "schema_version VARCHAR(32) DEFAULT NULL" not in canonical_source
    assert "schema_version     VARCHAR(32)  DEFAULT NULL" not in dynamic_source


def test_schema_version_gte_handles_semantic_and_branch_like_versions() -> None:
    assert schema_version_gte("0.3.5-b1-session-stamp-backlog-normalization", "0.3.5-b1-session-stamp-backlog-normalization") is True
    assert schema_version_gte("0.3.5-b1-session-stamp-backlog-normalization", "0.2.6") is True
    assert schema_version_gte("0.3.4-b1-join-key-normalization", "0.3.5-b1-session-stamp-backlog-normalization") is False


def test_report_schema_migrations_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_schema_migrations.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")


def test_backfill_phase_a_typed_replacements_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_phase_a_typed_replacements.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")


def test_report_type_normalization_preflight_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_type_normalization_preflight.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")


def test_collect_type_normalization_preflight_and_write_bundle(tmp_path: Path) -> None:
    query_rows = {
        "type_preflight.dynamic_uuid": {
            "total_dynamic_registry_rows": 10,
            "blank_dynamic_run_id_rows": 0,
            "dynamic_run_id_len36_rows": 10,
            "uuid_like_dynamic_run_id_rows": 10,
            "incompatible_dynamic_run_id_length_rows": 0,
        },
        "type_preflight.dynamic_static_fk": {
            "dynamic_sessions_static_run_id_nonnull_rows": 3,
            "dynamic_sessions_static_run_id_orphan_rows": 0,
        },
        "type_preflight.dynamic_static_type": [{"column_type": "bigint(20)", "is_nullable": "YES"}],
        "type_preflight.static_run_pk_type": [{"column_type": "bigint(20) unsigned", "is_nullable": "NO"}],
        "type_preflight.run_started": {
            "total_static_runs": 4,
            "blank_run_started_rows": 0,
            "parseable_run_started_rows": 4,
            "unparseable_run_started_rows": 0,
        },
        "type_preflight.status_domains": [
            {"domain_name": "artifact_registry.run_type", "domain_value": "dynamic", "row_count": 10}
        ],
        "type_preflight.collation_rows": [
            {"table_name": "apps", "column_name": "package_name", "collation_name": "utf8mb4_unicode_ci"},
            {"table_name": "apk_sets", "column_name": "package_name", "collation_name": "utf8mb4_general_ci"},
        ],
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        return query_rows[query_name]

    report = collect_type_normalization_preflight(fake_run_sql)
    assert report["summary"]["preflight_clean"] is True
    assert report["summary"]["collation_drift_count"] == 1
    files = write_type_normalization_preflight_bundle(report, tmp_path, stem="phase_a_type_normalization_preflight_test")
    payload = json.loads((tmp_path / "phase_a_type_normalization_preflight_test.json").read_text(encoding="utf-8"))
    assert payload["summary"]["preflight_clean"] is True
    assert files["json"].endswith("phase_a_type_normalization_preflight_test.json")


def test_latest_schema_version_prefers_schema_migration_registry() -> None:
    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.3-typed-backfill"}
        raise AssertionError("schema_version fallback should not be queried when registry is present")

    assert latest_schema_version(fake_run_sql) == "0.3.3-typed-backfill"


def test_attach_receipt_path_updates_latest_migration_row() -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), query_name))
        return None

    attach_receipt_path_to_latest_migration(
        fake_run_sql,
        migration_id="20260614_phase_a_typed_replacement_backfill_v1",
        receipt_path="/tmp/receipt.json",
    )
    assert calls
    _, params, query_name = calls[0]
    assert query_name == "schema_migrations.attach_receipt_path"
    assert params == ("/tmp/receipt.json", "20260614_phase_a_typed_replacement_backfill_v1")


def test_build_schema_migration_report_and_bundle(tmp_path: Path) -> None:
    rows = [
        {
            "migration_entry_id": 1,
            "migration_id": "20260614_phase_a_migration_governance_v1",
            "migration_name": "baseline",
            "applied_at_utc": "2026-06-14 00:00:00",
            "repo_git_commit": "abc123",
            "schema_version_before": "0.3.0-bootstrap",
            "schema_version_after": "0.3.1-schema-governance",
            "migration_checksum": registered_migrations()[0].checksum,
            "applied_by": "tester",
            "host_name": "host",
            "status": "applied",
            "notes": None,
            "receipt_path": "/tmp/one.json",
        },
        {
            "migration_entry_id": 2,
            "migration_id": "manual_unregistered_probe",
            "migration_name": "probe",
            "applied_at_utc": "2026-06-14 00:05:00",
            "repo_git_commit": "abc123",
            "schema_version_before": "0.3.1-schema-governance",
            "schema_version_after": "0.3.1-schema-governance",
            "migration_checksum": "deadbeef",
            "applied_by": "tester",
            "host_name": "host",
            "status": "applied",
            "notes": None,
            "receipt_path": None,
        },
    ]

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.3-typed-backfill"}
        if query_name == "schema_migrations.load_rows":
            return rows
        raise AssertionError(f"unexpected query_name: {query_name}")

    report = build_schema_migration_report(fake_run_sql)
    assert report["summary"]["registered_migration_count"] >= 3
    assert report["summary"]["missing_migration_count"] >= 2
    assert report["summary"]["checksum_mismatch_count"] == 0
    assert report["summary"]["unregistered_applied_row_count"] == 1
    assert report["missing_migrations"]
    assert report["unregistered_applied_rows"][0]["migration_id"] == "manual_unregistered_probe"

    files = write_schema_migration_report_bundle(report, tmp_path, stem="schema_migration_report_test")
    payload = json.loads((tmp_path / "schema_migration_report_test.json").read_text(encoding="utf-8"))
    assert payload["summary"]["unregistered_applied_row_count"] == 1
    assert files["json"].endswith("schema_migration_report_test.json")
    assert (tmp_path / "schema_migration_report_test_registered_migrations.csv").is_file()
    assert (tmp_path / "schema_migration_report_test_missing_migrations.txt").is_file()


def test_backfill_typed_replacement_columns_records_counts() -> None:
    state = {
        "latest_version": "0.3.1-schema-governance",
        "applied_migrations": {"20260614_phase_a_migration_governance_v1"},
        "recorded": [],
        "appended": [],
        "statements": [],
    }

    query_rows: dict[str | None, object] = {
        "type_preflight.dynamic_uuid": {
            "total_dynamic_registry_rows": 10,
            "blank_dynamic_run_id_rows": 0,
            "dynamic_run_id_len36_rows": 10,
            "uuid_like_dynamic_run_id_rows": 10,
            "incompatible_dynamic_run_id_length_rows": 0,
        },
        "type_preflight.dynamic_static_fk": {
            "dynamic_sessions_static_run_id_nonnull_rows": 2,
            "dynamic_sessions_static_run_id_orphan_rows": 0,
        },
        "type_preflight.dynamic_static_type": [{"column_type": "bigint(20)", "is_nullable": "YES"}],
        "type_preflight.static_run_pk_type": [{"column_type": "bigint(20) unsigned", "is_nullable": "NO"}],
        "type_preflight.run_started": {
            "total_static_runs": 4,
            "blank_run_started_rows": 0,
            "parseable_run_started_rows": 4,
            "unparseable_run_started_rows": 0,
        },
        "type_preflight.status_domains": [],
        "type_preflight.collation_rows": [],
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": state["latest_version"]}
        if query_name == "schema_migrations.load_rows":
            rows: list[dict[str, object]] = []
            for idx, migration_id in enumerate(sorted(state["applied_migrations"]), start=1):
                rows.append(
                    {
                        "migration_entry_id": idx,
                        "migration_id": migration_id,
                        "status": "applied",
                    }
                )
            return rows
        if query_name == "schema_migrations.insert":
            state["recorded"].append(tuple(params))
            migration_id = str(params[0])
            state["applied_migrations"].add(migration_id)
            if migration_id == "20260614_phase_a_typed_replacement_columns_v1":
                state["latest_version"] = "0.3.2-typed-columns"
            elif migration_id == "20260614_phase_a_typed_replacement_backfill_v1":
                state["latest_version"] = "0.3.3-typed-backfill"
            return None
        if query_name == "schema_migrations.append_schema_version":
            state["appended"].append(tuple(params))
            state["latest_version"] = str(params[0])
            return None
        if query_name and query_name.startswith("schema_migrations.apply."):
            state["statements"].append(sql.strip())
            return None
        result = query_rows.get(query_name)
        if isinstance(result, Mapping):
            return dict(result)
        if isinstance(result, list):
            return [dict(row) if isinstance(row, Mapping) else row for row in result]
        raise AssertionError(f"unexpected query_name: {query_name}")

    def fake_run_sql_rowcount(sql, params=(), *, query_name=None):  # noqa: ANN001,ARG001
        if query_name == "phase_a_typed_replacements.backfill_artifact_registry":
            return 10
        if query_name == "phase_a_typed_replacements.backfill_dynamic_sessions":
            return 2
        if query_name == "phase_a_typed_replacements.backfill_static_runs":
            return 4
        raise AssertionError(f"unexpected rowcount query: {query_name}")

    result = backfill_typed_replacement_columns(fake_run_sql, fake_run_sql_rowcount)
    assert result.ddl_applied is True
    assert result.artifact_registry_dynamic_run_uuid_backfilled == 10
    assert result.dynamic_sessions_static_run_id_u_backfilled == 2
    assert result.static_analysis_runs_run_started_at_utc_backfilled == 4
    assert result.latest_schema_version_after == "0.3.3-typed-backfill"
    assert len(state["recorded"]) == 2
    assert state["appended"][-1][0] == "0.3.3-typed-backfill"
