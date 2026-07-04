from __future__ import annotations

from pathlib import Path

from scytaledroid.Database.db_utils.schema_version_width_hotfix import (
    HOTFIX_SCHEMA_VERSION,
    planned_alter_sql,
    required_alter_sql,
    target_columns,
    write_schema_version_width_hotfix_preflight_bundle,
)


def test_schema_version_width_hotfix_targets_match_runtime_contract() -> None:
    targets = list(target_columns())
    assert len(targets) == 4
    unique_pairs = {(str(row["table"]), str(row["column"])) for row in targets}
    assert len(unique_pairs) == 4
    assert ("static_analysis_sessions", "schema_version") in unique_pairs
    assert ("static_analysis_runs", "schema_version") in unique_pairs
    assert ("dynamic_sessions", "schema_version") in unique_pairs
    assert ("runs", "schema_version") in unique_pairs
    assert len(HOTFIX_SCHEMA_VERSION) == 33


def test_schema_version_width_hotfix_planned_sql_only_mentions_target_tables() -> None:
    sql = planned_alter_sql()
    targets = list(target_columns())
    for target in targets:
        assert f"ALTER TABLE `{target['table']}`" in sql
        assert f"MODIFY COLUMN `{target['column']}`" in sql
    assert "ALTER TABLE `artifact_registry`" not in sql
    assert "ALTER TABLE `static_session_run_links`" not in sql


def test_schema_version_width_required_sql_empty_when_no_live_changes_are_needed(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_version_width_hotfix._build_required_alter_statements",
        lambda _run_sql: [],
    )
    assert required_alter_sql(lambda *_a, **_k: None) == ""


def test_schema_version_width_hotfix_bundle_writes_expected_receipt_files(tmp_path: Path) -> None:
    report = {
        "summary": {"target_column_count": 4, "preflight_clean": True},
        "columns": [{"table": "static_analysis_sessions", "column": "schema_version"}],
        "width_checks": [
            {
                "table": "static_analysis_sessions",
                "column": "schema_version",
                "fits_target_width": "yes",
            }
        ],
        "view_dependencies": [
            {"table": "static_analysis_sessions", "column": "schema_version", "view_name": "v_x"}
        ],
        "planned_alter_sql": "ALTER TABLE `static_analysis_sessions` MODIFY COLUMN `schema_version` varchar(64);",
        "migration_registry_preview": {"migration_id": "20260614_schema_version_width_hotfix_v1"},
    }

    files = write_schema_version_width_hotfix_preflight_bundle(
        report,
        tmp_path,
        stem="schema_version_width_hotfix_test",
    )

    expected = [
        "schema_version_width_hotfix_test_preflight.json",
        "schema_version_width_hotfix_test_columns.csv",
        "schema_version_width_hotfix_test_width_checks.csv",
        "schema_version_width_hotfix_test_view_dependencies.csv",
        "schema_version_width_hotfix_test_planned_alter.sql",
    ]
    for filename in expected:
        assert (tmp_path / filename).is_file(), filename
    assert files["planned_sql"].endswith("schema_version_width_hotfix_test_planned_alter.sql")
