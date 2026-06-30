from __future__ import annotations

from pathlib import Path

from scytaledroid.Database.db_utils.phase_b1_join_key_normalization import (
    migration_preview,
    planned_alter_sql,
    required_alter_sql,
    target_columns,
    write_phase_b1_join_key_preflight_bundle,
)


def test_phase_b1_join_key_normalization_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/phase_b1_join_key_normalization.py")
    assert_safe_script_help("scripts/db/phase_b1_join_key_normalization.py", "report")
    assert_safe_script_help("scripts/db/phase_b1_join_key_normalization.py", "apply")


def test_report_phase_b1_join_key_normalization_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/report_phase_b1_join_key_normalization.py")


def test_apply_phase_b1_join_key_normalization_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/apply_phase_b1_join_key_normalization.py")


def test_phase_b1_target_columns_match_first_wave_contract() -> None:
    targets = list(target_columns())
    assert len(targets) == 12
    unique_pairs = {(str(row["table"]), str(row["column"])) for row in targets}
    assert len(unique_pairs) == 12
    assert ("static_session_run_links", "session_stamp") in unique_pairs
    assert ("analysis_dynamic_cohort_status", "package_name_lc") in unique_pairs


def test_planned_alter_sql_only_mentions_first_wave_targets() -> None:
    sql = planned_alter_sql()
    targets = list(target_columns())
    for target in targets:
        assert f"ALTER TABLE `{target['table']}`" in sql
        assert f"MODIFY COLUMN `{target['column']}`" in sql
    assert "ALTER TABLE `artifact_registry`" not in sql
    assert "ALTER TABLE `static_analysis_findings`" not in sql


def test_required_alter_sql_empty_when_no_live_changes_are_needed(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.phase_b1_join_key_normalization.build_required_alter_statements",
        lambda _run_sql: [],
    )
    assert required_alter_sql(lambda *_a, **_k: None) == ""


def test_phase_b1_bundle_writes_expected_receipt_files(tmp_path: Path) -> None:
    report = {
        "summary": {"target_column_count": 12, "preflight_clean": True},
        "columns": [{"table": "static_analysis_sessions", "column": "session_stamp"}],
        "duplicate_checks": [],
        "width_checks": [{"table": "static_analysis_sessions", "column": "session_stamp", "width_safe": "yes"}],
        "join_parity_before": [{"join_name": "x", "join_count": 1}],
        "view_dependencies": [{"table": "static_analysis_sessions", "column": "session_stamp", "view_name": "v_x"}],
        "planned_alter_sql": "ALTER TABLE `static_analysis_sessions` MODIFY COLUMN `session_stamp` varchar(128);",
        "migration_registry_preview": migration_preview("20260614_phase_b1_join_key_collation_width_normalization"),
    }

    files = write_phase_b1_join_key_preflight_bundle(
        report,
        tmp_path,
        stem="phase_b1_join_key_normalization_test",
    )

    expected = [
        "phase_b1_join_key_normalization_test_preflight.json",
        "phase_b1_join_key_normalization_test_columns.csv",
        "phase_b1_join_key_normalization_test_duplicate_checks.csv",
        "phase_b1_join_key_normalization_test_width_checks.csv",
        "phase_b1_join_key_normalization_test_join_parity_before.csv",
        "phase_b1_join_key_normalization_test_view_dependencies.csv",
        "phase_b1_join_key_normalization_test_planned_alter.sql",
    ]
    for filename in expected:
        assert (tmp_path / filename).is_file(), filename
    assert files["planned_sql"].endswith("phase_b1_join_key_normalization_test_planned_alter.sql")
