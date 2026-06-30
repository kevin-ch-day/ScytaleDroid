from __future__ import annotations

from scytaledroid.Database.db_utils.phase_b1_join_key_normalization import (
    backlog_session_stamp_target_columns,
    planned_backlog_session_stamp_alter_sql,
)

def test_phase_b1_session_stamp_backlog_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/phase_b1_session_stamp_backlog.py")
    assert_safe_script_help("scripts/db/phase_b1_session_stamp_backlog.py", "report")
    assert_safe_script_help("scripts/db/phase_b1_session_stamp_backlog.py", "apply")


def test_report_phase_b1_session_stamp_backlog_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/report_phase_b1_session_stamp_backlog.py")


def test_apply_phase_b1_session_stamp_backlog_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/apply_phase_b1_session_stamp_backlog.py")


def test_backlog_session_stamp_targets_match_second_wave_contract() -> None:
    targets = list(backlog_session_stamp_target_columns())
    assert len(targets) == 7
    unique_pairs = {(str(row["table"]), str(row["column"])) for row in targets}
    assert len(unique_pairs) == 7
    assert ("risk_scores", "session_stamp") in unique_pairs
    assert ("static_fileproviders", "session_stamp") in unique_pairs
    assert ("static_session_rollups", "session_stamp") in unique_pairs


def test_backlog_session_stamp_planned_alter_sql_only_mentions_second_wave_targets() -> None:
    sql = planned_backlog_session_stamp_alter_sql()
    targets = list(backlog_session_stamp_target_columns())
    for target in targets:
        assert f"ALTER TABLE `{target['table']}`" in sql
        assert f"MODIFY COLUMN `{target['column']}`" in sql
    assert "ALTER TABLE `static_analysis_runs`" not in sql
    assert "ALTER TABLE `artifact_registry`" not in sql
