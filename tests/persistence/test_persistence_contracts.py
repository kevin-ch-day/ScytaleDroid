from scytaledroid.StaticAnalysis.cli.persistence.contracts import (
    AUTHORITATIVE_RUN_STATES,
    LEDGER_TABLES,
    SCIENTIFIC_UOW_TABLES,
    normalize_run_status,
)


def test_authoritative_run_state_mapping():
    assert normalize_run_status("RUNNING") == "STARTED"
    assert normalize_run_status("ABORTED") == "FAILED"
    assert normalize_run_status("COMPLETED") == "COMPLETED"
    assert normalize_run_status("STARTED") == "STARTED"
    assert normalize_run_status("garbage") == "FAILED"


def test_status_vocabulary_is_locked():
    assert AUTHORITATIVE_RUN_STATES == {"STARTED", "COMPLETED", "FAILED"}


def test_scientific_tables_do_not_overlap_ledger():
    assert SCIENTIFIC_UOW_TABLES.isdisjoint(LEDGER_TABLES)


def test_minimum_scientific_tables_present():
    expected = {
        "apps",
        "app_versions",
        "static_analysis_runs",
        "static_analysis_findings",
        "risk_scores",
        "static_permission_matrix",
        "static_permission_risk",
    }
    assert expected.issubset(SCIENTIFIC_UOW_TABLES)
