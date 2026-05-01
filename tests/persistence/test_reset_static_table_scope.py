from scytaledroid.Database.db_utils.reset_static import STATIC_ANALYSIS_TABLES


def test_reset_static_tables_include_scientific_run_scoped_permission_and_correlation_tables():
    expected = {
        "static_analysis_findings",
        "static_permission_matrix",
        "static_correlation_results",
        "masvs_control_coverage",
        "doc_hosts",
    }
    assert expected.issubset(set(STATIC_ANALYSIS_TABLES))
