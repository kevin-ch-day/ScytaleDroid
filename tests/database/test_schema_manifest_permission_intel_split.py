from __future__ import annotations

from scytaledroid.Database.db_queries import schema_manifest


def test_operational_schema_manifest_excludes_permission_intel_managed_tables():
    statements = "\n".join(schema_manifest.ordered_schema_statements())

    excluded = [
        "CREATE TABLE IF NOT EXISTS permission_governance_snapshots",
        "CREATE TABLE IF NOT EXISTS permission_governance_snapshot_rows",
        "CREATE TABLE IF NOT EXISTS permission_signal_catalog",
        "CREATE TABLE IF NOT EXISTS permission_signal_mappings",
        "CREATE TABLE IF NOT EXISTS permission_cohort_expectations",
    ]
    for marker in excluded:
        assert marker not in statements, marker

    assert "CREATE TABLE IF NOT EXISTS permission_audit_snapshots" in statements
    assert "CREATE TABLE IF NOT EXISTS permission_audit_apps" in statements


def test_permission_intel_schema_manifest_contains_dedicated_managed_tables():
    statements = "\n".join(schema_manifest.permission_intel_schema_statements())

    required = [
        "CREATE TABLE IF NOT EXISTS permission_governance_snapshots",
        "CREATE TABLE IF NOT EXISTS permission_governance_snapshot_rows",
        "CREATE TABLE IF NOT EXISTS permission_signal_catalog",
        "CREATE TABLE IF NOT EXISTS permission_signal_mappings",
        "CREATE TABLE IF NOT EXISTS permission_cohort_expectations",
    ]
    for marker in required:
        assert marker in statements, marker
