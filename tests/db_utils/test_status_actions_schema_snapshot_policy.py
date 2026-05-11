"""Policy constants for DB schema snapshot (legacy mirror vs required static)."""

from __future__ import annotations

from scytaledroid.Database.db_utils.action_groups import status_actions as sa


def test_required_static_tables_exclude_legacy_findings() -> None:
    assert "findings" not in sa.DB_SNAPSHOT_REQUIRED_STATIC_TABLES
    assert "static_analysis_runs" in sa.DB_SNAPSHOT_REQUIRED_STATIC_TABLES
    assert "static_analysis_findings" in sa.DB_SNAPSHOT_REQUIRED_STATIC_TABLES
    assert "static_permission_matrix" in sa.DB_SNAPSHOT_REQUIRED_STATIC_TABLES


def test_required_static_tables_cover_static_schema_gate_surfaces() -> None:
    """Snapshot ``required_tables.static`` should include every object required by ``static_schema_gate``."""
    required = set(sa.DB_SNAPSHOT_REQUIRED_STATIC_TABLES)
    for table in (
        "static_analysis_runs",
        "static_analysis_findings",
        "static_permission_matrix",
        "static_string_summary",
        "static_string_samples",
        "static_session_run_links",
        "static_session_rollups",
        "v_static_handoff_v1",
    ):
        assert table in required


def test_legacy_mirror_tables_are_legacy_five() -> None:
    assert set(sa.DB_SNAPSHOT_LEGACY_MIRROR_TABLES) == {
        "runs",
        "findings",
        "metrics",
        "buckets",
        "contributors",
    }


def test_legacy_mirror_meta_documents_optional_role() -> None:
    meta = sa.DB_SCHEMA_SNAPSHOT_LEGACY_MIRROR_META
    assert meta.get("role") == "legacy_mirror_compatibility_optional"
    text = meta.get("interpretation", "")
    assert "legacy mirror" in text.lower() or "Legacy mirror" in text
    assert "canonical" in text.lower()
    assert "gates.static_schema_gate" in text

