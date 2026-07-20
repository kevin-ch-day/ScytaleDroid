"""DB schema snapshot policy, bridge posture snapshot block, and session digest tables.

Merged from ``test_status_actions_schema_snapshot_policy``,
``test_status_actions_snapshot_bridge``, ``test_query_runner_session_digest_policy``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from scytaledroid.Database.db_utils.action_groups import status_actions as sa
from scytaledroid.Database.db_utils.menus.query_runner import (
    SESSION_DIGEST_REQUIRED_GROUP_TABLES,
    SESSION_DIGEST_REQUIRED_SINGLE_TABLES,
)

# --- status_actions: schema snapshot policy (legacy mirror vs required static) ---


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


# --- status_actions: bridge posture snapshot block (no live DB) ---


def test_bridge_posture_snapshot_block_success(monkeypatch: pytest.MonkeyPatch) -> None:
    row = SimpleNamespace(
        table="android_permission_dict_aosp",
        posture="derived_review",
        owner="core",
        rationale="test",
        current_writers=("w",),
        current_readers=("r",),
    )
    monkeypatch.setattr(sa, "bridge_posture_summary", lambda: {"freeze_candidate": 1})
    monkeypatch.setattr(sa, "list_bridge_postures", lambda: [row])

    block, err = sa._bridge_posture_snapshot_block()

    assert err is None
    assert block["summary"] == {"freeze_candidate": 1}
    assert block["tables"] == [
        {
            "table": "android_permission_dict_aosp",
            "posture": "derived_review",
            "owner": "core",
            "rationale": "test",
            "current_writers": ["w"],
            "current_readers": ["r"],
        }
    ]


@pytest.mark.parametrize("failing_fn", ("summary", "list_rows"))
def test_bridge_posture_snapshot_block_failure_safe_defaults(
    monkeypatch: pytest.MonkeyPatch, failing_fn: str
) -> None:
    row = SimpleNamespace(
        table="t",
        posture="p",
        owner="o",
        rationale="r",
        current_writers=(),
        current_readers=(),
    )
    if failing_fn == "summary":
        monkeypatch.setattr(
            sa,
            "bridge_posture_summary",
            lambda: (_ for _ in ()).throw(RuntimeError("summary boom")),
        )
        monkeypatch.setattr(sa, "list_bridge_postures", lambda: [row])
    else:
        monkeypatch.setattr(sa, "bridge_posture_summary", lambda: {"a": 0})
        monkeypatch.setattr(
            sa,
            "list_bridge_postures",
            lambda: (_ for _ in ()).throw(OSError("list boom")),
        )

    block, err = sa._bridge_posture_snapshot_block()

    assert block == {"summary": {}, "tables": []}
    assert err is not None
    assert "boom" in err


# --- query_runner: session digest required-table policy ---


def test_session_digest_single_requires_canonical_findings_not_legacy() -> None:
    assert "static_analysis_findings" in SESSION_DIGEST_REQUIRED_SINGLE_TABLES
    assert "findings" not in SESSION_DIGEST_REQUIRED_SINGLE_TABLES


def test_session_digest_group_does_not_require_findings_table() -> None:
    assert "findings" not in SESSION_DIGEST_REQUIRED_GROUP_TABLES
    assert "static_analysis_findings" not in SESSION_DIGEST_REQUIRED_GROUP_TABLES
