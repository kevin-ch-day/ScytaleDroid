from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.permissions.audit import PermissionAuditAccumulator
from scytaledroid.StaticAnalysis.modules.permissions.audit import _build_snapshot_lineage


def test_build_snapshot_lineage_tracks_fleet_static_run_ids() -> None:
    lineage = _build_snapshot_lineage(
        session_stamp="20260429-all-full",
        snapshot_key="perm-audit:app:20260429-all-full",
        run_id=None,
        static_run_id=None,
        run_map_payload={"by_package": {"com.a": {"static_run_id": 101}, "com.b": {"static_run_id": 202}}},
        static_run_id_map={"com.a": 101, "com.b": 202},
        run_map_required=True,
    )

    assert lineage["session_stamp"] == "20260429-all-full"
    assert lineage["static_run_count"] == 2
    assert lineage["static_run_ids"] == [101, 202]
    assert lineage["run_map_packages"] == 2
    assert lineage["run_map_required"] is True
    assert lineage["run_map_sha256"]


def test_build_snapshot_lineage_promotes_single_run_id_when_stable() -> None:
    lineage = _build_snapshot_lineage(
        session_stamp="20260429-single",
        snapshot_key="perm-audit:app:20260429-single",
        run_id=None,
        static_run_id=None,
        run_map_payload={"by_package": {"com.a": {"static_run_id": 777}}},
        static_run_id_map={"com.a": 777},
        run_map_required=False,
    )

    assert lineage["static_run_count"] == 1
    assert lineage["static_run_id"] == 777


def test_permission_audit_accumulator_clamps_negative_capped_score() -> None:
    accumulator = PermissionAuditAccumulator(
        scope_label="Example",
        scope_type="profile",
        total_groups=1,
        snapshot_id="perm-audit:app:test",
    )

    score_detail = {
        "score_raw": -0.5,
        "score_capped": -0.5,
        "score_3dp": -0.5,
        "grade": "A",
    }
    accumulator.add_app(
        package="com.example.app",
        label="Example",
        cohort="test",
        sdk={"target": 35},
        counts={"dangerous": 0, "signature": 0, "oem": 0},
        groups={},
        declared_in={},
        declared_permissions=[],
        score_detail=score_detail,
        vendor_present=False,
    )

    stored = accumulator.apps[0].score_detail
    assert stored["score_raw"] == -0.5
    assert stored["score_capped"] == 0.0
    assert stored["score_3dp"] == 0.0
