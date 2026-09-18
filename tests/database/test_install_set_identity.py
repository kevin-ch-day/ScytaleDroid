"""Known-answer coverage for split-aware package-lineage identity."""

from __future__ import annotations

from typing import Any

from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage

BASE_X = "a" * 64
SET_1204_HASH = "b" * 64
SET_1812_HASH = "c" * 64
BASE_LEGACY = "d" * 64


def _set(*, set_id: int, artifact_hash: str, members: int, splits: int) -> dict[str, Any]:
    return {
        "apk_set_id": set_id,
        "base_apk_sha256": BASE_X,
        "artifact_set_hash": artifact_hash,
        "package_name": "com.zhiliaoapp.musically",
        "version_code": "42",
        "version_name": "42.0",
        "member_count": members,
        "split_count": splits,
        "member_manifest": tuple(),
    }


def test_two_sets_sharing_a_base_hash_remain_two_coherent_rows() -> None:
    rows = lineage.expand_identity_rows(
        [
            {
                "apk_id": 77,
                "package_name": "com.zhiliaoapp.musically",
                "version_code": "42",
                "version_name": "42.0",
                "base_apk_sha256": BASE_X,
            },
            {
                "apk_id": 78,
                "package_name": "com.example.legacy",
                "version_code": "7",
                "version_name": "7.0",
                "base_apk_sha256": BASE_LEGACY,
            },
        ],
        {
            BASE_X: (
                _set(set_id=1204, artifact_hash=SET_1204_HASH, members=57, splits=56),
                _set(set_id=1812, artifact_hash=SET_1812_HASH, members=59, splits=58),
            )
        },
    )

    exact_rows = [row for row in rows if row["identity_kind"] == "exact_install_set"]
    assert [(row["apk_set_id"], row["artifact_set_hash"], row["member_count"], row["split_count"]) for row in exact_rows] == [
        (1204, SET_1204_HASH, 57, 56),
        (1812, SET_1812_HASH, 59, 58),
    ]
    legacy_row = next(row for row in rows if row["identity_kind"] == "base_only_legacy")
    assert legacy_row["apk_set_id"] is None
    assert legacy_row["artifact_set_hash"] is None


def test_presence_summary_does_not_hybridize_sibling_set_identity() -> None:
    unique_base = "e" * 64
    summary = lineage.summarize_install_set_presence_by_base_hash(
        {
            BASE_X: (
                {**_set(set_id=1204, artifact_hash=SET_1204_HASH, members=57, splits=56), "completeness_state": "complete"},
                {**_set(set_id=1812, artifact_hash=SET_1812_HASH, members=59, splits=58), "completeness_state": "unknown"},
            ),
            unique_base: (
                {
                    "apk_set_id": 9,
                    "base_apk_sha256": unique_base,
                    "artifact_set_hash": "f" * 64,
                    "member_count": 1,
                    "split_count": 0,
                    "completeness_state": "complete",
                },
            ),
        }
    )

    sibling = summary[BASE_X]
    assert sibling["install_sets_seen"] == 2
    assert sibling["apk_set_id"] is None
    assert sibling["artifact_set_hash"] is None
    assert sibling["member_count"] == 59
    assert sibling["split_count"] == 58
    assert sibling["complete_sets"] == 1
    assert sibling["completeness_state"] == "mixed"
    unique = summary[unique_base]
    assert unique["apk_set_id"] == 9
    assert unique["artifact_set_hash"] == "f" * 64
    assert unique["completeness_state"] == "complete"


def test_exact_static_and_dynamic_coverage_do_not_leak_to_sibling_set() -> None:
    set_1204 = {
        **_set(set_id=1204, artifact_hash=SET_1204_HASH, members=57, splits=56),
        "identity_kind": "exact_install_set",
    }
    set_1812 = {
        **_set(set_id=1812, artifact_hash=SET_1812_HASH, members=59, splits=58),
        "identity_kind": "exact_install_set",
    }
    exact_static = {
        (1204, SET_1204_HASH): {"canonical_completed_identity_valid": 1, "static_runs": 1}
    }
    exact_dynamic = {
        (1204, SET_1204_HASH): {"dynamic_sessions": 3, "dynamic_linked_sessions": 3}
    }

    assert lineage.coverage_for_identity(
        set_1204,
        exact_coverage=exact_static,
        legacy_base_coverage={},
    )["canonical_completed_identity_valid"] == 1
    assert lineage.coverage_for_identity(
        set_1812,
        exact_coverage=exact_static,
        legacy_base_coverage={},
    ) == {}
    assert lineage.coverage_for_identity(
        set_1204,
        exact_coverage=exact_dynamic,
        legacy_base_coverage={},
    )["dynamic_sessions"] == 3
    assert lineage.coverage_for_identity(
        set_1812,
        exact_coverage=exact_dynamic,
        legacy_base_coverage={},
    ) == {}


def test_base_only_legacy_evidence_stays_explicitly_base_only() -> None:
    base_only = {
        "identity_kind": "base_only_legacy",
        "base_apk_sha256": BASE_LEGACY,
        "apk_set_id": None,
        "artifact_set_hash": None,
    }
    coverage = lineage.coverage_for_identity(
        base_only,
        exact_coverage={(1204, SET_1204_HASH): {"dynamic_sessions": 3}},
        legacy_base_coverage={BASE_LEGACY: {"dynamic_sessions": 2, "dynamic_unlinked_sessions": 2}},
    )

    assert coverage == {"dynamic_sessions": 2, "dynamic_unlinked_sessions": 2}


def test_dynamic_coverage_can_use_a_matching_linked_static_identity_without_sibling_leakage() -> None:
    captured: dict[str, str] = {}

    class _Core:
        def run_sql(self, query, _params=(), *, query_name, **_kwargs):
            captured["query"] = query
            assert query_name == "package_lineage_read_model.exact_dynamic_coverage"
            return [
                {
                    "apk_set_id": 1204,
                    "artifact_set_hash": SET_1204_HASH,
                    "dynamic_sessions": 3,
                    "dynamic_unlinked_sessions": 0,
                    "dynamic_linked_sessions": 3,
                }
            ]

    coverage = lineage.fetch_exact_dynamic_coverage(_Core())

    assert coverage[(1204, SET_1204_HASH)]["dynamic_sessions"] == 3
    assert (1812, SET_1812_HASH) not in coverage
    assert "COALESCE(ds.apk_set_id, sar.apk_set_id)" in captured["query"]
    assert "ds.apk_set_id IS NULL OR sar.apk_set_id IS NULL OR ds.apk_set_id = sar.apk_set_id" in captured["query"]


def test_install_set_query_preserves_member_manifest_and_never_aggregates_siblings(monkeypatch) -> None:
    monkeypatch.setattr(lineage, "table_exists", lambda _core_q, _table: True)

    class _Core:
        def run_sql(self, _query, _params=(), *, query_name, **_kwargs):
            if query_name == "package_lineage_read_model.apk_sets":
                return [
                    _set(set_id=1204, artifact_hash=SET_1204_HASH, members=57, splits=56),
                    _set(set_id=1812, artifact_hash=SET_1812_HASH, members=59, splits=58),
                ]
            if query_name == "package_lineage_read_model.apk_set_members":
                return [
                    {"apk_set_id": 1204, "role": "base", "split_name": "", "sha256": BASE_X, "ordinal": 0, "member_status": "present"},
                    {"apk_set_id": 1812, "role": "base", "split_name": "", "sha256": BASE_X, "ordinal": 0, "member_status": "present"},
                ]
            raise AssertionError(query_name)

    sets = lineage.attach_install_set_members(_Core(), lineage.fetch_apk_sets_by_hash(_Core()))

    assert [(row["apk_set_id"], row["member_count"], row["split_count"]) for row in sets[BASE_X]] == [
        (1204, 57, 56),
        (1812, 59, 58),
    ]
    assert sets[BASE_X][0]["member_manifest"][0]["sha256"] == BASE_X
    assert sets[BASE_X][1]["member_manifest"][0]["sha256"] == BASE_X
