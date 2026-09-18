from scytaledroid.Database.db_utils.install_set_hash_version_propagation import (
    IDENTITY_CONFLICT, VERSION_UNKNOWN_LEGACY, decide_static_version, dynamic_legacy_classification, summarize_static_backfill,
)
def row(**kw):
    return {"id":1,"apk_set_id":4,"artifact_set_hash":"a"*64,"linked_artifact_set_hash":"a"*64,"linked_artifact_set_hash_version":"v1",**kw}
def test_safe_v1_and_v2_backfill_decisions():
    assert decide_static_version(row()).version == "v1"
    assert decide_static_version(row(linked_artifact_set_hash_version="v2")).version == "v2"
def test_conflict_and_unknown_fail_closed():
    assert decide_static_version(row(linked_artifact_set_hash="b"*64)).classification == IDENTITY_CONFLICT
    assert decide_static_version(row(apk_set_id=None)).classification == VERSION_UNKNOWN_LEGACY
    assert dynamic_legacy_classification({"artifact_set_hash":"a"*64}) == VERSION_UNKNOWN_LEGACY
def test_summary_separates_safe_conflict_and_unknown():
    got=summarize_static_backfill([row(),row(id=2,linked_artifact_set_hash="b"*64),row(id=3,apk_set_id=None)])
    assert got == {"static_total":3,"static_safe_candidates":1,"static_conflicts":1,"static_insufficient_proof":1}
