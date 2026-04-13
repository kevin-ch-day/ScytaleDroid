import hashlib
import json

from scytaledroid.DynamicAnalysis.core.freeze_identity import (
    compute_freeze_dataset_hash_from_payload,
    derive_freeze_dataset_identity,
)


def _sha(x: str) -> str:
    return hashlib.sha256(x.encode("utf-8")).hexdigest()


def test_freeze_dataset_hash_is_order_invariant_for_run_ids_and_keys():
    base = {
        "dataset_id": "Research Dataset Alpha",
        "dataset_version": "paper2_v1",
        "freeze_contract_version": 1,
        "paper_contract_version": 1,
        "paper_mode_contract_version": "v1",
        "paper_contract_hash": _sha("contract"),
        "capture_policy_version_required": 1,
        "reason_taxonomy_version": 1,
        "plan_schema_version_required": "0.2.6",
        "plan_paper_contract_version_required": 1,
        "quota_policy": {"baseline_required": 1, "interactive_required": 2},
        "qa_thresholds": {"min_pcap_bytes": 50000, "min_windows_baseline": 30},
        "included_run_ids": ["b", "a"],
        "included_run_checksums": {
            "a": {"files_sha256": {"run_manifest.json": _sha("a")}},
            "b": {"files_sha256": {"run_manifest.json": _sha("b")}},
        },
        # Volatile fields that must not influence identity:
        "created_at_utc": "2026-02-23T00:00:00Z",
        "tool_git_commit": "deadbeef",
    }
    h1 = compute_freeze_dataset_hash_from_payload(dict(base))

    # Reorder run ids and inject additional volatile metadata.
    variant = json.loads(json.dumps(base))
    variant["included_run_ids"] = ["a", "b"]
    variant["created_at_utc"] = "2099-01-01T00:00:00Z"
    variant["tool_git_commit"] = "cafebabe"
    # Reorder checksum dict keys by recreating it.
    variant["included_run_checksums"] = {
        "b": base["included_run_checksums"]["b"],
        "a": base["included_run_checksums"]["a"],
    }
    h2 = compute_freeze_dataset_hash_from_payload(variant)
    assert h1 == h2


def test_derive_freeze_dataset_identity_includes_canonical_payload_keys():
    freeze = {
        "included_run_ids": ["x"],
        "included_run_checksums": {"x": {"files_sha256": {"run_manifest.json": _sha("x")}}},
    }
    ident = derive_freeze_dataset_identity(freeze)
    assert isinstance(ident.hash, str) and len(ident.hash) == 64
    assert "included_run_ids" in ident.canonical_payload
    assert "included_run_checksums" in ident.canonical_payload
