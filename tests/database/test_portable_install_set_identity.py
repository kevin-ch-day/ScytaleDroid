"""Portable install-set digest contract tests."""

import json
from hashlib import sha256

from scytaledroid.Utils.install_set_identity import (
    canonical_member_manifest,
    compute_artifact_set_hash,
    hash_v1_ordered_digests,
    portable_set_identity,
)


def _members(split_name="config.en", role="split", extra=None):
    return [
        {"role": "base", "split_name": "base", "sha256": "a" * 64, "apk_set_id": 1204, "path": "/a"},
        {"role": role, "split_name": split_name, "sha256": "b" * 64, "apk_set_id": 1204, "path": "/b", **(extra or {})},
    ]


def test_v1_known_answer_preserves_historical_json_digest():
    assert compute_artifact_set_hash(_members(), version="v1") == "b46097e735d7c16e0156d269733d6178120bdeffa13bc6792c4cbb4b7042198a"


def test_v2_is_order_independent_and_semantically_sensitive():
    members = _members()
    assert compute_artifact_set_hash(members, version="v2") == compute_artifact_set_hash(list(reversed(members)), version="v2")
    sha_changed = _members()
    sha_changed[1]["sha256"] = "c" * 64
    assert compute_artifact_set_hash(members, version="v2") != compute_artifact_set_hash(sha_changed, version="v2")
    assert compute_artifact_set_hash(members, version="v2") != compute_artifact_set_hash(_members("config.fr"), version="v2")
    assert compute_artifact_set_hash(members, version="v2") != compute_artifact_set_hash(_members(role="base"), version="v2")


def test_v2_excludes_local_ids_paths_and_timestamps():
    left = _members(extra={"captured_at": "2026-01-01"})
    right = _members(extra={"captured_at": "2027-01-01"})
    for member in right:
        member["apk_set_id"] = 8888
        member["path"] = "/elsewhere"
    assert compute_artifact_set_hash(left, version="v2") == compute_artifact_set_hash(right, version="v2")
    assert portable_set_identity(artifact_set_hash_version="v2", artifact_set_hash=compute_artifact_set_hash(left, version="v2")) == portable_set_identity(artifact_set_hash_version="v2", artifact_set_hash=compute_artifact_set_hash(right, version="v2"))


def test_canonical_manifest_has_only_portable_member_evidence():
    assert canonical_member_manifest(_members()) == [
        {"role": "base", "split_name": "base", "sha256": "a" * 64},
        {"role": "split", "split_name": "config.en", "sha256": "b" * 64},
    ]


def _hex_digest(index: int) -> str:
    return f"{index:064x}"


def test_v1_ordered_digest_list_stays_byte_compatible_for_large_sets():
    for count in (2, 10, 11, 12, 61):
        digests = [_hex_digest(index) for index in range(count)]
        historical = sha256(json.dumps(digests).encode("utf-8")).hexdigest()
        assert hash_v1_ordered_digests(digests) == historical
        fake_members = [
            {
                "role": "base" if index == 0 else "split",
                "split_name": str(index),
                "sha256": digest,
            }
            for index, digest in enumerate(digests)
        ]
        resorted = compute_artifact_set_hash(fake_members, version="v1")
        if count >= 11:
            assert resorted != historical
        else:
            assert resorted == historical

