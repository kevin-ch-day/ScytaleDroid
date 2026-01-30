from __future__ import annotations

import json
from hashlib import sha256

from scytaledroid.StaticAnalysis.cli.execution import scan_flow


class FakeArtifact:
    def __init__(self, sha: str, split_name: str | None, *, is_split_member: bool = True):
        self.sha256 = sha
        self.metadata = {"split_name": split_name} if split_name is not None else {}
        self.path = None
        self.is_split_member = is_split_member


class FakeGroup:
    def __init__(self, base_artifact, artifacts):
        self.base_artifact = base_artifact
        self.artifacts = artifacts
        self.package_name = "com.example.app"


def test_compute_run_identity_orders_splits_by_name():
    base = FakeArtifact("base", "base")
    a = FakeArtifact("aaa", "split_config.en")
    b = FakeArtifact("bbb", "split_config.arm64_v8a")
    c = FakeArtifact("ccc", "split_df_vmsdk")
    group = FakeGroup(base, [c, b, a, base])
    identity = scan_flow._compute_run_identity(group)

    hashes = ["base", "bbb", "aaa", "ccc"]
    expected_hash = sha256(json.dumps(hashes).encode("utf-8")).hexdigest()

    assert identity["identity_valid"] is True
    assert identity["base_apk_sha256"] == "base"
    assert identity["artifact_set_hash"] == expected_hash


def test_compute_run_identity_missing_base():
    group = FakeGroup(None, [])
    identity = scan_flow._compute_run_identity(group)
    assert identity["identity_valid"] is False
    assert identity["identity_error_reason"] == "missing_base_artifact"


def test_compute_run_identity_missing_split_name():
    base = FakeArtifact("base", None)
    group = FakeGroup(base, [base])
    identity = scan_flow._compute_run_identity(group)
    assert identity["identity_valid"] is False
    assert identity["identity_error_reason"] == "split_name_missing"
