from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.execution import scan_flow
from scytaledroid.StaticAnalysis.cli.execution.scan_identity_helpers import (
    _split_name_for_artifact_with_reason,
)


class FakeArtifact:
    def __init__(self, path: Path, sha: str, split_name: str | None, *, is_split_member: bool = True):
        self.sha256 = sha
        self.metadata = {"split_name": split_name} if split_name is not None else {}
        self.path = path
        self.is_split_member = is_split_member


class FakeGroup:
    def __init__(self, base_artifact, artifacts):
        self.base_artifact = base_artifact
        self.artifacts = artifacts
        self.package_name = "com.example.app"


def _artifact(tmp_path: Path, name: str, split_name: str | None, *, is_split_member: bool = True) -> FakeArtifact:
    path = tmp_path / f"{name}.apk"
    path.write_bytes(name.encode("utf-8"))
    digest = sha256(path.read_bytes()).hexdigest()
    return FakeArtifact(path, digest, split_name, is_split_member=is_split_member)


def test_compute_run_identity_orders_splits_by_name(tmp_path: Path):
    base = _artifact(tmp_path, "base", "base", is_split_member=False)
    a = _artifact(tmp_path, "aaa", "split_config.en")
    b = _artifact(tmp_path, "bbb", "split_config.arm64_v8a")
    c = _artifact(tmp_path, "ccc", "split_df_vmsdk")
    group = FakeGroup(base, [c, b, a, base])
    identity = scan_flow._compute_run_identity(group)

    hashes = [base.sha256, b.sha256, a.sha256, c.sha256]
    expected_hash = sha256(json.dumps(hashes).encode("utf-8")).hexdigest()

    assert identity["identity_valid"] is True
    assert identity["base_apk_sha256"] == base.sha256
    assert identity["artifact_set_hash"] == expected_hash


def test_compute_run_identity_missing_base():
    group = FakeGroup(None, [])
    identity = scan_flow._compute_run_identity(group)
    assert identity["identity_valid"] is False
    assert identity["identity_error_reason"] == "missing_base_artifact"


def test_split_name_resolution_reports_missing_name_without_path():
    artifact = FakeArtifact.__new__(FakeArtifact)
    artifact.metadata = {}
    artifact.path = None

    split_name, reason = _split_name_for_artifact_with_reason(artifact)

    assert split_name is None
    assert "missing_split_name" in str(reason)


def test_compute_run_identity_rejects_declared_hash_mismatch(tmp_path: Path):
    base = _artifact(tmp_path, "base", "base", is_split_member=False)
    base.sha256 = "0" * 64

    identity = scan_flow._compute_run_identity(FakeGroup(base, [base]))

    assert identity["identity_valid"] is False
    assert "sha256_mismatch" in str(identity["identity_error_reason"])


def test_compute_run_identity_rejects_multiple_base_artifacts(tmp_path: Path):
    base_a = _artifact(tmp_path, "base-a", "base", is_split_member=False)
    base_b = _artifact(tmp_path, "base-b", "base-copy", is_split_member=False)

    identity = scan_flow._compute_run_identity(FakeGroup(base_a, [base_a, base_b]))

    assert identity["identity_valid"] is False
    assert identity["identity_error_reason"] == "multiple_base_artifacts:2"


def test_compute_config_hash_changes_when_split_scan_changes() -> None:
    params_on = RunParameters(profile="full", scope="app", scope_label="Example", scan_splits=True)
    params_off = RunParameters(profile="full", scope="app", scope_label="Example", scan_splits=False)

    assert scan_flow._compute_config_hash(params_on) != scan_flow._compute_config_hash(params_off)
