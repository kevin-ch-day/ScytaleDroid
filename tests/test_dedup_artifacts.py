from __future__ import annotations

import os
import time
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.execution.scan_flow import _dedupe_artifacts


class StubArtifact:
    def __init__(self, path: Path, label: str, sha: str):
        self.path = path
        self.artifact_label = label
        self.display_path = path.name
        self.sha256 = sha
        self.metadata = {}
        self.split_group_id = None
        self.apk_id = None


def test_dedup_artifacts_prefers_latest_mtime(tmp_path):
    shared_sha = "cafebabe"
    old_path = tmp_path / "base_old.apk"
    new_path = tmp_path / "base_new.apk"
    old_path.write_bytes(b"old")
    new_path.write_bytes(b"new")

    old_artifact = StubArtifact(old_path, "base", shared_sha)
    new_artifact = StubArtifact(new_path, "base", shared_sha)

    time.sleep(0.01)
    os.utime(new_path, (new_path.stat().st_atime, new_path.stat().st_mtime + 10))

    deduped = _dedupe_artifacts([old_artifact, new_artifact])
    assert len(deduped) == 1
    assert deduped[0].path == new_path


def test_dedup_artifacts_keeps_distinct_splits(tmp_path):
    shared_sha = "feedface"
    split_a = tmp_path / "split_a.apk"
    split_b = tmp_path / "split_b.apk"
    split_a.write_bytes(b"a")
    split_b.write_bytes(b"b")

    art_a = StubArtifact(split_a, "split_config.en", shared_sha)
    art_b = StubArtifact(split_b, "split_config.xhdpi", shared_sha)

    deduped = _dedupe_artifacts([art_a, art_b])
    assert len(deduped) == 2
    assert {artifact.artifact_label for artifact in deduped} == {"split_config.en", "split_config.xhdpi"}
