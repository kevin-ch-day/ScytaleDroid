from pathlib import Path

from scytaledroid.DynamicAnalysis.analysis.privacy_manifest import (
    validate_privacy_manifest,
    write_privacy_manifest,
)


def test_privacy_manifest_roundtrip(tmp_path: Path):
    path = write_privacy_manifest(tmp_path)
    assert validate_privacy_manifest(path) is True
