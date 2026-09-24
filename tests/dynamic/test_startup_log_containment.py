"""Startup directories and event logs cannot write through escaping symlinks."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger, append_run_event
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter


@pytest.mark.parametrize("directory", ["notes", "artifacts", "analysis"])
def test_layout_rejects_symlink_outside_root(tmp_path, directory):
    root = tmp_path / "run"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / directory).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        EvidencePackWriter(root).ensure_layout()
    assert list(outside.iterdir()) == []


def test_event_log_does_not_write_outside_pack(tmp_path):
    root = tmp_path / "run"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "notes").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        RunEventLogger(SimpleNamespace(run_dir=root))
    append_run_event(root, "startup", {"safe": True})
    assert list(outside.iterdir()) == []


def test_relative_event_log_manifest_path_is_stable(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    logger = RunEventLogger(SimpleNamespace(run_dir=Path("run")))
    logger.log("startup", {})
    assert logger.finalize().relative_path == "notes/run_events.jsonl"
