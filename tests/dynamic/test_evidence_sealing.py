from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest


def test_sealed_manifest_cannot_be_rewritten(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-08-13T00:00:00Z",
        status="success",
    )
    manifest.finalize()
    path = writer.write_manifest(manifest)
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(RuntimeError, match="sealed manifest"):
        writer.write_manifest(manifest)

    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert path.read_bytes().endswith(b"\n")
    assert not list(tmp_path.glob(".run_manifest.json.tmp.*"))


def test_manifest_seal_does_not_clobber_concurrent_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-race",
        created_at="2026-08-16T00:00:00Z",
        status="success",
    )
    winner = b'{"dynamic_run_id":"winner"}\n'
    real_link = os.link

    def _publish_winner_then_link(source: Path, destination: Path) -> None:
        Path(destination).write_bytes(winner)
        real_link(source, destination)

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.core.evidence_pack.os.link",
        _publish_winner_then_link,
    )

    with pytest.raises(RuntimeError, match="sealed manifest"):
        writer.write_manifest(manifest)

    assert (tmp_path / "run_manifest.json").read_bytes() == winner
    assert not list(tmp_path.glob(".run_manifest.json.tmp.*"))


def test_manifest_seal_success_is_not_masked_by_temp_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-cleanup",
        created_at="2026-08-16T00:00:00Z",
        status="success",
    )
    real_unlink = Path.unlink

    def _fail_temp_cleanup(path: Path, *args, **kwargs) -> None:
        if path.name.startswith(".run_manifest.json.tmp."):
            raise PermissionError("simulated cleanup failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", _fail_temp_cleanup)

    sealed = writer.write_manifest(manifest)

    assert sealed == tmp_path / "run_manifest.json"
    assert sealed.exists()


@pytest.mark.parametrize("relative_path", ["../outside.json", "/tmp/outside.json", "."])
def test_evidence_writer_rejects_paths_outside_run(
    tmp_path: Path,
    relative_path: str,
) -> None:
    run_dir = tmp_path / "run"
    writer = EvidencePackWriter(run_dir)
    writer.ensure_layout()

    with pytest.raises(ValueError, match="must remain inside run directory"):
        writer.write_json(relative_path, {"unsafe": True})

    assert not (tmp_path / "outside.json").exists()


def test_evidence_writer_uses_complete_newline_terminated_json(tmp_path: Path) -> None:
    writer = EvidencePackWriter(tmp_path)
    writer.ensure_layout()

    path = writer.write_json("analysis/result.json", {"status": "complete"})

    assert path.read_text(encoding="utf-8") == '{\n  "status": "complete"\n}\n'
    assert not list(path.parent.glob(f".{path.name}.tmp.*"))
