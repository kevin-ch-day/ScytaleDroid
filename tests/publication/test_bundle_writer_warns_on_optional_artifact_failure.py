from __future__ import annotations

from pathlib import Path

import pytest

from scytaledroid.Publication.canonical_bundle_writer import write_canonical_publication_directory


def test_bundle_writer_warns_on_optional_snapshot_tex_failure(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # Minimal baseline bundle root (not used by this optional snapshot branch).
    baseline_root = tmp_path / "baseline"
    baseline_root.mkdir(parents=True, exist_ok=True)
    (baseline_root / "manifest").mkdir(parents=True, exist_ok=True)
    # Required for snapshot provenance copy stage.
    (baseline_root / "manifest" / "phase_e_artifacts_manifest.json").write_text("{}", encoding="utf-8")

    # Snapshot dir exists but does not contain tables/risk_summary_per_group.csv, so the optional
    # TeX render should fail and emit a warning (not silently swallow).
    snapshot_dir = tmp_path / "snapshot"
    (snapshot_dir / "tables").mkdir(parents=True, exist_ok=True)
    (snapshot_dir / "manifest").mkdir(parents=True, exist_ok=True)
    # Required snapshot manifest placeholders for the copy stage.
    for name in ("selection_manifest.json", "freeze_manifest.json", "model_registry.json"):
        (snapshot_dir / "manifest" / name).write_text("{}", encoding="utf-8")

    caplog.clear()
    res = write_canonical_publication_directory(
        baseline_bundle_root=baseline_root,
        snapshot_dir=snapshot_dir,
        snapshot_id="snap1",
        overwrite=True,
    )
    assert res.ok is True
    assert any("Optional snapshot provenance TeX render skipped" in r.getMessage() for r in caplog.records)
