from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.utils import run_cleanup


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_find_incomplete_dynamic_run_dirs(monkeypatch, tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(run_cleanup.app_config, "OUTPUT_DIR", str(output_root))
    root = output_root / "evidence" / "dynamic"
    complete = root / "run-complete"
    incomplete = root / "run-incomplete"
    _write_json(complete / "run_manifest.json", {"dynamic_run_id": "run-complete"})
    incomplete.mkdir(parents=True, exist_ok=True)

    found = run_cleanup.find_incomplete_dynamic_run_dirs()
    assert [p.name for p in found] == ["run-incomplete"]


def test_prune_incomplete_dynamic_run_dirs(monkeypatch, tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    monkeypatch.setattr(run_cleanup.app_config, "OUTPUT_DIR", str(output_root))
    root = output_root / "evidence" / "dynamic"
    complete = root / "run-complete"
    incomplete_a = root / "run-incomplete-a"
    incomplete_b = root / "run-incomplete-b"
    _write_json(complete / "run_manifest.json", {"dynamic_run_id": "run-complete"})
    incomplete_a.mkdir(parents=True, exist_ok=True)
    incomplete_b.mkdir(parents=True, exist_ok=True)

    deleted = run_cleanup.prune_incomplete_dynamic_run_dirs()
    assert deleted == 2
    assert complete.exists()
    assert not incomplete_a.exists()
    assert not incomplete_b.exists()
