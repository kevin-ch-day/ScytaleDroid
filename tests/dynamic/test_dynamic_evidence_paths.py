from __future__ import annotations

import os
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    dynamic_evidence_root,
    ensure_legacy_dynamic_symlink,
    iter_dynamic_run_dirs,
    legacy_dynamic_evidence_root,
    resolve_dynamic_run_dir,
    resolve_evidence_path,
)

RUN_ID = "4d3def16-83a9-43f6-8dad-0d1dd295d795"


def test_dynamic_evidence_root_defaults_to_data(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(tmp_path / "data" / "evidence" / "dynamic"))

    assert dynamic_evidence_root() == tmp_path / "data" / "evidence" / "dynamic"


def test_resolve_evidence_path_prefers_canonical_over_legacy(monkeypatch, tmp_path: Path) -> None:
    canonical_root = tmp_path / "data" / "evidence" / "dynamic"
    legacy_root = tmp_path / "output" / "evidence" / "dynamic"
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(canonical_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    canonical = canonical_root / RUN_ID
    legacy = legacy_root / RUN_ID
    canonical.mkdir(parents=True)
    legacy.mkdir(parents=True)

    assert resolve_evidence_path(f"output/evidence/dynamic/{RUN_ID}") == canonical
    assert resolve_dynamic_run_dir(RUN_ID) == canonical


def test_resolve_evidence_path_falls_back_to_legacy(monkeypatch, tmp_path: Path) -> None:
    canonical_root = tmp_path / "data" / "evidence" / "dynamic"
    legacy_root = tmp_path / "output" / "evidence" / "dynamic"
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(canonical_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    legacy = legacy_root / RUN_ID
    legacy.mkdir(parents=True)

    assert legacy_dynamic_evidence_root() == legacy_root
    assert resolve_evidence_path(f"output/evidence/dynamic/{RUN_ID}") == legacy
    assert resolve_dynamic_run_dir(RUN_ID) == legacy


def test_iter_dynamic_run_dirs_dedupes_by_run_id(monkeypatch, tmp_path: Path) -> None:
    canonical_root = tmp_path / "data" / "evidence" / "dynamic"
    legacy_root = tmp_path / "output" / "evidence" / "dynamic"
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(canonical_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    (canonical_root / RUN_ID).mkdir(parents=True)
    (legacy_root / RUN_ID).mkdir(parents=True)
    (legacy_root / "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa").mkdir(parents=True)

    assert iter_dynamic_run_dirs() == (
        canonical_root / RUN_ID,
        legacy_root / "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    )


def test_ensure_legacy_dynamic_symlink_for_canonical_run(monkeypatch, tmp_path: Path) -> None:
    canonical_root = tmp_path / "data" / "evidence" / "dynamic"
    legacy_root = tmp_path / "output" / "evidence" / "dynamic"
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", str(canonical_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    run_dir = canonical_root / RUN_ID
    run_dir.mkdir(parents=True)

    link = ensure_legacy_dynamic_symlink(run_dir)

    assert link == legacy_root / RUN_ID
    assert link.is_symlink()
    assert link.resolve() == run_dir
    assert not Path(os.readlink(link)).is_absolute()
