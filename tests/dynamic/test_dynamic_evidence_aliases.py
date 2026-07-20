"""Regression coverage for portable dynamic-evidence compatibility aliases."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.utils.path_utils import (
    inspect_legacy_dynamic_aliases,
    rebuild_legacy_dynamic_aliases,
)


def _run(root: Path, run_id: str) -> Path:
    path = root / run_id
    path.mkdir(parents=True)
    return path


def test_alias_rebuild_repairs_only_canonical_run_aliases(tmp_path: Path) -> None:
    canonical = tmp_path / "data" / "evidence" / "dynamic"
    legacy = tmp_path / "output" / "evidence" / "dynamic"
    run_one = _run(canonical, "run-one")
    _run(canonical, "run-two")
    legacy.mkdir(parents=True)
    (legacy / "run-one").symlink_to(run_one, target_is_directory=True)
    (legacy / "run-two").symlink_to(tmp_path / "old-host" / "run-two", target_is_directory=True)
    (legacy / "orphan").symlink_to(tmp_path / "old-host" / "orphan", target_is_directory=True)

    before = inspect_legacy_dynamic_aliases(canonical_root=canonical, legacy_root=legacy)
    planned = rebuild_legacy_dynamic_aliases(canonical_root=canonical, legacy_root=legacy)

    assert before.canonical_runs == 2
    assert before.valid == 1
    assert before.stale == 1
    assert before.orphaned == 1
    assert [(repair.run_id, repair.action) for repair in planned] == [("run-two", "replace-stale")]
    assert not (legacy / "run-two").exists()

    applied = rebuild_legacy_dynamic_aliases(canonical_root=canonical, legacy_root=legacy, apply=True)
    after = inspect_legacy_dynamic_aliases(canonical_root=canonical, legacy_root=legacy)

    assert [(repair.run_id, repair.action) for repair in applied] == [("run-two", "replace-stale")]
    assert after.valid == 2
    assert after.orphaned == 1
    assert (legacy / "orphan").is_symlink()


def test_alias_rebuild_preserves_non_symlink_conflicts(tmp_path: Path) -> None:
    canonical = tmp_path / "canonical"
    legacy = tmp_path / "legacy"
    _run(canonical, "run-one")
    legacy.mkdir()
    (legacy / "run-one").mkdir()

    repairs = rebuild_legacy_dynamic_aliases(canonical_root=canonical, legacy_root=legacy, apply=True)
    summary = inspect_legacy_dynamic_aliases(canonical_root=canonical, legacy_root=legacy)

    assert [(repair.run_id, repair.action) for repair in repairs] == [("run-one", "conflict")]
    assert summary.conflicts == 1
    assert (legacy / "run-one").is_dir()


def test_alias_rebuild_prunes_only_orphaned_symlinks_when_explicit(tmp_path: Path) -> None:
    canonical = tmp_path / "canonical"
    legacy = tmp_path / "legacy"
    _run(canonical, "run-one")
    legacy.mkdir()
    orphan = legacy / "orphan"
    orphan.symlink_to(tmp_path / "old-host" / "orphan", target_is_directory=True)
    conflict = legacy / "not-a-run"
    conflict.mkdir()

    planned = rebuild_legacy_dynamic_aliases(
        canonical_root=canonical,
        legacy_root=legacy,
        prune_orphans=True,
    )
    applied = rebuild_legacy_dynamic_aliases(
        canonical_root=canonical,
        legacy_root=legacy,
        apply=True,
        prune_orphans=True,
    )

    assert [(repair.run_id, repair.action) for repair in planned] == [
        ("run-one", "create"),
        ("orphan", "remove-orphan"),
    ]
    assert [(repair.run_id, repair.action) for repair in applied] == [
        ("run-one", "create"),
        ("orphan", "remove-orphan"),
    ]
    assert not orphan.exists()
    assert not orphan.is_symlink()
    assert conflict.is_dir()
