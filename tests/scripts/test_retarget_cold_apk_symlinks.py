"""Contract tests for the dry-run-first cold APK symlink migration helper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "device_analysis" / "retarget_cold_apk_symlinks.py"
    spec = importlib.util.spec_from_file_location("retarget_cold_apk_symlinks", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_retarget_cold_apk_symlinks_is_dry_run_then_applies_verified_target(tmp_path: Path) -> None:
    tool = _module()
    canonical = tmp_path / "data" / "store" / "apk" / "sha256"
    old_root = tmp_path / "old-cold"
    new_root = tmp_path / "new-cold"
    digest = "a" * 64
    old_target = old_root / "sha256" / digest[:2] / f"{digest}.apk"
    new_target = new_root / "sha256" / digest[:2] / f"{digest}.apk"
    old_target.parent.mkdir(parents=True)
    new_target.parent.mkdir(parents=True)
    old_target.write_bytes(b"old")
    new_target.write_bytes(b"new")
    link = canonical / digest[:2] / f"{digest}.apk"
    link.parent.mkdir(parents=True)
    link.symlink_to(old_target)

    planned = tool.plan_retarget(canonical_root=canonical, old_root=old_root, new_root=new_root)
    applied = tool.plan_retarget(canonical_root=canonical, old_root=old_root, new_root=new_root, apply=True)

    assert [(action.action, action.detail) for action in planned] == [("retarget", str(new_target))]
    assert [(action.action, action.detail) for action in applied] == [("retarget", str(new_target))]
    assert link.resolve() == new_target


def test_retarget_cold_apk_symlinks_refuses_missing_mapped_target(tmp_path: Path) -> None:
    tool = _module()
    canonical = tmp_path / "canonical"
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    target = old_root / "blob.apk"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"old")
    link = canonical / "blob.apk"
    link.parent.mkdir()
    link.symlink_to(target)

    actions = tool.plan_retarget(canonical_root=canonical, old_root=old_root, new_root=new_root, apply=True)

    assert [(action.action, action.detail) for action in actions] == [
        ("blocked", f"mapped target unavailable: {new_root / 'blob.apk'}"),
    ]
    assert link.resolve() == target
