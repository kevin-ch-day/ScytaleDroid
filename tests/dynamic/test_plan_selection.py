from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.DynamicAnalysis import menu
from scytaledroid.Utils.evidence_store import filesystem_safe_slug


def _write_plan(path: Path, *, package: str, run_id: int, signature: str, version: str = "v1") -> None:
    payload = {
        "package_name": package,
        "static_run_id": run_id,
        "run_identity": {
            "run_signature": signature,
            "run_signature_version": version,
            "artifact_set_hash": "a" * 64,
            "base_apk_sha256": "b" * 64,
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _setup_plan_dir(tmp_path: Path, package: str) -> Path:
    base_dir = tmp_path / "static_analysis" / "dynamic_plan"
    base_dir.mkdir(parents=True, exist_ok=True)
    slug = filesystem_safe_slug(package)
    return base_dir / f"{slug}-test.json"


def test_resolve_plan_path_unique_static_run(monkeypatch, tmp_path: Path) -> None:
    package = "com.example.app"
    plan_path = _setup_plan_dir(tmp_path, package)
    _write_plan(plan_path, package=package, run_id=42, signature="sig-42")

    monkeypatch.setattr(menu.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(menu, "_fetch_static_run_row", lambda _: {
        "run_signature": "sig-42",
        "run_signature_version": "v1",
    })
    monkeypatch.setattr(menu, "_prompt_legacy_plan_selection", lambda: False)

    resolved, note = menu._resolve_plan_path(package, None)
    assert resolved == str(plan_path)
    assert note is None


def test_resolve_plan_path_requires_static_run_id(monkeypatch, tmp_path: Path) -> None:
    package = "com.example.app"
    plan_path_1 = _setup_plan_dir(tmp_path, package)
    plan_path_2 = plan_path_1.with_name(plan_path_1.name.replace("test", "alt"))
    _write_plan(plan_path_1, package=package, run_id=1, signature="sig-1")
    _write_plan(plan_path_2, package=package, run_id=2, signature="sig-2")

    monkeypatch.setattr(menu.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(menu, "_prompt_legacy_plan_selection", lambda: False)

    resolved, note = menu._resolve_plan_path(package, None)
    assert resolved is None
    assert "Multiple static_run_id" in (note or "")


def test_resolve_plan_path_no_matching_signature(monkeypatch, tmp_path: Path) -> None:
    package = "com.example.app"
    plan_path = _setup_plan_dir(tmp_path, package)
    _write_plan(plan_path, package=package, run_id=7, signature="sig-plan")

    monkeypatch.setattr(menu.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(menu, "_fetch_static_run_row", lambda _: {
        "run_signature": "sig-db",
        "run_signature_version": "v1",
    })
    monkeypatch.setattr(menu, "_prompt_legacy_plan_selection", lambda: False)

    resolved, note = menu._resolve_plan_path(package, 7)
    assert resolved is None
    assert "No plan matches" in (note or "")
