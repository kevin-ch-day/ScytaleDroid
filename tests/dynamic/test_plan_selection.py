from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis import menu
from scytaledroid.Utils.evidence_store import filesystem_safe_slug


def _write_plan(
    path: Path,
    *,
    package: str,
    run_id: int,
    signature: str,
    version: str = "v1",
    artifact_set_hash: str = "a" * 64,
    base_apk_sha256: str = "b" * 64,
) -> None:
    payload = {
        "package_name": package,
        "static_run_id": run_id,
        "run_identity": {
            "run_signature": signature,
            "run_signature_version": version,
            "artifact_set_hash": artifact_set_hash,
            "base_apk_sha256": base_apk_sha256,
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _setup_plan_dir(tmp_path: Path, package: str) -> Path:
    base_dir = tmp_path / "static_analysis" / "dynamic_plan"
    base_dir.mkdir(parents=True, exist_ok=True)
    slug = filesystem_safe_slug(package)
    return base_dir / f"{slug}-test.json"


def test_resolve_plan_selection_unique_identity(monkeypatch, tmp_path: Path) -> None:
    package = "com.example.app"
    plan_path = _setup_plan_dir(tmp_path, package)
    _write_plan(plan_path, package=package, run_id=42, signature="sig-42")

    monkeypatch.setattr(menu.app_config, "DATA_DIR", str(tmp_path))
    selection = menu._resolve_plan_selection(package)
    assert selection
    assert selection["plan_path"] == str(plan_path)
    assert selection["static_run_id"] == 42


def test_resolve_plan_selection_requires_choice(monkeypatch, tmp_path: Path) -> None:
    package = "com.example.app"
    plan_path_1 = _setup_plan_dir(tmp_path, package)
    plan_path_2 = plan_path_1.with_name(plan_path_1.name.replace("test", "alt"))
    _write_plan(plan_path_1, package=package, run_id=1, signature="sig-1", artifact_set_hash="a" * 64)
    _write_plan(plan_path_2, package=package, run_id=2, signature="sig-2", artifact_set_hash="c" * 64)

    monkeypatch.setattr(menu.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(menu, "_prompt_baseline_selection", lambda *_args, **_kwargs: None)

    selection = menu._resolve_plan_selection(package)
    assert selection is None


def test_resolve_plan_selection_filters_invalid_version(monkeypatch, tmp_path: Path) -> None:
    package = "com.example.app"
    plan_path = _setup_plan_dir(tmp_path, package)
    _write_plan(plan_path, package=package, run_id=7, signature="sig-plan", version="v0")

    monkeypatch.setattr(menu.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(menu, "_prompt_missing_baseline", lambda *_args, **_kwargs: None)
    selection = menu._resolve_plan_selection(package)
    assert selection is None
