from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence import state_summary


def _write_plan(path: Path, package_name: str, *, valid: bool = True) -> None:
    payload = {
        "package_name": package_name,
        "generated_at": "2026-05-14T18:00:00Z",
        "static_run_id": 123,
        "apk_set_id": 55,
        "run_identity": {
            "base_apk_sha256": "b" * 64,
            "artifact_set_hash": "a" * 64,
            "run_signature": "c" * 64,
            "run_signature_version": "v1",
            "static_handoff_hash": "d" * 64,
            "identity_valid": valid,
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_static_handoff_plan_summary_reports_dataset_readiness(monkeypatch, tmp_path: Path) -> None:
    plan_dir = tmp_path / "static_analysis" / "dynamic_plan"
    plan_dir.mkdir(parents=True)
    _write_plan(plan_dir / "com.example.one-plan.json", "com.example.one")
    _write_plan(plan_dir / "com.example.two-plan.json", "com.example.two")
    _write_plan(plan_dir / "com.example.outside-plan.json", "com.example.outside")
    _write_plan(plan_dir / "com.example.bad-plan.json", "com.example.bad", valid=False)

    monkeypatch.setattr(state_summary.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_summary, "load_dataset_packages", lambda: ["com.example.one", "com.example.two"])

    out = state_summary.build_static_handoff_plan_summary()

    assert out["dynamic_plan_files"] == 4
    assert out["valid_plan_files"] == 3
    assert out["invalid_plan_files"] == 1
    assert out["dataset_packages_total"] == 2
    assert out["dataset_packages_with_plan"] == 2
    assert out["dataset_packages_missing_plan"] == 0
    assert out["ready_for_guided_dataset_run"] is True


def test_static_handoff_plan_summary_lists_missing_dataset_plans(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "static_analysis" / "dynamic_plan").mkdir(parents=True)

    monkeypatch.setattr(state_summary.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(state_summary, "load_dataset_packages", lambda: ["com.example.missing"])

    out = state_summary.build_static_handoff_plan_summary()

    assert out["dataset_packages_with_plan"] == 0
    assert out["dataset_packages_missing_plan"] == 1
    assert out["missing_packages"] == ["com.example.missing"]
    assert out["ready_for_guided_dataset_run"] is False
