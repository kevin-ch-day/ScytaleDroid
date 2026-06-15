from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis import menu


class _Cfg:
    baseline_required = 3
    interactive_required = 2


def _write_manifest(
    root: Path,
    run_id: str,
    package_name: str,
    *,
    run_profile: str,
    ended_at: str,
) -> None:
    run_dir = root / run_id
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    payload = {
        "dynamic_run_id": run_id,
        "target": {"package_name": package_name, "signer_set_hash": "a" * 64},
        "operator": {"capture_policy_version": 1, "run_profile": run_profile},
        "dataset": {
            "valid_dataset_run": True,
            "paper_eligible": True,
            "run_profile": None,
            "window_count": 24,
            "low_signal": False,
        },
        "ended_at": ended_at,
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    plan = {
        "package_name": package_name,
        "run_identity": {
            "run_signature": "r" * 64,
            "run_signature_version": "v1",
            "artifact_set_hash": "b" * 64,
            "base_apk_sha256": "c" * 64,
            "static_handoff_hash": "d" * 64,
            "signer_set_hash": "a" * 64,
            "identity_valid": True,
        },
    }
    (run_dir / "inputs" / "static_dynamic_plan.json").write_text(json.dumps(plan), encoding="utf-8")


def test_summarize_evidence_quota_counts_manual_after_baselines_by_time(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    package = "bbc.mobile.news.ww"

    _write_manifest(root, "a-manual-1", package, run_profile="interaction_manual", ended_at="2026-06-15T19:38:04Z")
    _write_manifest(root, "b-manual-2", package, run_profile="interaction_manual", ended_at="2026-06-15T19:52:42Z")
    _write_manifest(root, "c-base-1", package, run_profile="baseline_idle", ended_at="2026-06-15T18:31:28Z")
    _write_manifest(root, "d-base-2", package, run_profile="baseline_idle", ended_at="2026-06-15T18:39:48Z")
    _write_manifest(root, "e-base-3", package, run_profile="baseline_idle", ended_at="2026-06-15T18:46:09Z")

    monkeypatch.setattr(menu.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(
        menu,
        "derive_freeze_eligibility",
        lambda **_kwargs: type(
            "Eligibility",
            (),
            {"paper_eligible": True, "reason_code": None, "all_reason_codes": ()},
        )(),
    )

    out = menu._summarize_evidence_quota({package}, _Cfg())

    assert out["quota_runs_counted"] == 5
    assert out["apps_satisfied"] == 1
    assert out["extra_eligible_runs"] == 0
