from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence import freeze_readiness_audit


def _write_run(root: Path, run_id: str, package_name: str, *, valid: bool = True) -> None:
    run_dir = root / run_id
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    payload = {
        "dynamic_run_id": run_id,
        "target": {
            "package_name": package_name,
            "signer_set_hash": "a" * 64,
        },
        "operator": {
            "capture_policy_version": 1,
            "run_profile": "baseline_connected",
        },
        "dataset": {
            "valid_dataset_run": valid,
            "run_profile": "baseline_connected",
            "window_count": 24,
        },
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


def test_freeze_presence_classification_rejects_run_id_outside_evidence_root(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / "dataset_freeze.json").write_text(
        json.dumps({"included_run_ids": ["../outside-run", None]}),
        encoding="utf-8",
    )
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    result = freeze_readiness_audit._classify_freeze_run_id_presence(
        archive_dir=archive,
        evidence_root=evidence_root,
    )

    assert result["total_run_ids"] == 1
    assert result["missing_run_dirs"] == 1
    assert result["sample_by_reason"]["missing_run_dirs"] == [
        {"run_id": "../outside-run", "reason": "unsafe_run_id"}
    ]


def test_freeze_presence_classification_reports_manifest_run_id_mismatch(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / "dataset_freeze.json").write_text(
        json.dumps({"included_run_ids": ["run-a"]}),
        encoding="utf-8",
    )
    evidence_root = tmp_path / "evidence"
    _write_run(evidence_root, "run-a", "com.example")
    manifest_path = evidence_root / "run-a" / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["dynamic_run_id"] = "run-b"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = freeze_readiness_audit._classify_freeze_run_id_presence(
        archive_dir=archive,
        evidence_root=evidence_root,
    )

    assert result["found_but_identity_mismatch"] == 1
    assert result["sample_by_reason"]["found_but_identity_mismatch"] == [
        {"run_id": "run-a", "reason": "manifest_run_id_mismatch"}
    ]


def test_run_freeze_readiness_audit_scopes_run_counts_to_active_research_cohort(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    out_dir = tmp_path / "audit"
    archive = tmp_path / "data" / "archive"
    archive.mkdir(parents=True, exist_ok=True)

    _write_run(root, "run-beta", "com.example.beta")
    _write_run(root, "run-alpha", "com.example.alpha")

    monkeypatch.setattr(freeze_readiness_audit.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(freeze_readiness_audit.app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        freeze_readiness_audit,
        "active_research_cohort_packages",
        lambda: ("com.example.beta",),
    )
    monkeypatch.setattr(
        freeze_readiness_audit,
        "derive_freeze_eligibility",
        lambda **_kwargs: type(
            "Eligibility",
            (),
            {
                "paper_eligible": True,
                "reason_code": None,
                "all_reason_codes": (),
            },
        )(),
    )

    summary = freeze_readiness_audit.run_freeze_readiness_audit(
        evidence_root=root,
        out_dir=out_dir,
    )

    assert summary.total_runs == 1
    assert summary.valid_runs == 1
    assert summary.paper_eligible_runs == 1
    payload = json.loads(Path(summary.report_path).read_text(encoding="utf-8"))
    assert payload["summary"]["total_runs"] == 1
    assert payload["summary"]["workspace_total_runs"] == 2


def test_run_freeze_readiness_audit_counts_manual_after_baselines_by_time(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "output" / "evidence" / "dynamic"
    out_dir = tmp_path / "audit"
    archive = tmp_path / "data" / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    package = "bbc.mobile.news.ww"

    _write_run(root, "a-manual-1", package)
    _write_run(root, "b-manual-2", package)
    _write_run(root, "c-base-1", package)
    _write_run(root, "d-base-2", package)
    _write_run(root, "e-base-3", package)

    for run_id, profile, ended_at in [
        ("a-manual-1", "interaction_manual", "2026-06-15T19:38:04Z"),
        ("b-manual-2", "interaction_manual", "2026-06-15T19:52:42Z"),
        ("c-base-1", "baseline_idle", "2026-06-15T18:31:28Z"),
        ("d-base-2", "baseline_idle", "2026-06-15T18:39:48Z"),
        ("e-base-3", "baseline_idle", "2026-06-15T18:46:09Z"),
    ]:
        manifest_path = root / run_id / "run_manifest.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["operator"]["run_profile"] = profile
        payload["dataset"]["run_profile"] = None
        payload["ended_at"] = ended_at
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(freeze_readiness_audit.app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(freeze_readiness_audit.app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(freeze_readiness_audit, "active_research_cohort_packages", lambda: (package,))
    monkeypatch.setattr(
        freeze_readiness_audit,
        "derive_freeze_eligibility",
        lambda **_kwargs: type(
            "Eligibility",
            (),
            {
                "paper_eligible": True,
                "reason_code": None,
                "all_reason_codes": (),
            },
        )(),
    )

    summary = freeze_readiness_audit.run_freeze_readiness_audit(
        evidence_root=root,
        out_dir=out_dir,
    )

    assert summary.quota_runs_counted == 5
    assert summary.apps_satisfied == 0
