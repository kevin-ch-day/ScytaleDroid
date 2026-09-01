from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Publication.paper3_authority import build_paper3_authority_audit


def _write_manifest(root: Path, run_id: str, *, paper_eligible: bool) -> None:
    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {
                    "package_name": "com.example.app",
                    "version_code": "7",
                    "version_name": "7.0",
                    "run_identity": {
                        "static_run_id": "77",
                        "base_apk_sha256": "a" * 64,
                        "identity_valid": True,
                    },
                },
                "operator": {"run_profile": "interaction_manual"},
                "dataset": {
                    "valid_dataset_run": True,
                    "paper_eligible": paper_eligible,
                    "paper_exclusion_primary_reason_code": "EXCLUDED_SCRIPT_ABORT" if not paper_eligible else None,
                    "pcap_available": True,
                },
            }
        ),
        encoding="utf-8",
    )


def test_authority_audit_reports_membership_delta_and_selected_exclusion(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    _write_manifest(evidence_root, "shared", paper_eligible=True)
    _write_manifest(evidence_root, "historic-only", paper_eligible=True)
    _write_manifest(evidence_root, "candidate-excluded", paper_eligible=False)
    alignment = tmp_path / "alignment.json"
    freeze = tmp_path / "freeze.json"
    alignment.write_text(json.dumps({"selected_dynamic_run_ids": ["shared", "historic-only"]}), encoding="utf-8")
    freeze.write_text(
        json.dumps(
            {
                "selection_contract": {"explicit_paper_ineligible_runs": "excluded"},
                "apps": [{"selected_dynamic_run_ids": "shared,candidate-excluded"}],
            }
        ),
        encoding="utf-8",
    )

    report = build_paper3_authority_audit(
        alignment_manifest_path=alignment,
        freeze_manifest_path=freeze,
        evidence_root=evidence_root,
    )

    assert report["summary"] == {
        "historical_selected_runs": 2,
        "candidate_selected_runs": 2,
        "shared_runs": 1,
        "historical_only_runs": 1,
        "candidate_only_runs": 1,
        "historical_explicitly_paper_ineligible_runs": 0,
        "candidate_explicitly_paper_ineligible_runs": 1,
        "candidate_declared_paper_excluded_runs": 0,
    }
    assert report["candidate_explicitly_paper_ineligible"][0]["dynamic_run_id"] == "candidate-excluded"
    memberships = {row["dynamic_run_id"]: row["membership"] for row in report["runs"]}
    assert memberships == {
        "candidate-excluded": "candidate_only",
        "historic-only": "historical_only",
        "shared": "shared",
    }


def test_authority_audit_does_not_read_run_outside_evidence_root(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    alignment = tmp_path / "alignment.json"
    freeze = tmp_path / "freeze.json"
    alignment.write_text(
        json.dumps({"selected_dynamic_run_ids": ["../outside-run"]}),
        encoding="utf-8",
    )
    freeze.write_text(json.dumps({"apps": []}), encoding="utf-8")

    report = build_paper3_authority_audit(
        alignment_manifest_path=alignment,
        freeze_manifest_path=freeze,
        evidence_root=evidence_root,
    )

    assert report["runs"][0]["artifact_status"] == "unsafe_run_id"
