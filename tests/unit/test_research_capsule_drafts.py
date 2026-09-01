from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Publication.research_capsule import sha256_file
from scytaledroid.Publication.research_capsule_drafts import (
    build_paper_freeze_ledger_drafts,
    split_run_ids,
)


def test_split_run_ids_handles_freeze_csv_and_sequences() -> None:
    assert split_run_ids("run-a, run-b,,") == ["run-a", "run-b"]
    assert split_run_ids(["run-a", " run-b "]) == ["run-a", "run-b"]


def test_drafts_follow_explicit_selected_run_ids_without_scanning(tmp_path: Path) -> None:
    run_id = "run-selected"
    run_dir = tmp_path / "evidence" / run_id
    (run_dir / "artifacts/pcapdroid_capture").mkdir(parents=True)
    (run_dir / "analysis").mkdir()
    (run_dir / "inputs").mkdir()
    (run_dir / "notes").mkdir()
    pcap = run_dir / "artifacts/pcapdroid_capture/capture.pcap"
    pcap.write_bytes(b"pcap")
    for relative_path in ("analysis/pcap_features.json", "analysis/pcap_report.json", "analysis/summary.json", "inputs/static_dynamic_plan.json", "notes/run_events.jsonl"):
        (run_dir / relative_path).write_text("{}", encoding="utf-8")
    manifest = {
        "target": {
            "package_name": "com.example.app",
            "version_code": "7",
            "version_name": "7.0",
            "static_run_id": 77,
            "apk_paths": ["/data/app/base.apk"],
            "run_identity": {"base_apk_sha256": "a" * 64},
        },
        "dataset": {"paper_eligible": True, "valid_dataset_run": True},
        "scenario": {"id": "basic_usage", "started_at": "2026-07-19T00:00:00Z"},
        "operator": {"run_profile": "interaction_manual"},
        "artifacts": [{"type": "pcapdroid_capture", "relative_path": "artifacts/pcapdroid_capture/capture.pcap", "sha256": sha256_file(pcap)}],
        "outputs": [
            {"type": "pcap_features", "relative_path": "analysis/pcap_features.json", "sha256": sha256_file(run_dir / "analysis/pcap_features.json")},
            {"type": "pcap_report", "relative_path": "analysis/pcap_report.json", "sha256": sha256_file(run_dir / "analysis/pcap_report.json")},
            {"type": "analysis_summary_json", "relative_path": "analysis/summary.json", "sha256": sha256_file(run_dir / "analysis/summary.json")},
        ],
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    freeze = {"paper_id": "paper3", "apps": [{"app": "Example", "package_name": "com.example.app", "selected_relation": "current", "selected_dynamic_run_ids": run_id}]}

    apk_ledger, evidence_ledger = build_paper_freeze_ledger_drafts(
        freeze_manifest=freeze,
        repo_root=tmp_path,
        evidence_root=tmp_path / "evidence",
        display_name_by_package={"com.example.app": "Example App"},
    )

    assert apk_ledger["review_status"] == "DRAFT_UNREVIEWED"
    assert apk_ledger["entries"][0]["app_name"] == "Example App"
    assert apk_ledger["entries"][0]["selected_apk_path"] == ""
    assert evidence_ledger["entries"][0]["dynamic_run_id"] == run_id
    assert evidence_ledger["entries"][0]["run_profile"] == "interaction_manual"
    assert evidence_ledger["entries"][0]["pcap"]["sha256"] == sha256_file(pcap)


def test_drafts_can_use_a_submission_identifier_without_relabeling_evidence(tmp_path: Path) -> None:
    apk_ledger, evidence_ledger = build_paper_freeze_ledger_drafts(
        freeze_manifest={"paper_id": "paper3", "apps": []},
        repo_root=tmp_path,
        evidence_root=tmp_path / "evidence",
        paper_id="IEEE-CARS-2026",
    )

    assert apk_ledger["paper_id"] == "IEEE-CARS-2026"
    assert evidence_ledger["paper_id"] == "IEEE-CARS-2026"


def test_drafts_preserve_but_do_not_include_explicitly_paper_ineligible_run(tmp_path: Path) -> None:
    run_id = "run-explicitly-excluded"
    run_dir = tmp_path / "evidence" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {
                    "package_name": "com.example.app",
                    "version_code": "7",
                    "run_identity": {"base_apk_sha256": "a" * 64},
                },
                "dataset": {
                    "valid_dataset_run": True,
                    "paper_eligible": False,
                    "paper_exclusion_primary_reason_code": "EXCLUDED_SCRIPT_ABORT",
                },
            }
        ),
        encoding="utf-8",
    )
    freeze = {
        "apps": [{"package_name": "com.example.app", "selected_dynamic_run_ids": run_id}],
        "selection_contract": {"explicit_paper_ineligible_runs": "excluded"},
    }

    apk_ledger, evidence_ledger = build_paper_freeze_ledger_drafts(
        freeze_manifest=freeze,
        repo_root=tmp_path,
        evidence_root=tmp_path / "evidence",
    )

    assert apk_ledger["entries"] == []
    assert evidence_ledger["selected_run_count"] == 1
    assert evidence_ledger["explicitly_excluded_selected_run_count"] == 1
    assert evidence_ledger["entries"] == [
        {
            "base_apk_sha256": "a" * 64,
            "draft_status": "excluded_by_current_policy",
            "dynamic_run_id": run_id,
            "inclusion_disposition": "excluded",
            "package_name": "com.example.app",
            "paper_eligibility": "explicit_paper_exclusion",
            "paper_exclusion_reason": "EXCLUDED_SCRIPT_ABORT",
            "version_code": "7",
        }
    ]


def test_drafts_do_not_follow_run_or_artifact_paths_outside_evidence_root(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    run_dir = evidence_root / "safe-run"
    run_dir.mkdir(parents=True)
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"outside")
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {"package_name": "com.example.app"},
                "artifacts": [
                    {
                        "type": "pcapdroid_capture",
                        "relative_path": "../../outside.pcap",
                        "sha256": sha256_file(outside),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    freeze = {
        "apps": [
            {
                "package_name": "com.example.app",
                "selected_dynamic_run_ids": ["safe-run", "../outside-run"],
            }
        ]
    }

    _, evidence_ledger = build_paper_freeze_ledger_drafts(
        freeze_manifest=freeze,
        repo_root=tmp_path,
        evidence_root=evidence_root,
    )

    by_run = {entry["dynamic_run_id"]: entry for entry in evidence_ledger["entries"]}
    assert by_run["safe-run"]["pcap"] == {
        "path": "",
        "sha256": "",
        "draft_status": "unsafe_manifest_path",
    }
    assert by_run["../outside-run"]["draft_status"] == "unsafe_run_id"
