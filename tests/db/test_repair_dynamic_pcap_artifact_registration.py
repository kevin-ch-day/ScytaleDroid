from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.db import repair_dynamic_pcap_artifact_registration as repair


def test_generate_report_dry_run_plans_missing_pcap_artifact_without_mutating_manifest(
    tmp_path: Path,
) -> None:
    run_dir = _make_run(tmp_path, "run-1", include_pcap_artifact=False)
    before = (run_dir / "run_manifest.json").read_text(encoding="utf-8")

    summary = repair.generate_report(
        evidence_root=tmp_path,
        output_dir=tmp_path / "audit",
        run_ids=["run-1"],
        apply=False,
    )

    assert summary["candidate_rows"] == 1
    assert summary["safe_auto_repair_rows"] == 1
    assert summary["applied_rows"] == 0
    assert (run_dir / "run_manifest.json").read_text(encoding="utf-8") == before
    with (tmp_path / "audit" / "pcap_artifact_registration_repair_plan.csv").open(
        encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["repair_action"] == "add_missing_pcap_artifact"
    assert rows[0]["applied"] == "0"


def test_generate_report_apply_adds_only_pcap_artifact(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, "run-apply", include_pcap_artifact=False)

    summary = repair.generate_report(
        evidence_root=tmp_path,
        output_dir=tmp_path / "audit",
        run_ids=["run-apply"],
        apply=True,
    )

    assert summary["applied_rows"] == 1
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    pcap_artifacts = [item for item in manifest["artifacts"] if item["type"] == "pcapdroid_capture"]
    assert len(pcap_artifacts) == 1
    assert pcap_artifacts[0]["relative_path"] == "artifacts/pcapdroid_capture/app.pcap"
    assert manifest["dataset"]["valid_dataset_run"] is False
    assert manifest["dataset"]["invalid_reason_code"] == "PCAP_MISSING"


def test_existing_missing_artifact_path_is_review_only(tmp_path: Path) -> None:
    _make_run(
        tmp_path,
        "run-mismatch",
        include_pcap_artifact=True,
        pcap_artifact_path="artifacts/pcapdroid_capture/missing.pcap",
    )

    summary = repair.generate_report(
        evidence_root=tmp_path,
        output_dir=tmp_path / "audit",
        run_ids=["run-mismatch"],
        apply=True,
    )

    assert summary["candidate_rows"] == 1
    assert summary["review_only_rows"] == 1
    assert summary["applied_rows"] == 0


def _make_run(
    root: Path,
    run_id: str,
    *,
    include_pcap_artifact: bool,
    pcap_artifact_path: str = "artifacts/pcapdroid_capture/app.pcap",
) -> Path:
    run_dir = root / run_id
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True)
    analysis_dir.mkdir(parents=True)
    pcap = capture_dir / "app.pcap"
    pcap.write_bytes(b"pcap-bytes")
    artifacts = [
        {
            "type": "pcapdroid_capture_meta",
            "relative_path": "artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
            "produced_by": "pcapdroid_capture",
        }
    ]
    if include_pcap_artifact:
        artifacts.append(
            {
                "type": "pcapdroid_capture",
                "relative_path": pcap_artifact_path,
                "produced_by": "pcapdroid_capture",
            }
        )
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps({"pcap_name": "app.pcap", "pcap_size_bytes": pcap.stat().st_size}),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "pcap_path": "artifacts/pcapdroid_capture/app.pcap",
                "pcap_capture_name": "app.pcap",
                "pcap_size_bytes": pcap.stat().st_size,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": run_id,
                "target": {"package_name": "com.example"},
                "dataset": {"valid_dataset_run": False, "invalid_reason_code": "PCAP_MISSING"},
                "artifacts": artifacts,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return run_dir
