from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.diagnostics import (
    canonical_pcap_failure_code,
    canonical_pcap_failure_code_from_raw_detail,
    dataset_pcap_failure_detail,
    deep_audit_pcap_failure_detail,
    export_pcap_failure_detail,
    extract_verify_issue_codes,
    raw_pcap_failure_detail_from_canonical,
    verify_issue_codes_csv,
)


def test_extract_verify_issue_codes_dedupes_and_preserves_order() -> None:
    verify_row = {
        "issues": [
            {"code": "pcap_artifact_missing"},
            {"code": "pcap_artifact_missing"},
            {"code": "protocol_empty_no_reason"},
        ]
    }
    assert extract_verify_issue_codes(verify_row) == ("pcap_artifact_missing", "protocol_empty_no_reason")
    assert verify_issue_codes_csv(verify_row) == "pcap_artifact_missing;protocol_empty_no_reason"


def test_canonical_pcap_failure_code_handles_missing_artifact() -> None:
    canonical = canonical_pcap_failure_code(
        artifact_rel="",
        artifact_exists=False,
        pcap_size_bytes=0,
        report_status="skip",
        invalid_reason_code="PCAP_MISSING",
        verify_row={"issues": [{"code": "pcap_artifact_missing"}]},
    )
    assert canonical == "artifact_missing"
    assert deep_audit_pcap_failure_detail(canonical) == "PCAP_MISSING"
    assert export_pcap_failure_detail(canonical) == "invalid_pcap_artifact_missing"


def test_canonical_pcap_failure_code_handles_local_file_empty() -> None:
    canonical = canonical_pcap_failure_code(
        artifact_rel="artifacts/pcapdroid_capture/run.pcap",
        artifact_exists=True,
        pcap_size_bytes=0,
        report_status="skip",
        invalid_reason_code="PCAP_MISSING",
        verify_row={"issues": []},
    )
    assert canonical == "local_file_empty"
    assert deep_audit_pcap_failure_detail(canonical) == "PCAP_LOCAL_FILE_EMPTY"
    assert export_pcap_failure_detail(canonical) == "invalid_pcap_local_file_empty"


def test_canonical_pcap_failure_code_handles_parse_failure() -> None:
    canonical = canonical_pcap_failure_code(
        artifact_rel="artifacts/pcapdroid_capture/run.pcap",
        artifact_exists=True,
        pcap_size_bytes=4096,
        report_status="partial",
        invalid_reason_code="PCAP_PARSE_ERROR",
        verify_row={"issues": []},
    )
    assert canonical == "parse_failed"
    assert deep_audit_pcap_failure_detail(canonical) == "PCAP_PARSE_FAILED"
    assert export_pcap_failure_detail(canonical) == "invalid_pcap_parse_error"


def test_dataset_pcap_failure_detail_handles_device_empty_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-empty-device"
    meta_path = run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "failure_diagnostics": {
                    "expected_device_path_exists": True,
                    "expected_device_path_size_bytes": 0,
                }
            }
        ),
        encoding="utf-8",
    )
    assert dataset_pcap_failure_detail(run_dir, pcap_size_int=0) == "PCAP_DEVICE_FILE_EMPTY"


def test_dataset_pcap_failure_detail_handles_delayed_device_empty_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-delayed-empty-device"
    meta_path = run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "failure_diagnostics": {
                    "expected_device_path_exists": False,
                    "expected_device_path_size_bytes": None,
                    "latest_fallback_path": None,
                    "delayed_expected_device_path_exists": True,
                    "delayed_expected_device_path_size_bytes": 0,
                }
            }
        ),
        encoding="utf-8",
    )
    assert dataset_pcap_failure_detail(run_dir, pcap_size_int=0) == "PCAP_DEVICE_FILE_EMPTY"


def test_dataset_pcap_failure_detail_handles_local_parse_failure(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-parse-failed"
    pcap_path = run_dir / "artifacts" / "pcapdroid_capture" / "run.pcap"
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    pcap_path.write_bytes(b"not-empty")
    assert dataset_pcap_failure_detail(run_dir, pcap_size_int=4096) == "PCAP_PARSE_FAILED"


def test_raw_pcap_failure_detail_from_canonical_handles_artifact_missing() -> None:
    assert raw_pcap_failure_detail_from_canonical("artifact_missing") == "PCAP_ARTIFACT_MISSING"


def test_canonical_pcap_failure_code_from_raw_detail_handles_local_missing() -> None:
    assert canonical_pcap_failure_code_from_raw_detail("PCAP_LOCAL_FILE_MISSING") == "local_file_missing"
