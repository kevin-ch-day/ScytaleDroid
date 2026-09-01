from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence.freeze_verify import (
    REQUIRED_FROZEN_INPUTS,
    verify_dataset_freeze_immutability,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_freeze(path: Path, *, run_ids: list[object], checksums: dict[str, object]) -> None:
    path.write_text(
        json.dumps(
            {
                "included_run_ids": run_ids,
                "included_run_checksums": checksums,
            }
        ),
        encoding="utf-8",
    )


def test_freeze_verifier_accepts_matching_contained_files(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    run_dir = evidence_root / "run-1"
    pcap = run_dir / "capture.pcap"
    expected_files: dict[str, str] = {}
    for relative_path in REQUIRED_FROZEN_INPUTS:
        artifact = run_dir / relative_path
        artifact.parent.mkdir(parents=True, exist_ok=True)
        content = relative_path.encode("utf-8")
        artifact.write_bytes(content)
        expected_files[relative_path] = _sha256(content)
    pcap.write_bytes(b"pcap")
    freeze_path = tmp_path / "freeze.json"
    _write_freeze(
        freeze_path,
        run_ids=["run-1"],
        checksums={
            "run-1": {
                "files_sha256": expected_files,
                "pcap": {"relative_path": "capture.pcap", "sha256": _sha256(b"pcap")},
            }
        },
    )

    result = verify_dataset_freeze_immutability(
        freeze_path=freeze_path,
        evidence_root=evidence_root,
        write_outputs=False,
    )

    assert result.scanned == 1
    assert result.missing == 0
    assert result.mismatches == 0
    assert result.issues == []


def test_freeze_verifier_rejects_paths_outside_run_directory(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    (evidence_root / "run-1").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    freeze_path = tmp_path / "freeze.json"
    _write_freeze(
        freeze_path,
        run_ids=["run-1"],
        checksums={
            "run-1": {
                "files_sha256": {"../../outside.txt": _sha256(b"outside")},
            }
        },
    )

    result = verify_dataset_freeze_immutability(
        freeze_path=freeze_path,
        evidence_root=evidence_root,
        write_outputs=False,
    )

    assert result.missing == 6
    assert result.mismatches == 0
    assert result.issues[-1] == {
        "run_id": "run-1",
        "issue": "unsafe_path",
        "path": "../../outside.txt",
    }
    assert sum(issue["issue"] == "missing_expected_checksum" for issue in result.issues) == 5


def test_freeze_verifier_reports_malformed_entries_and_non_files(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    directory = evidence_root / "run-1" / "not-a-file"
    directory.mkdir(parents=True)
    freeze_path = tmp_path / "freeze.json"
    _write_freeze(
        freeze_path,
        run_ids=["run-1", "run-1", None, "../outside-run"],
        checksums={
            "run-1": {
                "files_sha256": {
                    "": "bad",
                    "not-a-file": _sha256(b"irrelevant"),
                }
            }
        },
    )

    result = verify_dataset_freeze_immutability(
        freeze_path=freeze_path,
        evidence_root=evidence_root,
        write_outputs=False,
    )

    assert result.scanned == 1
    assert result.missing == 10
    assert result.mismatches == 0
    assert {issue["issue"] for issue in result.issues} == {
        "invalid_checksum_entry",
        "missing_file",
        "duplicate_run_id",
        "invalid_run_id",
        "unsafe_run_id",
        "missing_expected_checksum",
    }
