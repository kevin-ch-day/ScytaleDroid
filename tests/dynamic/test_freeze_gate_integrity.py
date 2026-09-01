from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.tools import freeze_gate


def _write_freeze(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_research_gate_checks_frozen_input_hashes_before_ml(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    run_dir = evidence_root / "run-1"
    run_dir.mkdir(parents=True)
    frozen_input = run_dir / "run_manifest.json"
    frozen_input.write_text("original", encoding="utf-8")
    freeze_path = tmp_path / "freeze.json"
    _write_freeze(
        freeze_path,
        {
            "included_run_ids": ["run-1"],
            "included_run_checksums": {
                "run-1": {
                    "files_sha256": {
                        "run_manifest.json": hashlib.sha256(b"different").hexdigest(),
                    }
                }
            },
            "min_pcap_bytes_used": freeze_gate.profile_config.MIN_PCAP_BYTES,
        },
    )

    result = freeze_gate.run_freeze_gate(
        freeze_path=freeze_path,
        evidence_root=evidence_root,
    )

    assert result.passed is False
    assert any("freeze_immutability:run-1:sha_mismatch" in error for error in result.errors)


def test_research_gate_rejects_unsafe_duplicate_and_nonstring_run_ids(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    freeze_path = tmp_path / "freeze.json"
    _write_freeze(
        freeze_path,
        {
            "included_run_ids": ["../outside", "../outside", None],
            "included_run_checksums": {"../outside": {"files_sha256": {}}},
            "min_pcap_bytes_used": freeze_gate.profile_config.MIN_PCAP_BYTES,
        },
    )

    result = freeze_gate.run_freeze_gate(
        freeze_path=freeze_path,
        evidence_root=evidence_root,
    )

    assert result.passed is False
    assert "freeze_manifest:unsafe_run_id:../outside" in result.errors
    assert "freeze_manifest:duplicate_run_id:../outside" in result.errors
    assert "freeze_manifest:invalid_run_id" in result.errors
    assert result.checked_runs == 0
