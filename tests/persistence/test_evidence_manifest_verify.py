"""Tests for ``evidence_manifest_verify`` (no DB by default)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from scytaledroid.StaticAnalysis.cli.persistence import evidence_manifest_verify as emv


def test_verify_payload_ok_minimal(tmp_path: Path) -> None:
    rp = tmp_path / "r.json"
    rp.write_text("{}", encoding="utf-8")
    h = hashlib.sha256(rp.read_bytes()).hexdigest()
    manifest = {
        "manifest_schema_version": "1",
        "session_stamp": "s1",
        "generated_at_utc": "2026-01-01T00:00:00Z",
        "git_commit": "abc",
        "canonical_artifacts": [{"path": str(rp), "role": "detector_report", "sha256": h}],
        "handoff": {"runs": []},
        "detector_report": {"runs": []},
    }
    assert emv.verify_evidence_manifest_payload(manifest) == []


def test_verify_payload_detects_sha256_mismatch(tmp_path: Path) -> None:
    rp = tmp_path / "r.json"
    rp.write_text("{}", encoding="utf-8")
    manifest = {
        "manifest_schema_version": "1",
        "session_stamp": "s1",
        "generated_at_utc": "2026-01-01T00:00:00Z",
        "git_commit": "abc",
        "canonical_artifacts": [
            {"path": str(rp), "role": "detector_report", "sha256": "0" * 64},
        ],
        "handoff": {"runs": []},
        "detector_report": {"runs": []},
    }
    issues = emv.verify_evidence_manifest_payload(manifest)
    assert any("sha256_mismatch" in x for x in issues)


def test_verify_db_handoff_mismatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    hp = tmp_path / "h.json"
    hp.write_text('{"x":1}', encoding="utf-8")
    disk_hash = hashlib.sha256(hp.read_bytes()).hexdigest()
    manifest = {
        "handoff": {
            "runs": [
                {"static_run_id": 9, "json_path": str(hp), "sha256": disk_hash},
            ]
        }
    }

    def fake_run_sql(sql, params, fetch=None, **kwargs):
        assert fetch == "one"
        assert params == (9,)
        return ("f" * 64,)

    issues = emv.verify_manifest_handoff_hash_vs_database(manifest, run_sql=fake_run_sql)
    assert any("sar_hash_mismatch" in x for x in issues)


def test_verify_db_handoff_skips_when_sar_hash_missing(tmp_path: Path) -> None:
    hp = tmp_path / "h.json"
    hp.write_text("{}", encoding="utf-8")
    manifest = {"handoff": {"runs": [{"static_run_id": 1, "json_path": str(hp)}]}}
    issues = emv.verify_manifest_handoff_hash_vs_database(
        manifest,
        run_sql=lambda *_a, **_k: (None,),
    )
    assert issues == []
