from __future__ import annotations

from pathlib import Path

from scytaledroid.Publication.research_capsule import build_research_capsule_manifest, sha256_file
from scytaledroid.Publication.research_capsule_ledgers import (
    preview_db_export_spec,
    validate_apk_ledger,
    validate_db_export_spec,
    verify_apk_ledger,
    verify_evidence_ledger,
)


def _apk_entry(path: Path, *, version_code: str = "1", digest: str | None = None) -> dict[str, str]:
    return {
        "package_name": "com.example.app",
        "app_name": "Example",
        "version_name": "1.0",
        "version_code": version_code,
        "base_apk_sha256": digest or sha256_file(path),
        "selected_apk_path": path.name,
        "static_run_id": "42",
        "paper_build_relation": "selected_paper_build",
        "inclusion_disposition": "included",
    }


def _evidence_entry(pcap: Path, artifact: Path, *, version_code: str = "1", digest: str | None = None) -> dict[str, object]:
    return {
        "package_name": "com.example.app",
        "version_code": version_code,
        "base_apk_sha256": digest or "a" * 64,
        "dynamic_run_id": "run-1",
        "run_profile": "interaction_manual",
        "capture_started_at_utc": "2026-07-19T00:00:00Z",
        "pcap": {"path": pcap.name, "sha256": sha256_file(pcap)},
        "artifacts": [{"role": "run_manifest", "path": artifact.name, "sha256": sha256_file(artifact)}],
        "paper_eligibility": "paper_selected",
        "validity_state": "VALID",
        "manuscript_dependencies": ["Table 1"],
    }


def test_apk_ledger_rejects_duplicate_entries_and_hash_mismatch(tmp_path: Path) -> None:
    apk = tmp_path / "example.apk"
    apk.write_bytes(b"apk")
    entry = _apk_entry(apk)
    ledger = {"schema_version": 1, "paper_id": "paper3", "review_status": "APPROVED", "entries": [entry, dict(entry)]}

    assert "entries[1]:duplicate_build" in validate_apk_ledger(ledger)
    entry["base_apk_sha256"] = "b" * 64
    assert any(issue.startswith("apk_hash_mismatch:") for issue in verify_apk_ledger(ledger, repo_root=tmp_path))


def test_evidence_ledger_rejects_missing_artifacts_and_unselected_build(tmp_path: Path) -> None:
    apk = tmp_path / "example.apk"
    pcap = tmp_path / "capture.pcap"
    artifact = tmp_path / "run_manifest.json"
    apk.write_bytes(b"apk")
    pcap.write_bytes(b"pcap")
    artifact.write_text("{}", encoding="utf-8")
    apk_entry = _apk_entry(apk)
    evidence_entry = _evidence_entry(pcap, artifact, digest=apk_entry["base_apk_sha256"])
    evidence_entry["pcap"] = {"path": "missing.pcap", "sha256": "a" * 64}
    evidence_entry["version_code"] = "2"

    issues = verify_evidence_ledger(
        {"schema_version": 1, "paper_id": "paper3", "review_status": "APPROVED", "entries": [evidence_entry]},
        repo_root=tmp_path,
        apk_ledger={"schema_version": 1, "paper_id": "paper3", "review_status": "APPROVED", "entries": [apk_entry]},
    )

    assert "evidence_unselected_build:com.example.app:2" in issues
    assert any(issue.startswith("evidence_missing:") for issue in issues)


def test_db_export_preview_rejects_broad_spec_and_zero_rows() -> None:
    unsafe = {
        "schema_version": 1,
        "paper_id": "paper3",
        "review_status": "APPROVED",
        "schema_definition_included": True,
        "scope": {"run_ids": ["run-1"]},
        "exclusions": ["credentials"],
        "tables": [{"schema": "core", "table": "dynamic_sessions", "predicate": "1=1"}],
    }
    assert "tables[0].predicate:unscoped_or_unsafe" in validate_db_export_spec(unsafe)

    scoped = unsafe | {"tables": [{"schema": "core", "table": "dynamic_sessions", "predicate": "dynamic_run_id IN ('run-1')"}]}
    preview = preview_db_export_spec(scoped, row_counter=lambda _schema, _table, _predicate: 0)
    assert preview["ok"] is False
    assert preview["issues"] == ["zero_matching_rows:core.dynamic_sessions"]


def test_capsule_manifest_is_deterministic_with_pinned_generation_time(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    kwargs = {
        "paper_id": "paper3",
        "repo_root": tmp_path,
        "items": {"freeze": [source]},
        "generated_at_utc": "2026-07-19T00:00:00+00:00",
    }

    assert build_research_capsule_manifest(**kwargs) == build_research_capsule_manifest(**kwargs)
