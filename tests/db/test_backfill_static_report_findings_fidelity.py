from __future__ import annotations

import json
from pathlib import Path

from scripts.db import backfill_static_report_findings_fidelity as script


def _report_payload(*, package_name: str, session_stamp: str, with_fidelity: bool) -> dict[str, object]:
    metadata: dict[str, object] = {
        "package_name": package_name,
        "app_label": package_name,
        "session_stamp": session_stamp,
        "is_split_member": False,
        "pipeline_summary": {
            "total_findings": 10,
            "severity_counts": {"P0": 1, "P1": 9},
        },
    }
    if with_fidelity:
        metadata["findings_fidelity"] = {
            "finding_fidelity_status": "complete",
            "runtime_findings": 10,
            "persisted_db_findings": 10,
            "capped_not_persisted": 0,
            "cap_metadata_grain": "package",
            "per_finding_persistence_status_available": False,
        }
    return {
        "generated_at": "2026-06-16T06:10:28.356005+00:00",
        "manifest": {"package_name": package_name},
        "metadata": metadata,
        "findings": [{"finding_id": "f1", "severity_gate": {"value": "P0"}}],
    }


def _run_health_payload(*, session_stamp: str, package_name: str) -> dict[str, object]:
    return {
        "session_stamp": session_stamp,
        "apps": [
            {
                "package_name": package_name,
                "app_label": package_name,
                "finding_persistence": {
                    "runtime_findings": 10,
                    "persisted_findings_db": 10,
                    "capped_not_persisted": 0,
                    "capped_by_detector": {},
                },
            }
        ],
    }


def test_help_is_safe_without_pythonpath(assert_safe_script_help) -> None:
    out = assert_safe_script_help("scripts/db/backfill_static_report_findings_fidelity.py")
    assert "--apply" in out


def test_dry_run_reports_missing_targets(tmp_path: Path, monkeypatch, capsys) -> None:
    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    session_stamp = "20260616-all-full"
    archive_dir = data_root / "static_analysis" / "reports" / "archive" / session_stamp
    run_health_dir = data_root / "store" / "apk"
    archive_dir.mkdir(parents=True)
    run_health_dir.mkdir(parents=True)

    missing_path = archive_dir / "missing.json"
    missing_path.write_text(
        json.dumps(_report_payload(package_name="com.example.one", session_stamp=session_stamp, with_fidelity=False)),
        encoding="utf-8",
    )
    present_path = archive_dir / "present.json"
    present_path.write_text(
        json.dumps(_report_payload(package_name="com.example.two", session_stamp=session_stamp, with_fidelity=True)),
        encoding="utf-8",
    )
    (run_health_dir / f"{session_stamp}_run_health.json").write_text(
        json.dumps(_run_health_payload(session_stamp=session_stamp, package_name="com.example.one")),
        encoding="utf-8",
    )

    monkeypatch.setattr(script, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(
        script,
        "_load_optional_db",
        lambda _session: (
            {
                "run_rows": {
                    "com.example.one": {"persisted_findings_db": 10, "findings_runtime_total": 10, "findings_capped_total": 0}
                },
                "package_persisted_by_severity": {
                    "com.example.one": {"P0": 1}
                },
            },
            [],
        ),
    )

    rc = script.main(["--session", session_stamp])

    out = capsys.readouterr().out
    assert rc == 0
    assert "missing reports: 1" in out
    assert "com.example.one" in out
    payload = json.loads(missing_path.read_text(encoding="utf-8"))
    assert "findings_fidelity" not in payload["metadata"]


def test_apply_backfills_missing_report_metadata(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    session_stamp = "20260616-all-full"
    archive_dir = data_root / "static_analysis" / "reports" / "archive" / session_stamp
    run_health_dir = data_root / "store" / "apk"
    archive_dir.mkdir(parents=True)
    run_health_dir.mkdir(parents=True)

    missing_path = archive_dir / "missing.json"
    missing_path.write_text(
        json.dumps(_report_payload(package_name="com.example.one", session_stamp=session_stamp, with_fidelity=False)),
        encoding="utf-8",
    )
    (run_health_dir / f"{session_stamp}_run_health.json").write_text(
        json.dumps(_run_health_payload(session_stamp=session_stamp, package_name="com.example.one")),
        encoding="utf-8",
    )

    monkeypatch.setattr(script, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(
        script,
        "_load_optional_db",
        lambda _session: (
            {
                "run_rows": {
                    "com.example.one": {"persisted_findings_db": 10, "findings_runtime_total": 10, "findings_capped_total": 0}
                },
                "package_persisted_by_severity": {
                    "com.example.one": {"P0": 1}
                },
            },
            [],
        ),
    )

    rc = script.main(["--session", session_stamp, "--apply"])

    assert rc == 0
    payload = json.loads(missing_path.read_text(encoding="utf-8"))
    ff = payload["metadata"]["findings_fidelity"]
    assert ff["runtime_findings"] == 10
    assert ff["persisted_db_findings"] == 10
    assert ff["capped_not_persisted"] == 0
    assert ff["cap_metadata_grain"] == "package"
    receipt_dir = repo_root / "data" / "state" / "static_report_findings_fidelity_backfill"
    receipts = sorted(receipt_dir.glob("*.json"))
    assert receipts
