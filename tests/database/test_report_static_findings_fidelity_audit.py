from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_static_findings_fidelity_audit as report


def _base_report_payload(
    *,
    package_name: str,
    display_name: str,
    session_stamp: str,
    generated_at: str,
    sha256: str,
    severity_counts: dict[str, int],
    total_findings: int,
    findings_fidelity: dict[str, object] | None = None,
) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    for sev, count in severity_counts.items():
        for idx in range(count):
            findings.append(
                {
                    "finding_id": f"{package_name}.{sev.lower()}.{idx}",
                    "title": f"{sev} finding {idx}",
                    "severity_gate": {"value": sev},
                    "evidence": [{"description": f"desc-{sev}-{idx}"}],
                }
            )
    metadata: dict[str, object] = {
        "package_name": package_name,
        "app_label": display_name,
        "is_split_member": False,
        "session_stamp": session_stamp,
        "pipeline_summary": {
            "total_findings": total_findings,
            "severity_counts": severity_counts,
        },
    }
    if findings_fidelity is not None:
        metadata["findings_fidelity"] = findings_fidelity
    return {
        "generated_at": generated_at,
        "manifest": {
            "package_name": package_name,
        },
        "findings": findings,
        "metadata": metadata,
        "hashes": {"sha256": sha256},
    }


def _split_report_payload(
    *,
    package_name: str,
    display_name: str,
    session_stamp: str,
    generated_at: str,
    findings_fidelity: dict[str, object] | None = None,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "package_name": package_name,
        "app_label": display_name,
        "is_split_member": True,
        "session_stamp": session_stamp,
        "pipeline_summary": {
            "total_findings": 1,
            "severity_counts": {"P1": 1},
        },
    }
    if findings_fidelity is not None:
        metadata["findings_fidelity"] = findings_fidelity
    return {
        "generated_at": generated_at,
        "manifest": {
            "package_name": package_name,
        },
        "findings": [
            {
                "finding_id": f"{package_name}.split.0",
                "title": "Split-only finding",
                "severity_gate": {"value": "P1"},
            }
        ],
        "metadata": metadata,
    }


def _run_health_payload(*, session_stamp: str) -> dict[str, object]:
    return {
        "session_stamp": session_stamp,
        "post_run_grain_present": True,
        "post_run_merge_status": "merged",
        "run_rollups": {
            "findings_runtime_total": 12,
            "findings_persisted_db_total": 8,
            "findings_capped_not_persisted_total": 4,
        },
        "apps": [
            {
                "package_name": "com.example.one",
                "app_label": "Example One",
                "discovered_artifacts": 3,
                "report_paths_short": [
                    f"data/static_analysis/reports/archive/{session_stamp}/aa.json",
                    f"data/static_analysis/reports/archive/{session_stamp}/ab.json",
                ],
                "finding_persistence": {
                    "runtime_findings": 10,
                    "persisted_findings_db": 6,
                    "capped_not_persisted": 4,
                    "capped_by_detector": {"ipc_components": 4},
                },
            },
            {
                "package_name": "com.example.two",
                "app_label": "Example Two",
                "discovered_artifacts": 1,
                "report_paths_short": [
                    f"data/static_analysis/reports/archive/{session_stamp}/bb.json"
                ],
                "finding_persistence": {
                    "runtime_findings": 2,
                    "persisted_findings_db": 2,
                    "capped_not_persisted": 0,
                    "capped_by_detector": {},
                },
            },
        ],
    }


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_static_findings_fidelity_audit.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or "").lower()
    assert out.startswith("usage:")
    assert "--session" in out
    assert "static findings fidelity" in out


def test_main_generates_expected_audit_bundle(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    session_stamp = "20260613-all-full"
    archive_dir = data_root / "static_analysis" / "reports" / "archive" / session_stamp
    run_health_dir = data_root / "store" / "apk"
    output_dir = repo_root / "output" / "audit" / "static_findings_fidelity" / "smoke"
    archive_dir.mkdir(parents=True)
    run_health_dir.mkdir(parents=True)

    (archive_dir / "aa.json").write_text(
        json.dumps(
            _base_report_payload(
                package_name="com.example.one",
                display_name="Example One",
                session_stamp=session_stamp,
                generated_at="2026-06-13T10:00:00Z",
                sha256="aa" * 32,
                severity_counts={"P0": 1, "P1": 9},
                total_findings=10,
                findings_fidelity={
                    "finding_fidelity_status": "capped",
                    "runtime_findings": 10,
                    "persisted_db_findings": 6,
                    "capped_not_persisted": 4,
                    "cap_metadata_grain": "package",
                    "per_finding_persistence_status_available": False,
                },
            )
        ),
        encoding="utf-8",
    )
    (archive_dir / "ab.json").write_text(
        json.dumps(
            _split_report_payload(
                package_name="com.example.one",
                display_name="Example One",
                session_stamp=session_stamp,
                generated_at="2026-06-13T10:00:10Z",
                findings_fidelity={
                    "finding_fidelity_status": "capped",
                    "runtime_findings": 10,
                    "persisted_db_findings": 6,
                    "capped_not_persisted": 4,
                    "cap_metadata_grain": "package",
                    "per_finding_persistence_status_available": False,
                },
            )
        ),
        encoding="utf-8",
    )
    (archive_dir / "bb.json").write_text(
        json.dumps(
            _base_report_payload(
                package_name="com.example.two",
                display_name="Example Two",
                session_stamp=session_stamp,
                generated_at="2026-06-13T10:01:00Z",
                sha256="bb" * 32,
                severity_counts={"P1": 2},
                total_findings=2,
                findings_fidelity={
                    "finding_fidelity_status": "complete",
                    "runtime_findings": 2,
                    "persisted_db_findings": 2,
                    "capped_not_persisted": 0,
                    "cap_metadata_grain": "package",
                    "per_finding_persistence_status_available": False,
                },
            )
        ),
        encoding="utf-8",
    )
    (run_health_dir / f"{session_stamp}_run_health.json").write_text(
        json.dumps(_run_health_payload(session_stamp=session_stamp)),
        encoding="utf-8",
    )

    def _fake_db(_session_stamp: str) -> tuple[dict[str, object], list[str]]:
        return (
            {
                "db_name": "scytaledroid_core_prod",
                "run_rows": {
                    "com.example.one": {
                        "display_name": "Example One",
                        "persisted_findings_db": 6,
                    },
                    "com.example.two": {
                        "display_name": "Example Two",
                        "persisted_findings_db": 2,
                    },
                },
                "package_persisted_by_severity": {
                    "com.example.one": {"P0": 1, "P1": 5},
                    "com.example.two": {"P1": 2},
                },
                "detector_persisted_totals": {"ipc_components": 6, "network_surface": 2},
                "detector_persisted_p0": {"ipc_components": 1},
                "detector_packages": {
                    "ipc_components": {"com.example.one"},
                    "network_surface": {"com.example.two"},
                },
                "surface_presence": {
                    "static_analysis_runs": True,
                    "static_analysis_findings": True,
                    "vw_static_finding_surfaces_latest": True,
                    "v_static_handoff_v1": True,
                    "v_static_masvs_matrix_v1": True,
                },
            },
            [],
        )

    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(report, "_load_optional_db", _fake_db)

    rc = report.main(["--session", session_stamp, "--output-dir", str(output_dir)])
    assert rc == 0

    expected = {
        "summary.json",
        "finding_fidelity_by_package.csv",
        "finding_fidelity_by_detector.csv",
        "finding_fidelity_by_severity.csv",
        "finding_fidelity_by_artifact_grain.csv",
        "capped_findings_examples.csv",
        "db_consumer_fidelity_gaps.csv",
        "recommended_next_action.json",
    }
    assert {p.name for p in output_dir.iterdir()} == expected

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["session_stamp"] == session_stamp
    assert summary["runtime_findings_total"] == 12
    assert summary["persisted_db_findings_total"] == 8
    assert summary["capped_not_persisted_total"] == 4
    assert summary["packages_with_capped_findings"] == 1
    assert summary["detectors_with_capped_findings"] == 1
    assert summary["p0_runtime_findings"] == 1
    assert summary["p0_persisted_findings"] == 1
    assert summary["p0_capped_not_persisted"] == 0
    assert summary["per_report_cap_metadata_available"] == 1
    assert summary["per_finding_persisted_flags_available"] == 0
    assert summary["reports_with_fidelity_metadata"] == 3
    assert summary["reports_missing_fidelity_metadata"] == 0
    assert summary["metadata_grain_distribution"] == {"package": 3}
    assert summary["db_consumer_warning_required"] == 1
    assert summary["cap_policy_detector_aware"] is True
    assert summary["cap_policy_severity_aware"] is False
    assert summary["recommended_next_action"] == "add_db_summary_counts_for_capped_findings"

    pkg_rows = list(csv.DictReader((output_dir / "finding_fidelity_by_package.csv").open()))
    heavy = next(row for row in pkg_rows if row["package_name"] == "com.example.one")
    assert heavy["capped_not_persisted"] == "4"
    assert heavy["p0_runtime"] == "1"
    assert heavy["p0_persisted"] == "1"
    assert heavy["p0_capped"] == "0"
    assert heavy["multi_artifact_package"] == "1"
    assert "ipc_components:4" in heavy["top_capped_detectors"]

    det_rows = list(csv.DictReader((output_dir / "finding_fidelity_by_detector.csv").open()))
    ipc = next(row for row in det_rows if row["detector_name"] == "ipc_components")
    assert ipc["runtime_findings"] == "10"
    assert ipc["persisted_db_findings"] == "6"
    assert ipc["capped_not_persisted"] == "4"
    assert ipc["p0_persisted"] == "1"

    sev_rows = list(csv.DictReader((output_dir / "finding_fidelity_by_severity.csv").open()))
    p0 = next(row for row in sev_rows if row["severity"] == "P0")
    assert p0["runtime_findings"] == "1"
    assert p0["persisted_db_findings"] == "1"
    assert p0["capped_not_persisted"] == "0"

    grain_rows = list(
        csv.DictReader((output_dir / "finding_fidelity_by_artifact_grain.csv").open())
    )
    split = next(row for row in grain_rows if row["artifact_grain"] == "split_apk")
    assert split["capped_not_persisted"] == "4"

    gaps = list(csv.DictReader((output_dir / "db_consumer_fidelity_gaps.csv").open()))
    assert any(row["file_or_view"] == "v_static_masvs_matrix_v1" for row in gaps)

    rec = json.loads((output_dir / "recommended_next_action.json").read_text(encoding="utf-8"))
    assert rec["recommended_action"] == "add_db_summary_counts_for_capped_findings"
    assert "investigate_ipc_components_noise" in rec["secondary_actions"]


def test_p0_status_is_marked_unknown_without_db_support(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    session_stamp = "20260613-all-full"
    archive_dir = data_root / "static_analysis" / "reports" / "archive" / session_stamp
    run_health_dir = data_root / "store" / "apk"
    output_dir = repo_root / "output" / "audit" / "static_findings_fidelity" / "smoke-unknown"
    archive_dir.mkdir(parents=True)
    run_health_dir.mkdir(parents=True)

    (archive_dir / "aa.json").write_text(
        json.dumps(
            _base_report_payload(
                package_name="com.example.one",
                display_name="Example One",
                session_stamp=session_stamp,
                generated_at="2026-06-13T10:00:00Z",
                sha256="aa" * 32,
                severity_counts={"P0": 1, "P1": 1},
                total_findings=2,
            )
        ),
        encoding="utf-8",
    )
    (run_health_dir / f"{session_stamp}_run_health.json").write_text(
        json.dumps(
            {
                "session_stamp": session_stamp,
                "run_rollups": {
                    "findings_runtime_total": 2,
                    "findings_persisted_db_total": 1,
                    "findings_capped_not_persisted_total": 1,
                },
                "apps": [
                    {
                        "package_name": "com.example.one",
                        "app_label": "Example One",
                        "discovered_artifacts": 1,
                        "finding_persistence": {
                            "runtime_findings": 2,
                            "persisted_findings_db": 1,
                            "capped_not_persisted": 1,
                            "capped_by_detector": {"ipc_components": 1},
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(
        report,
        "_load_optional_db",
        lambda _session: (
            {
                "db_name": None,
                "run_rows": {},
                "package_persisted_by_severity": {},
                "detector_persisted_totals": {},
                "detector_persisted_p0": {},
                "detector_packages": {},
                "surface_presence": {},
            },
            ["db_unavailable:test"],
        ),
    )

    rc = report.main(["--session", session_stamp, "--output-dir", str(output_dir)])
    assert rc == 0

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["p0_persisted_findings"] is None
    assert summary["p0_capped_not_persisted"] is None
    assert summary["per_report_cap_metadata_available"] == 0
    assert summary["reports_with_fidelity_metadata"] == 0
    assert summary["reports_missing_fidelity_metadata"] == 1
    assert summary["metadata_grain_distribution"] == {}
    assert summary["recommended_next_action"] == "add_per_report_cap_metadata"

    pkg_rows = list(csv.DictReader((output_dir / "finding_fidelity_by_package.csv").open()))
    only = pkg_rows[0]
    assert only["p0_runtime"] == "1"
    assert only["p0_persisted"] == ""
    assert only["p0_capped"] == ""
    assert "unknown" in (only["notes"] or "")
