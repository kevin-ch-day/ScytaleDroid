from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_dynamic_readiness_audit as report


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_dynamic_readiness_audit.py"
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
    assert "--output-dir" in out
    assert "dynamic readiness" in out


def test_expected_store_path_uses_sha256_prefix() -> None:
    data_dir = Path("/repo/data")
    sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    path = report._expected_store_path(data_dir, sha)
    assert str(path) == "/repo/data/store/apk/sha256/ab/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.apk"


def test_plan_missing_required_fields_flags_core_identity_gaps() -> None:
    missing = report._plan_missing_required_fields(
        {
            "package_name": "com.example.app",
            "static_run_id": None,
            "base_apk_sha256": "",
            "artifact_set_hash": "",
            "static_handoff_hash": "",
        }
    )
    assert missing == [
        "static_run_id",
        "base_apk_sha256",
        "artifact_set_hash",
        "static_handoff_hash",
    ]


def test_linkage_status_prioritizes_missing_store_artifact() -> None:
    status = report._linkage_status(
        static_run_id=123,
        baseline_present=True,
        base_apk_sha256="a" * 64,
        store_present=False,
        report_match_count=1,
        identity_complete=True,
    )
    assert status == "missing_store_artifact"


def test_identity_linked_requires_identity_and_some_corroboration() -> None:
    assert (
        report._identity_linked(
            static_identity_complete=True,
            static_run_manifest_present=False,
            handoff_view_present=True,
            handoff_path_present=False,
        )
        is True
    )
    assert (
        report._identity_linked(
            static_identity_complete=False,
            static_run_manifest_present=True,
            handoff_view_present=True,
            handoff_path_present=True,
        )
        is False
    )


def test_classify_readiness_level_uses_ordered_progression() -> None:
    status = report._classify_readiness_level(
        static_plan_present=True,
        identity_linked=True,
        apk_store_ready=True,
        dynamic_capture_ready=True,
        dynamic_evidence_present=True,
        analysis_ready=True,
        freeze_ready=False,
    )
    assert status == "analysis_ready"

    status = report._classify_readiness_level(
        static_plan_present=True,
        identity_linked=False,
        apk_store_ready=False,
        dynamic_capture_ready=False,
        dynamic_evidence_present=False,
        analysis_ready=False,
        freeze_ready=False,
    )
    assert status == "static_plan_ready"


def test_match_baseline_for_plan_uses_repo_filename_pattern(tmp_path: Path) -> None:
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    target = baseline_dir / "com.example.app-full-all-20260613T001754Z.json"
    target.write_text("{}", encoding="utf-8")
    plan_path = tmp_path / "com.example.app-full-all-sr3393-20260613T001754Z.json"
    plan_path.write_text("{}", encoding="utf-8")
    assert report._match_baseline_for_plan(plan_path, baseline_dir) == str(target)


def test_main_generates_summary_contract_and_output_bundle_without_dynamic_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scytaledroid.Config import app_config

    repo_root = tmp_path / "repo"
    data_root = tmp_path / "data"
    output_root = tmp_path / "output"
    dynamic_plan_dir = data_root / "static_analysis" / "dynamic_plan"
    apk_store_dir = data_root / "store" / "apk" / "sha256"
    dynamic_plan_dir.mkdir(parents=True)
    apk_store_dir.mkdir(parents=True)

    sha = "ab" * 32
    store_path = data_root / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_bytes(b"apk")

    plan_path = dynamic_plan_dir / "com.example.app-full-all-sr123-20260613T001754Z.json"
    plan_path.write_text(
        json.dumps(
            {
                "package_name": "com.example.app",
                "static_run_id": 123,
                "run_identity": {
                    "static_run_id": 123,
                    "base_apk_sha256": sha,
                    "artifact_set_hash": "cd" * 32,
                    "static_handoff_hash": "ef" * 32,
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(app_config, "DATA_DIR", str(data_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(report, "_init_optional_db", lambda: ({}, set(), {}, [], None))
    monkeypatch.setattr(report, "_load_latest_paper_readiness", lambda _root: None)
    monkeypatch.setattr(report, "_load_static_run_evidence_index", lambda _root: {})

    out_dir = output_root / "audit" / "dynamic_readiness" / "contract-smoke"
    rc = report.main(["--output-dir", str(out_dir)])

    assert rc == 0
    summary_path = out_dir / "summary.json"
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    expected_keys = {
        "generated_at",
        "repo_root",
        "data_root",
        "dynamic_plan_count",
        "baseline_count",
        "dynamic_evidence_pack_count",
        "packages_with_dynamic_plan",
        "packages_with_baseline",
        "packages_with_complete_static_linkage",
        "packages_with_resolved_apk_store_identity",
        "packages_with_dynamic_evidence",
        "packages_analysis_ready",
        "packages_freeze_ready",
        "blocked_package_count",
        "top_blocker_types",
        "readiness_level_counts",
        "output_files",
        "warnings",
        "assumptions",
        "no_db_writes",
        "experimental_audit",
    }
    assert expected_keys.issubset(summary.keys())
    assert summary["dynamic_plan_count"] == 1
    assert summary["dynamic_evidence_pack_count"] == 0
    assert summary["blocked_package_count"] == 1
    assert summary["no_db_writes"] is True
    assert summary["experimental_audit"] is True
    assert summary["dynamic_plans_total"] == 1
    assert summary["dynamic_evidence_packs_total"] == 0
    assert isinstance(summary["readiness_level_counts"], dict)
    assert isinstance(summary["top_blocker_types"], list)
    assert "risk" not in summary_path.read_text(encoding="utf-8").lower()

    for name in summary["output_files"]:
        assert (out_dir / name).exists()

    header = (out_dir / "dynamic_readiness_matrix.csv").read_text(encoding="utf-8").splitlines()[0].lower()
    assert "risk" not in header


def test_main_marks_analysis_ready_when_expected_evidence_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scytaledroid.Config import app_config

    repo_root = tmp_path / "repo"
    data_root = tmp_path / "data"
    output_root = tmp_path / "output"
    dynamic_plan_dir = data_root / "static_analysis" / "dynamic_plan"
    baseline_dir = data_root / "static_analysis" / "baseline"
    dynamic_plan_dir.mkdir(parents=True)
    baseline_dir.mkdir(parents=True)

    sha = "12" * 32
    store_path = data_root / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_bytes(b"apk")

    plan_path = dynamic_plan_dir / "com.example.app-full-all-sr123-20260613T001754Z.json"
    plan_path.write_text(
        json.dumps(
            {
                "package_name": "com.example.app",
                "static_run_id": 123,
                "run_identity": {
                    "static_run_id": 123,
                    "base_apk_sha256": sha,
                    "artifact_set_hash": "34" * 32,
                    "static_handoff_hash": "56" * 32,
                },
            }
        ),
        encoding="utf-8",
    )
    (baseline_dir / "com.example.app-full-all-20260613T001754Z.json").write_text("{}", encoding="utf-8")

    baseline_pack = report.DynamicEvidencePack(
        dynamic_run_id="dyn-baseline",
        package_name="com.example.app",
        static_run_id=123,
        base_apk_sha256=sha,
        evidence_pack_path=str(output_root / "evidence" / "dynamic" / "dyn-baseline"),
        run_manifest_path="/tmp/run_manifest.json",
        static_dynamic_plan_path="/tmp/static_dynamic_plan.json",
        pcap_paths=("/tmp/baseline.pcap",),
        logcat_paths=("/tmp/baseline.txt",),
        pcap_features_present=True,
        static_dynamic_overlap_present=True,
        summary_present=True,
        pcap_report_present=True,
        window_params_present=True,
        threshold_present=True,
        rdi_derivable=True,
        freeze_stamped=False,
        run_mode="baseline",
        valid_dataset_run=True,
        paper_eligible=True,
        manifest_status="complete",
        missing_fields=tuple(),
    )
    interactive_pack = report.DynamicEvidencePack(
        dynamic_run_id="dyn-interactive",
        package_name="com.example.app",
        static_run_id=123,
        base_apk_sha256=sha,
        evidence_pack_path=str(output_root / "evidence" / "dynamic" / "dyn-interactive"),
        run_manifest_path="/tmp/run_manifest_interactive.json",
        static_dynamic_plan_path="/tmp/static_dynamic_plan_interactive.json",
        pcap_paths=("/tmp/interactive.pcap",),
        logcat_paths=("/tmp/interactive.txt",),
        pcap_features_present=True,
        static_dynamic_overlap_present=True,
        summary_present=True,
        pcap_report_present=True,
        window_params_present=True,
        threshold_present=True,
        rdi_derivable=True,
        freeze_stamped=False,
        run_mode="interactive",
        valid_dataset_run=True,
        paper_eligible=True,
        manifest_status="complete",
        missing_fields=tuple(),
    )

    monkeypatch.setattr(app_config, "DATA_DIR", str(data_root))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)
    monkeypatch.setattr(report, "_init_optional_db", lambda: ({}, {123}, {}, [], None))
    monkeypatch.setattr(report, "_load_latest_paper_readiness", lambda _root: None)
    monkeypatch.setattr(report, "_load_static_run_evidence_index", lambda _root: {})
    monkeypatch.setattr(
        report,
        "_scan_dynamic_evidence_packs",
        lambda _root: {
            baseline_pack.dynamic_run_id: baseline_pack,
            interactive_pack.dynamic_run_id: interactive_pack,
        },
    )

    out_dir = output_root / "audit" / "dynamic_readiness" / "analysis-ready"
    rc = report.main(["--output-dir", str(out_dir)])

    assert rc == 0
    rows = list(csv.DictReader((out_dir / "dynamic_readiness_matrix.csv").open(encoding="utf-8")))
    assert len(rows) == 1
    row = rows[0]
    assert row["package_name"] == "com.example.app"
    assert row["readiness_level"] == "analysis_ready"
    assert row["pcap_features_present"] == "1"
    assert row["static_dynamic_overlap_present"] == "1"

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["packages_analysis_ready"] == 1
    assert summary["readiness_level_counts"]["analysis_ready"] == 1
