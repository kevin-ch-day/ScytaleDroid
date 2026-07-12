from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from scripts.db import report_harvest_path_stale_audit as report


def _receipt_payload(
    *,
    package_name: str,
    session_label: str,
    app_label: str = "Example App",
    device_serial: str = "SER123",
    version_code: str = "1",
    version_name: str = "1.0",
    snapshot_id: int = 10,
    snapshot_captured_at: str = "2026-06-13T10:00:00Z",
    generated_at_utc: str = "2026-06-13T10:10:00Z",
    apk_paths: list[str] | None = None,
    split_count: int = 1,
    preflight_reason: str | None = None,
    capture_status: str = "clean",
    stale_replan: dict[str, object] | None = None,
    errors: list[dict[str, str]] | None = None,
    runtime_skips: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema": "harvest_package_manifest_v1",
        "generated_at_utc": generated_at_utc,
        "package": {
            "package_name": package_name,
            "app_label": app_label,
            "version_name": version_name,
            "version_code": version_code,
            "device_serial": device_serial,
            "snapshot_id": snapshot_id,
            "snapshot_captured_at": snapshot_captured_at,
            "session_label": session_label,
        },
        "inventory": {
            "primary_path": (apk_paths or ["/data/app/base.apk"])[0],
            "apk_paths": apk_paths or ["/data/app/base.apk"],
            "split_count": split_count,
        },
        "planning": {
            "preflight_reason": preflight_reason,
            "expected_artifacts": [
                {
                    "is_base": True,
                    "planned_source_path": (apk_paths or ["/data/app/base.apk"])[0],
                }
            ],
        },
        "execution": {
            "errors": errors or [],
            "runtime_skips": runtime_skips or [],
            "stale_replan": stale_replan,
            "observed_artifacts": [],
            "drift_reasons": [],
            "mirror_failure_reasons": [],
        },
        "status": {
            "capture_status": capture_status,
            "research_status": "pending_audit",
        },
        "paths": {
            "legacy_manifest_path": f"data/device_apks/{device_serial}/runs/{session_label}/{package_name}/harvest_package_manifest.json",
            "receipt_path": f"data/receipts/harvest/{session_label}/{package_name}.json",
        },
    }


def test_help_is_safe_without_pythonpath() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_harvest_path_stale_audit.py"
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
    assert "--receipt-root" in out
    assert "harvest path-stale" in out


def test_snapshot_age_bucket_boundaries() -> None:
    assert report._snapshot_age_bucket(None) == "unknown"
    assert report._snapshot_age_bucket(30) == "0-15m"
    assert report._snapshot_age_bucket(1800) == "15m-1h"
    assert report._snapshot_age_bucket(3600) == "1h-6h"
    assert report._snapshot_age_bucket(7 * 3600) == "6h-24h"
    assert report._snapshot_age_bucket(25 * 3600) == "24h+"


def test_split_shape_classification() -> None:
    assert report._split_shape(1, None) == "base_only"
    assert report._split_shape(2, None) == "base_plus_splits"
    assert report._split_shape(None, 3) == "base_plus_splits"
    assert report._split_shape(None, None) == "unknown"


def test_path_stale_outcome_parses_new_execution_block() -> None:
    payload = _receipt_payload(
        package_name="com.example.new",
        session_label="RUN1",
        stale_replan={
            "required": True,
            "outcome": "path_stale_package_paths_changed_since_inventory",
            "details": {
                "drift_reasons": ["artifact_set_changed"],
                "refreshed_primary_path": "/data/app/base_new.apk",
            },
        },
        capture_status="drifted",
    )

    assert report._path_stale_outcome(payload) == "path_stale_package_paths_changed_since_inventory"
    row = report._event_row(
        payload=payload,
        source_kind="receipt",
        source_path=Path("/repo/data/receipts/harvest/RUN1/com.example.new.json"),
        inventory_index={
            ("SER123", 10): "data/state/SER123/inventory/inventory_20260613-100000.json"
        },
    )
    assert row is not None
    assert row["path_set_changed"] == 1
    assert row["replan_success"] == 1
    assert row["replan_failed"] == 0


def test_path_stale_outcome_parses_legacy_receipt() -> None:
    payload = _receipt_payload(
        package_name="com.example.legacy",
        session_label="RUN1",
        errors=[{"source_path": "/data/app/base.apk", "reason": "path_stale"}],
    )

    assert report._path_stale_outcome(payload) == "legacy_or_unknown_path_stale"


def test_event_row_classifies_package_updated_since_inventory() -> None:
    payload = _receipt_payload(
        package_name="com.example.updated",
        session_label="RUN2",
        stale_replan={
            "required": True,
            "outcome": "path_stale_package_updated_since_inventory",
            "details": {
                "drift_reasons": ["version_code_changed", "artifact_set_changed"],
                "refreshed_version_code": "2",
                "refreshed_version_name": "2.0",
                "refreshed_primary_path": "/data/app/base.apk",
                "refreshed_apk_paths": ["/data/app/base.apk", "/data/app/split.apk"],
                "refreshed_split_count": 2,
            },
        },
        split_count=2,
        apk_paths=["/data/app/base_old.apk", "/data/app/split_old.apk"],
        capture_status="drifted",
    )

    row = report._event_row(
        payload=payload,
        source_kind="receipt",
        source_path=Path("/repo/data/receipts/harvest/RUN2/com.example.updated.json"),
        inventory_index={},
    )
    assert row is not None
    assert row["version_code_changed"] == 1
    assert row["version_name_changed"] == 1
    assert row["split_apk_package"] == 1
    assert row["package_shape"] == "base_plus_splits"
    assert row["package_recovered_after_replan"] == 0


def test_event_row_counts_clean_package_updated_replan_as_recovered() -> None:
    payload = _receipt_payload(
        package_name="com.example.updatedclean",
        session_label="RUN2",
        stale_replan={
            "required": True,
            "outcome": "path_stale_package_updated_since_inventory",
            "details": {
                "drift_reasons": ["version_code_changed", "artifact_set_changed"],
                "refreshed_version_code": "2",
                "refreshed_version_name": "2.0",
                "refreshed_primary_path": "/data/app/base.apk",
                "refreshed_apk_paths": ["/data/app/base.apk", "/data/app/split.apk"],
                "refreshed_split_count": 2,
            },
        },
        split_count=2,
        apk_paths=["/data/app/base_old.apk", "/data/app/split_old.apk"],
        capture_status="clean",
    )

    row = report._event_row(
        payload=payload,
        source_kind="receipt",
        source_path=Path("/repo/data/receipts/harvest/RUN2/com.example.updatedclean.json"),
        inventory_index={},
    )
    assert row is not None
    assert row["replan_success"] == 1
    assert row["package_recovered_after_replan"] == 1
    assert row["final_package_status"] == "clean"


def test_event_row_does_not_count_blocked_replan_as_recovered() -> None:
    payload = _receipt_payload(
        package_name="com.example.blocked",
        session_label="RUN2",
        stale_replan={
            "required": True,
            "outcome": "path_stale_blocked_before_pull",
            "details": {
                "refreshed_skip_reason": "policy_non_root",
                "refreshed_primary_path": "/system/app/Blocked/base.apk",
                "refreshed_apk_paths": ["/system/app/Blocked/base.apk"],
                "refreshed_split_count": 1,
            },
        },
        capture_status="clean",
    )

    row = report._event_row(
        payload=payload,
        source_kind="receipt",
        source_path=Path("/repo/data/receipts/harvest/RUN2/com.example.blocked.json"),
        inventory_index={},
    )

    assert row is not None
    assert row["replan_success"] == 1
    assert row["package_recovered_after_replan"] == 0


def test_recommendation_prefers_more_evidence_for_low_event_volume() -> None:
    rec = report._build_recommendation(
        records=[{"id": 1}, {"id": 2}],
        events=[{"replan_success": 1}, {"replan_success": 0}],
        package_rows=[],
        age_rows=[],
    )
    assert rec["recommended_action"] == "collect_more_live_harvest_evidence"


def test_main_generates_expected_output_files_and_counts(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    receipts_root = data_root / "receipts" / "harvest"
    state_root = data_root / "state" / "SER123" / "inventory"
    output_root = repo_root / "output"
    session_a = receipts_root / "RUN-A"
    session_b = receipts_root / "RUN-B"
    session_a.mkdir(parents=True)
    session_b.mkdir(parents=True)
    state_root.mkdir(parents=True)

    (state_root / "inventory_20260613-100000.meta.json").write_text(
        json.dumps({"snapshot_id": 10}),
        encoding="utf-8",
    )
    (state_root / "inventory_20260613-100000.json").write_text(
        json.dumps({"packages": []}),
        encoding="utf-8",
    )

    new_payload = _receipt_payload(
        package_name="com.example.one",
        session_label="RUN-A",
        stale_replan={
            "required": True,
            "outcome": "path_stale_refreshed_and_retried",
            "details": {
                "refreshed_primary_path": "/data/app/base.apk",
                "refreshed_apk_paths": ["/data/app/base.apk"],
                "refreshed_split_count": 1,
            },
        },
    )
    legacy_payload = _receipt_payload(
        package_name="com.example.two",
        session_label="RUN-B",
        generated_at_utc="2026-06-14T12:00:00Z",
        snapshot_captured_at="2026-06-13T10:00:00Z",
        errors=[{"source_path": "/data/app/base.apk", "reason": "path_stale"}],
        split_count=2,
        apk_paths=["/data/app/base.apk", "/data/app/split.apk"],
    )
    clean_payload = _receipt_payload(
        package_name="com.example.clean",
        session_label="RUN-B",
    )

    (session_a / "com.example.one.json").write_text(json.dumps(new_payload), encoding="utf-8")
    (session_b / "com.example.two.json").write_text(json.dumps(legacy_payload), encoding="utf-8")
    (session_b / "com.example.clean.json").write_text(json.dumps(clean_payload), encoding="utf-8")

    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)

    out_dir = output_root / "audit" / "harvest_path_stale" / "smoke"
    rc = report.main(["--output-dir", str(out_dir)])

    assert rc == 0
    expected = {
        "summary.json",
        "path_stale_events.csv",
        "path_stale_by_package.csv",
        "path_stale_by_session.csv",
        "replan_outcome_summary.csv",
        "snapshot_age_summary.csv",
        "split_apk_path_stale_summary.csv",
        "recommended_next_action.json",
    }
    assert expected == {path.name for path in out_dir.iterdir()}

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["harvest_session_count"] == 2
    assert summary["package_record_count"] == 3
    assert summary["path_stale_event_count"] == 2
    assert summary["replan_success_count"] == 1
    assert summary["replan_failed_count"] == 0
    assert "risk" not in (out_dir / "summary.json").read_text(encoding="utf-8").lower()

    event_rows = list(csv.DictReader((out_dir / "path_stale_events.csv").open(encoding="utf-8")))
    assert len(event_rows) == 2
    assert {row["stale_replan_outcome"] for row in event_rows} == {
        "path_stale_refreshed_and_retried",
        "legacy_or_unknown_path_stale",
    }

    package_rows = list(
        csv.DictReader((out_dir / "path_stale_by_package.csv").open(encoding="utf-8"))
    )
    assert {row["package_name"] for row in package_rows} == {"com.example.one", "com.example.two"}

    session_rows = list(
        csv.DictReader((out_dir / "path_stale_by_session.csv").open(encoding="utf-8"))
    )
    assert len(session_rows) == 2
    bucket_rows = list(
        csv.DictReader((out_dir / "snapshot_age_summary.csv").open(encoding="utf-8"))
    )
    assert {row["snapshot_age_bucket"] for row in bucket_rows} >= {"0-15m", "24h+", "unknown"}
    split_rows = list(
        csv.DictReader((out_dir / "split_apk_path_stale_summary.csv").open(encoding="utf-8"))
    )
    assert {row["package_shape"] for row in split_rows} == {
        "base_only",
        "base_plus_splits",
        "unknown",
    }

    recommendation = json.loads(
        (out_dir / "recommended_next_action.json").read_text(encoding="utf-8")
    )
    assert recommendation["recommended_action"] == "collect_more_live_harvest_evidence"


def test_main_can_scope_to_one_receipt_root(tmp_path: Path, monkeypatch) -> None:
    repo_root = tmp_path / "repo"
    data_root = repo_root / "data"
    receipts_root = data_root / "receipts" / "harvest"
    session_a = receipts_root / "RUN-A"
    session_b = receipts_root / "RUN-B"
    default_manifest_dir = data_root / "device_apks" / "SER123" / "runs" / "RUN-C" / "com.example.manifest"
    session_a.mkdir(parents=True)
    session_b.mkdir(parents=True)
    default_manifest_dir.mkdir(parents=True)

    stale_payload = _receipt_payload(
        package_name="com.example.one",
        session_label="RUN-A",
        stale_replan={
            "required": True,
            "outcome": "path_stale_refreshed_and_retried",
            "details": {
                "refreshed_primary_path": "/data/app/base.apk",
                "refreshed_apk_paths": ["/data/app/base.apk"],
                "refreshed_split_count": 1,
            },
        },
    )
    other_payload = _receipt_payload(
        package_name="com.example.two",
        session_label="RUN-B",
        errors=[{"source_path": "/data/app/base.apk", "reason": "path_stale"}],
    )
    manifest_payload = _receipt_payload(
        package_name="com.example.manifest",
        session_label="RUN-C",
        errors=[{"source_path": "/data/app/base.apk", "reason": "path_stale"}],
    )
    (session_a / "com.example.one.json").write_text(json.dumps(stale_payload), encoding="utf-8")
    (session_b / "com.example.two.json").write_text(json.dumps(other_payload), encoding="utf-8")
    (default_manifest_dir / "harvest_package_manifest.json").write_text(
        json.dumps(manifest_payload),
        encoding="utf-8",
    )

    monkeypatch.setattr(report, "_REPO_ROOT", repo_root)
    out_dir = repo_root / "output" / "audit" / "harvest_path_stale" / "scoped"
    rc = report.main(
        [
            "--receipt-root",
            str(session_a),
            "--output-dir",
            str(out_dir),
        ]
    )

    assert rc == 0
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["scan_scope"] == "scoped"
    assert summary["receipt_roots"] == ["data/receipts/harvest/RUN-A"]
    assert summary["package_record_count"] == 1
    assert summary["path_stale_event_count"] == 1
    event_rows = list(csv.DictReader((out_dir / "path_stale_events.csv").open(encoding="utf-8")))
    assert [row["package_name"] for row in event_rows] == ["com.example.one"]
