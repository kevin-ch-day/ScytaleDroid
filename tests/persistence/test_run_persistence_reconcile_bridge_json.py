"""Reconcile overlay onto persistence audit bridge counts (legacy mirror per table)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit import (
    _empty_audit_summary,
    refresh_existing_persistence_audit_payload,
    refresh_persistence_audit_artifact,
)
from scytaledroid.StaticAnalysis.cli.flows.run_persistence_queries import _apply_reconcile_summary


def test_apply_reconcile_summary_maps_distinct_legacy_mirror_package_counts(monkeypatch) -> None:
    """Bridge JSON must not copy secondary_compat_mirror_packages into all three keys."""
    fake_reconcile = SimpleNamespace(
        completed_runs=2,
        started_runs=0,
        failed_runs=0,
        canonical_findings=99,
        canonical_permission_matrix=1,
        canonical_permission_risk=2,
        findings_summary_packages=3,
        string_summary_packages=4,
        handoff_paths=5,
        legacy_runs_packages=6,
        legacy_risk_packages=7,
        secondary_compat_mirror_packages=100,
        legacy_metrics_mirror_packages=3,
        legacy_buckets_mirror_packages=2,
        legacy_contributors_mirror_packages=7,
        session_run_links=9,
        session_rollups=10,
        missing_findings_summary=set(),
        missing_string_summary=set(),
        missing_legacy_runs=set(),
        missing_risk_scores=set(),
        missing_secondary_compat_mirror_count=0,
        bridge_only_runs=set(),
        bridge_only_risk_scores=set(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_queries.reconcile_static_session",
        lambda _session_label: fake_reconcile,
    )

    outcome = SimpleNamespace(
        canonical_failed=False,
        persistence_failed=False,
        compat_export_failed=False,
        compat_export_stage=None,
    )
    summary = _empty_audit_summary(
        session_label="sess-x",
        expected_packages=[],
        outcome=outcome,
        report_paths=[],
    )
    _apply_reconcile_summary(summary, "sess-x")

    bridge = summary["bridge"]
    assert bridge["metrics_packages"] == 3
    assert bridge["buckets_packages"] == 2
    assert bridge["contributors_packages"] == 7
    assert bridge["secondary_compat_mirror_packages"] == 100


def test_empty_audit_summary_uses_filesystem_archive_count(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    archive_dir = tmp_path / "data" / "static_analysis" / "reports" / "archive" / "sess-fs"
    archive_dir.mkdir(parents=True, exist_ok=True)
    (archive_dir / "a.json").write_text("{}", encoding="utf-8")
    (archive_dir / "b.json").write_text("{}", encoding="utf-8")

    outcome = SimpleNamespace(
        canonical_failed=False,
        persistence_failed=False,
        compat_export_failed=False,
        compat_export_stage=None,
    )
    summary = _empty_audit_summary(
        session_label="sess-fs",
        expected_packages=[],
        outcome=outcome,
        report_paths=["data/static_analysis/reports/latest/example.json"],
    )

    reports = summary["reports"]
    assert reports["latest_json_paths"] == 1
    assert reports["recorded_archive_json_paths"] == 0
    assert reports["archive_json_paths"] == 2
    assert reports["archive_present"] is True
    assert Path(reports["archive_dir"]).name == "sess-fs"


def test_refresh_existing_persistence_audit_payload_rebuilds_summary(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    archive_dir = tmp_path / "data" / "static_analysis" / "reports" / "archive" / "sess-refresh"
    archive_dir.mkdir(parents=True, exist_ok=True)
    for name in ("a.json", "b.json", "c.json"):
        (archive_dir / name).write_text("{}", encoding="utf-8")

    fake_reconcile = SimpleNamespace(
        completed_runs=2,
        started_runs=0,
        failed_runs=0,
        canonical_findings=10,
        canonical_permission_matrix=1,
        canonical_permission_risk=1,
        findings_summary_packages=2,
        string_summary_packages=2,
        handoff_paths=2,
        legacy_runs_packages=0,
        legacy_risk_packages=0,
        secondary_compat_mirror_packages=0,
        legacy_metrics_mirror_packages=0,
        legacy_buckets_mirror_packages=0,
        legacy_contributors_mirror_packages=0,
        session_run_links=2,
        session_rollups=1,
        missing_findings_summary=set(),
        missing_string_summary=set(),
        missing_legacy_runs=set(),
        missing_risk_scores=set(),
        missing_secondary_compat_mirror_count=0,
        bridge_only_runs=set(),
        bridge_only_risk_scores=set(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_queries.reconcile_static_session",
        lambda _session_label: fake_reconcile,
    )

    payload = {
        "session_stamp": "sess-refresh",
        "outcome": {
            "canonical_failed": False,
            "persistence_failed": False,
            "compat_export_failed": False,
            "compat_export_stage": None,
        },
        "rows": [
            {"package_name": "pkg.alpha", "artifact_reports": 2},
            {"package_name": "pkg.beta", "artifact_reports": 3},
        ],
        "summary": {
            "reports": {
                "json_report_paths": 5,
                "latest_json_paths": 5,
            }
        },
    }

    refreshed = refresh_existing_persistence_audit_payload(payload)

    reports = refreshed["summary"]["reports"]
    assert reports["json_report_paths"] == 5
    assert reports["latest_json_paths"] == 5
    assert reports["recorded_archive_json_paths"] == 0
    assert reports["archive_json_paths"] == 3
    assert reports["archive_present"] is True
    assert refreshed["summary_refresh_source"] == "db_and_filesystem_rebuild"
    assert refreshed["summary_refreshed_at_utc"]
    assert refreshed["summary"]["canonical"]["baseline_runs"] == 2
    assert refreshed["summary"]["bridge"]["session_rollups"] == 1


def test_refresh_persistence_audit_artifact_writes_updated_summary(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    archive_dir = tmp_path / "data" / "static_analysis" / "reports" / "archive" / "sess-write"
    archive_dir.mkdir(parents=True, exist_ok=True)
    (archive_dir / "a.json").write_text("{}", encoding="utf-8")

    fake_reconcile = SimpleNamespace(
        completed_runs=1,
        started_runs=0,
        failed_runs=0,
        canonical_findings=1,
        canonical_permission_matrix=0,
        canonical_permission_risk=0,
        findings_summary_packages=1,
        string_summary_packages=1,
        handoff_paths=1,
        legacy_runs_packages=0,
        legacy_risk_packages=0,
        secondary_compat_mirror_packages=0,
        legacy_metrics_mirror_packages=0,
        legacy_buckets_mirror_packages=0,
        legacy_contributors_mirror_packages=0,
        session_run_links=1,
        session_rollups=1,
        missing_findings_summary=set(),
        missing_string_summary=set(),
        missing_legacy_runs=set(),
        missing_risk_scores=set(),
        missing_secondary_compat_mirror_count=0,
        bridge_only_runs=set(),
        bridge_only_risk_scores=set(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_queries.reconcile_static_session",
        lambda _session_label: fake_reconcile,
    )

    path = tmp_path / "audit.json"
    path.write_text(
        json.dumps(
            {
                "session_stamp": "sess-write",
                "outcome": {"canonical_failed": False, "persistence_failed": False},
                "rows": [{"package_name": "pkg.alpha", "artifact_reports": 1}],
                "summary": {"reports": {"json_report_paths": 1, "latest_json_paths": 1}},
            }
        ),
        encoding="utf-8",
    )

    refreshed = refresh_persistence_audit_artifact(path, write=True)
    written = json.loads(path.read_text(encoding="utf-8"))

    assert refreshed["summary"]["reports"]["archive_json_paths"] == 1
    assert written["summary"]["reports"]["archive_json_paths"] == 1
    assert written["summary_refresh_source"] == "db_and_filesystem_rebuild"


def test_refresh_existing_persistence_audit_payload_survives_reconcile_failure(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    archive_dir = tmp_path / "data" / "static_analysis" / "reports" / "archive" / "sess-offline"
    archive_dir.mkdir(parents=True, exist_ok=True)
    (archive_dir / "a.json").write_text("{}", encoding="utf-8")
    (archive_dir / "b.json").write_text("{}", encoding="utf-8")

    payload = {
        "session_stamp": "sess-offline",
        "outcome": {
            "canonical_failed": False,
            "persistence_failed": False,
            "compat_export_failed": False,
            "compat_export_stage": None,
        },
        "rows": [{"package_name": "pkg.alpha", "artifact_reports": 2}],
        "summary": {"reports": {"json_report_paths": 2, "latest_json_paths": 2}},
    }

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit._apply_reconcile_summary",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("db offline")),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit._apply_direct_summary_fallback",
        lambda *_a, **_k: None,
    )

    refreshed = refresh_existing_persistence_audit_payload(payload)

    assert refreshed["summary"]["reports"]["archive_json_paths"] == 2
    assert refreshed["summary"]["reports"]["archive_present"] is True
    assert refreshed["summary"]["canonical"]["run_statuses"] == {"COMPLETED": 1}
    assert refreshed["summary"]["reconciliation_error"] == "db offline"


def test_refresh_existing_persistence_audit_payload_empty_rows_keeps_status_unknown(monkeypatch) -> None:
    payload = {
        "session_stamp": "sess-empty",
        "outcome": {
            "canonical_failed": False,
            "persistence_failed": False,
            "compat_export_failed": False,
            "compat_export_stage": None,
        },
        "rows": [],
        "summary": {"reports": {"json_report_paths": 0, "latest_json_paths": 0}},
    }

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit._apply_reconcile_summary",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("db offline")),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.run_persistence_audit._apply_direct_summary_fallback",
        lambda *_a, **_k: None,
    )

    refreshed = refresh_existing_persistence_audit_payload(payload)

    assert refreshed["summary"]["canonical"]["run_statuses"] == {}
    assert refreshed["summary"]["reconciliation_error"] == "db offline"
