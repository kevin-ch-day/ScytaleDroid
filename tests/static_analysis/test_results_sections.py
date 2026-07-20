from __future__ import annotations

import json

import pytest
from scytaledroid.StaticAnalysis.cli.execution.results_sections import (
    render_export_all_tables_section,
    render_permission_snapshot_summary_section,
    render_persistence_audit_summary_section,
    render_static_output_context,
)
from scytaledroid.StaticAnalysis.cli.execution.view import DetailBuffer

pytestmark = [pytest.mark.contract, pytest.mark.report_contract, pytest.mark.unit]


def test_render_static_output_context_compact_by_default(monkeypatch, capsys):
    monkeypatch.delenv("SCYTALEDROID_VERBOSE_RESULTS", raising=False)

    render_static_output_context(
        {
            "session_id": "sess-compact",
            "device_serial": "ZY22JK89DR",
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical",
            "analyzed_apps": 1,
            "observed_artifacts": 12,
            "acquisition": {
                "harvested": 1,
                "persisted": 1,
                "blocked_policy": 0,
                "blocked_scope": 0,
            },
        }
    )

    out = capsys.readouterr().out

    assert "Run Context" in out
    assert "Session  : sess-compact" in out
    assert "Analyzed : 1 app(s), 12 artifact(s)" in out
    assert "Stage Context" not in out
    assert "Acquisition Counters" not in out
    assert "Device reality" not in out


def test_render_persistence_audit_summary_section_displays_reconciliation(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    audit_path = tmp_path / "output" / "audit" / "persistence" / "sess-audit_persistence_audit.json"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(
        """
        {
          "schema_version": "v2",
          "total_apps": 120,
          "summary": {
            "outcome": {
              "canonical_failed": false,
              "persistence_failed": false,
              "compat_export_failed": true,
              "compat_export_stage": "run.create"
            },
            "canonical": {
              "run_statuses": {"COMPLETED": 120},
              "findings": 3368,
              "permission_matrix": 4947,
              "permission_risk": 4947,
              "handoff_paths": 120
            },
            "bridge": {
              "runs": 120,
              "risk_scores": 120,
              "metrics_packages": 120,
              "buckets_packages": 120,
              "contributors_packages": 120
            },
            "reconciliation": {
              "missing_legacy_runs_count": 0,
              "missing_findings_summary_count": 0
            },
            "reports": {
              "json_report_paths": 120,
              "latest_json_paths": 120,
              "recorded_archive_json_paths": 0,
              "archive_json_paths": 120,
              "archive_dir": "data/static_analysis/reports/archive/sess-audit"
            }
          }
        }
        """.strip(),
        encoding="utf-8",
    )

    render_persistence_audit_summary_section("sess-audit")

    out = capsys.readouterr().out
    assert "Persistence audit summary" in out
    assert "Schema   : v2" in out
    assert "Outcome  : canonical_failed=False persistence_failed=False compat_export_failed=True" in out
    assert "Compat stage (export): run.create" in out
    assert "Canonical persistence" in out
    assert "Run statuses      : {'COMPLETED': 120}" in out
    assert "Findings (rows)   : 3368" in out
    assert "Compatibility / derived surfaces" in out
    assert "risk_scores remains an active permission-posture session surface on the core DB." in out
    assert "Reports" in out
    assert "Recorded under latest/    : 120" in out
    assert "Recorded under archive/   : 0" in out
    assert "Filesystem archive count  : 120" in out
    assert "Gaps     : none" in out


def test_render_export_all_tables_section_lists_known_paths(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    audit_path = tmp_path / "output" / "audit" / "persistence" / "sess-export_persistence_audit.json"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text("{}", encoding="utf-8")
    snapshot_path = tmp_path / "data" / "audit" / "perm-audit_app_sess-export" / "snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text("{}", encoding="utf-8")

    render_export_all_tables_section("sess-export")

    out = capsys.readouterr().out
    assert "Normalized findings CSV : output/tables/sess-export_normalized_findings.csv" in out
    assert "Persistence audit       : output/audit/persistence/sess-export_persistence_audit.json" in out
    assert "Permission snapshot     : data/audit/perm-audit_app_sess-export/snapshot.json" in out
    assert "Selection manifest" not in out


def test_render_permission_snapshot_summary_uses_nested_permission_prevalence(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    session = "sess-nested"
    snapshot_path = tmp_path / "data" / "audit" / "perm-audit_app_sess-nested" / "snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(
        json.dumps(
            {
                "inventory": {
                    "apps_total": 1,
                    "apps_in_scope": 1,
                    "cohort_counts": {"User": 1},
                },
                "permission_prevalence": {
                    "permissions": [
                        {"name": "android.permission.CAMERA"},
                        {"name": "android.permission.RECORD_AUDIO"},
                    ],
                    "signals": [{"name": "overlay_risk"}],
                },
            }
        ),
        encoding="utf-8",
    )

    render_permission_snapshot_summary_section(session)

    out = capsys.readouterr().out
    assert "Distinct permission names (session rollup) : 2" in out
    assert "Distinct signal names (session rollup)     : 1" in out


def test_render_permission_snapshot_summary_legacy_top_level_keys(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    session = "sess-legacy"
    snapshot_path = tmp_path / "data" / "audit" / "perm-audit_app_sess-legacy" / "snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(
        json.dumps(
            {
                "inventory": {"apps_total": 1, "apps_in_scope": 1},
                "permissions": [{"name": "android.permission.READ_CONTACTS"}],
                "signals": [],
            }
        ),
        encoding="utf-8",
    )

    render_permission_snapshot_summary_section(session)

    out = capsys.readouterr().out
    assert "Distinct permission names (session rollup) : 1" in out
    assert "Distinct signal names (session rollup)     : 0" in out


def test_detail_buffer_compacts_leading_and_repeated_blank_lines() -> None:
    buffer = DetailBuffer()
    buffer.add("")
    buffer.add("")
    buffer.add("Normalized findings")
    buffer.add("")
    buffer.add("")
    buffer.add("Permission matrix")
    buffer.add("")

    assert buffer.compact_lines() == [
        "Normalized findings",
        "",
        "Permission matrix",
    ]
