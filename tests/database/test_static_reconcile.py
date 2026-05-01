from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Database.db_utils import static_reconcile


def test_reconcile_static_session_summarizes_missing_packages(tmp_path: Path, monkeypatch) -> None:
    reports_root = tmp_path / "static_analysis" / "reports" / "archive" / "sess"
    reports_root.mkdir(parents=True, exist_ok=True)
    (reports_root / "a.json").write_text(json.dumps({"normalized_package_name": "pkg.one"}), encoding="utf-8")
    (reports_root / "b.json").write_text(json.dumps({"package_name": "pkg.two"}), encoding="utf-8")

    monkeypatch.setattr(static_reconcile.app_config, "DATA_DIR", str(tmp_path))

    def _run_sql(sql, params=(), fetch=None, **_kwargs):
        session = params[0] if params else None
        if "FROM information_schema.COLUMNS" not in sql:
            assert session == "sess"
        if "COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND status='COMPLETED'" in sql:
            return (2,)
        if "COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND status='STARTED'" in sql:
            return (0,)
        if "COUNT(*) FROM static_analysis_runs WHERE session_label=%s AND status='FAILED'" in sql:
            return (0,)
        if "COUNT(*) FROM static_analysis_runs WHERE session_label=%s" in sql:
            return (2,)
        if "FROM static_analysis_findings" in sql:
            return (12,)
        if "FROM static_permission_matrix" in sql:
            return (7,)
        if "FROM static_permission_risk_vnext" in sql:
            return (7,)
        if "COUNT(*) FROM static_session_run_links WHERE session_stamp=%s" in sql:
            return (1,)
        if "FROM static_session_rollups WHERE session_stamp=%s" in sql:
            return (0,)
        if "static_handoff_json_path" in sql:
            return (2,)
        if "FROM information_schema.COLUMNS" in sql:
            return [
                ("runs", "package", "utf8mb4_general_ci"),
                ("static_session_run_links", "package_name", "latin1_swedish_ci"),
            ]
        if "SELECT a.package_name" in sql and "status='COMPLETED'" in sql:
            return [("pkg.one",), ("pkg.two",)]
        if "status='FAILED'" in sql:
            return []
        if "FROM static_findings_summary" in sql:
            return [("pkg.one",)]
        if "FROM static_string_summary" in sql:
            return [("pkg.one",), ("pkg.two",)]
        if "SELECT package FROM runs" in sql:
            return [("pkg.one",)]
        if "SELECT package_name FROM risk_scores" in sql:
            return [("pkg.one",)]
        if "FROM findings f" in sql:
            return [("pkg.one",)]
        if "FROM metrics m" in sql:
            return [("pkg.one",)]
        if "FROM buckets b" in sql:
            return [("pkg.one",)]
        if "FROM contributors c" in sql:
            return [("pkg.one",)]
        if "SELECT package_name FROM static_session_run_links WHERE session_stamp=%s" in sql:
            return [("pkg.one",)]
        if "FROM v_web_static_dynamic_app_summary WHERE latest_static_session_stamp=%s" in sql:
            return [("pkg.one",)]
        if "FROM web_static_dynamic_app_summary_cache WHERE latest_static_session_stamp=%s" in sql:
            return []
        raise AssertionError(sql)

    monkeypatch.setattr(static_reconcile.core_q, "run_sql", _run_sql)
    monkeypatch.setattr(static_reconcile, "static_dynamic_summary_cache_is_stale", lambda: True)

    summary = static_reconcile.reconcile_static_session("sess")

    assert summary.completed_runs == 2
    assert summary.report_files == 2
    assert summary.report_packages == 2
    assert summary.missing_session_links == {"pkg.two"}
    assert summary.missing_legacy_runs == {"pkg.two"}
    assert summary.missing_risk_scores == {"pkg.two"}
    assert summary.missing_findings_summary == {"pkg.two"}
    assert summary.missing_string_summary == set()
    assert summary.missing_report_packages == set()
    assert summary.web_view_packages == 1
    assert summary.web_cache_packages == 0
    assert summary.missing_web_view_packages == {"pkg.two"}
    assert summary.missing_web_cache_packages == {"pkg.one", "pkg.two"}
    assert summary.cache_stale is True
    assert summary.package_collations["runs.package"] == "utf8mb4_general_ci"
    assert any(risk.startswith("mixed_package_collations=") for risk in summary.collation_risks)


def test_repair_session_run_links_inserts_missing_rows(monkeypatch) -> None:
    queries: list[tuple[str, tuple[object, ...] | None, str | None]] = []

    def _run_sql(sql, params=(), fetch=None, **_kwargs):
        if "LEFT JOIN static_session_run_links" in sql:
            return [
                {
                    "package_name": "pkg.one",
                    "static_run_id": 101,
                    "pipeline_version": "2.0.0",
                    "run_signature": "sig1",
                    "run_signature_version": "v1",
                    "base_apk_sha256": "a" * 64,
                    "artifact_set_hash": "b" * 64,
                    "identity_valid": 1,
                    "identity_error_reason": None,
                }
            ]
        if "SELECT id FROM static_analysis_runs WHERE id IN" in sql:
            return [(101,)]
        raise AssertionError(sql)

    def _run_sql_write(sql, params=(), query_name=None, **_kwargs):
        queries.append((sql, tuple(params), query_name))
        return 1

    monkeypatch.setattr(static_reconcile.core_q, "run_sql", _run_sql)
    monkeypatch.setattr(static_reconcile.core_q, "run_sql_write", _run_sql_write)

    inserted = static_reconcile.repair_session_run_links("sess")

    assert inserted == 1
    assert queries
    sql, params, query_name = queries[0]
    assert "INSERT INTO static_session_run_links" in sql
    assert params[:3] == ("sess", "pkg.one", 101)
    assert query_name == "db_utils.static_reconcile.repair_session_run_links"


def test_write_reconcile_audit_writes_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(static_reconcile.app_config, "OUTPUT_DIR", str(tmp_path))
    summary = static_reconcile.StaticSessionReconcileSummary(
        session_label="sess",
        total_runs=2,
        completed_runs=2,
        started_runs=0,
        failed_runs=0,
        canonical_findings=1,
        canonical_permission_matrix=2,
        canonical_permission_risk=2,
        findings_summary_packages=2,
        string_summary_packages=2,
        legacy_runs_packages=2,
        legacy_risk_packages=2,
        secondary_compat_mirror_packages=2,
        session_run_links=2,
        session_rollups=1,
        handoff_paths=2,
        report_files=5,
        report_packages=2,
        completed_packages={"pkg.one", "pkg.two"},
        failed_packages=set(),
        missing_session_links=set(),
        missing_legacy_runs=set(),
        missing_risk_scores=set(),
        missing_secondary_compat_mirror_count=0,
        missing_findings_summary=set(),
        missing_string_summary=set(),
        missing_report_packages=set(),
        stale_report_only_packages=set(),
        web_view_packages=2,
        web_cache_packages=1,
        missing_web_view_packages=set(),
        missing_web_cache_packages={"pkg.two"},
        cache_stale=False,
        package_collations={"runs.package": "utf8mb4_general_ci"},
        collation_risks=[],
    )

    out = static_reconcile.write_reconcile_audit(summary)

    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["session_label"] == "sess"
    assert payload["summary"]["counts"]["reports"]["archive_json_files"] == 5
    assert payload["summary"]["counts"]["web"]["cache_packages"] == 1


def test_refresh_summary_cache_and_reconcile(monkeypatch) -> None:
    monkeypatch.setattr(static_reconcile, "refresh_static_dynamic_summary_cache", lambda: (77, object()))
    expected = static_reconcile.StaticSessionReconcileSummary(
        session_label="sess",
        total_runs=1,
        completed_runs=1,
        started_runs=0,
        failed_runs=0,
        canonical_findings=1,
        canonical_permission_matrix=1,
        canonical_permission_risk=1,
        findings_summary_packages=1,
        string_summary_packages=1,
        legacy_runs_packages=1,
        legacy_risk_packages=1,
        secondary_compat_mirror_packages=1,
        session_run_links=1,
        session_rollups=1,
        handoff_paths=1,
        report_files=1,
        report_packages=1,
        completed_packages={"pkg.one"},
        failed_packages=set(),
        missing_session_links=set(),
        missing_legacy_runs=set(),
        missing_risk_scores=set(),
        missing_secondary_compat_mirror_count=0,
        missing_findings_summary=set(),
        missing_string_summary=set(),
        missing_report_packages=set(),
        stale_report_only_packages=set(),
        web_view_packages=1,
        web_cache_packages=1,
        missing_web_view_packages=set(),
        missing_web_cache_packages=set(),
        cache_stale=False,
        package_collations={},
        collation_risks=[],
    )
    monkeypatch.setattr(static_reconcile, "reconcile_static_session", lambda session_label: expected)

    rebuilt, summary = static_reconcile.refresh_summary_cache_and_reconcile("sess")

    assert rebuilt == 77
    assert summary is expected
