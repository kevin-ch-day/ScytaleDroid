from __future__ import annotations

import pytest

from scytaledroid.StaticAnalysis.cli.execution import results

from tests.static_analysis._results_support import (
    make_app_result,
    make_outcome,
    make_params,
)


pytestmark = [pytest.mark.contract, pytest.mark.report_contract, pytest.mark.unit]


def test_build_run_results_view_model_resolves_session_and_grade(monkeypatch, tmp_path):
    app_result = make_app_result(
        tmp_path=tmp_path,
        package_name="pkg.example",
        app_label="Example App",
        version_name="1.2.3",
        version_code=42,
        base_apk_sha256="abc123",
    )
    outcome = make_outcome(
        tmp_path=tmp_path,
        app_results=[app_result],
        failures=["some_failure"],
    )
    params = make_params(
        session_stamp="sess-123",
        session_label="session-alpha",
        persistence_ready=False,
        dry_run=False,
    )

    def _run_sql(query, params=None, fetch=None):
        del params, fetch
        sql = " ".join(str(query).split()).lower()
        if "count(*) from static_analysis_runs" in sql:
            return (3,)
        if "min(id)" in sql and "static_analysis_runs" in sql:
            return (700,)
        if "where session_label=%s and is_canonical=1" in sql:
            return (718,)
        if "where session_label=%s" in sql and "order by id desc" in sql:
            return (719,)
        raise AssertionError(f"unexpected query: {sql}")

    monkeypatch.setattr(results.core_q, "run_sql", _run_sql)
    monkeypatch.setattr(
        results,
        "_collect_static_output_context",
        lambda *_a, **_k: {
            "session_id": "session-alpha",
            "device_serial": "ZY22JK89DR",
            "snapshot_id": 26,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical / non-root",
            "analyzed_apps": 1,
            "planned_artifacts": 1,
            "observed_artifacts": 1,
            "acquisition": {},
        },
    )

    view_model = results.build_run_results_view_model(
        outcome,
        params,
        totals={"high": 2, "critical": 0},
        artifact_count=1,
    )

    assert view_model.title == "Static analysis summary"
    assert str(view_model.subtitle) == "Full • Scope: All apps • Session: session-alpha"
    assert view_model.session_meta.attempts == 3
    assert view_model.session_meta.canonical_id == 718
    assert view_model.session_meta.latest_id == 719
    assert view_model.session_meta.first_static_run_id == 700
    assert "Result set: Experimental" in str(view_model.footer)
    assert "persistence gate failed" in str(view_model.footer)
    assert "run failures present" in str(view_model.footer)
    assert view_model.version_line == "Version: 1.2.3 (42) • SHA-256: abc123"
    assert view_model.planned_artifacts == 1
    assert view_model.observed_artifacts == 1


def test_build_run_results_view_model_skips_session_db_lookups_for_dry_run(monkeypatch, tmp_path):
    outcome = make_outcome(
        tmp_path=tmp_path,
        app_results=[],
    )
    params = make_params(
        session_stamp="sess-dry",
        dry_run=True,
    )

    def _fail_run_sql(*_args, **_kwargs):
        raise AssertionError("DB lookup should not run for dry-run session metadata")

    monkeypatch.setattr(results.core_q, "run_sql", _fail_run_sql)
    monkeypatch.setattr(
        results,
        "_collect_static_output_context",
        lambda *_a, **_k: {
            "session_id": "sess-dry",
            "device_serial": None,
            "snapshot_id": None,
            "scope_analyzed": "Harvested APK artifacts only",
            "mode_label": "Canonical",
            "analyzed_apps": 0,
            "planned_artifacts": 0,
            "observed_artifacts": 0,
            "acquisition": {},
        },
    )

    view_model = results.build_run_results_view_model(
        outcome,
        params,
        totals={"high": 0, "critical": 0},
        artifact_count=0,
    )

    assert "Session: sess-dry" in str(view_model.subtitle)
    assert view_model.session_meta.attempts is None
    assert view_model.session_meta.canonical_id is None
    assert view_model.session_meta.latest_id is None
