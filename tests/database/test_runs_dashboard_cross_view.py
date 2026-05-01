from __future__ import annotations

from scytaledroid.Database.db_utils.menus import runs_dashboard


def test_render_findings_summary_prefers_finding_surface_view_when_session_matches(
    monkeypatch, capsys
) -> None:
    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **_kwargs):
        if "FROM vw_static_finding_surfaces_latest" in query:
            return {
                "package_name": "org.example.app",
                "session_stamp": "20260415-all-full",
                "canonical_high": 4,
                "canonical_med": 3,
                "canonical_low": 2,
                "canonical_info": 1,
            }
        raise AssertionError("legacy static_findings_summary should not be queried")

    monkeypatch.setattr(runs_dashboard, "run_sql", fake_run_sql)

    runs_dashboard._render_findings_summary("20260415-all-full", "org.example.app")
    out = capsys.readouterr().out
    assert "findings: H4/M3/L2/I1" in out


def test_render_findings_summary_falls_back_to_canonical_query_when_view_session_differs(
    monkeypatch, capsys
) -> None:
    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **_kwargs):
        if "FROM vw_static_finding_surfaces_latest" in query:
            return {
                "package_name": "org.example.app",
                "session_stamp": "20260426-signal-light",
                "canonical_high": 9,
                "canonical_med": 9,
                "canonical_low": 9,
                "canonical_info": 9,
            }
        if "FROM static_analysis_findings" in query:
            return {
                "high": 1,
                "med": 2,
                "low": 3,
                "info": 4,
            }
        raise AssertionError(query)

    monkeypatch.setattr(runs_dashboard, "run_sql", fake_run_sql)

    runs_dashboard._render_findings_summary("20260415-all-full", "org.example.app")
    out = capsys.readouterr().out
    assert "findings: H1/M2/L3/I4" in out


def test_render_permission_snapshot_prefers_risk_surface_view(monkeypatch, capsys) -> None:
    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **_kwargs):
        if "FROM vw_static_risk_surfaces_latest" in query:
            return {
                "package_name": "org.example.app",
                "session_stamp": "20260415-all-full",
                "permission_audit_grade": "B",
                "permission_audit_score_capped": 47,
                "permission_audit_dangerous_count": 5,
                "permission_audit_signature_count": 2,
                "permission_audit_vendor_count": 1,
            }
        raise AssertionError("raw permission_audit_apps should not be queried")

    monkeypatch.setattr(runs_dashboard, "run_sql", fake_run_sql)

    runs_dashboard._render_permission_snapshot("20260415-all-full", "org.example.app")
    out = capsys.readouterr().out
    assert "score=47" in out
    assert "grade=B" in out
    assert "dangerous=5" in out
    assert "signature=2" in out
    assert "oem=1" in out


def test_render_findings_summary_falls_back_when_view_query_errors(monkeypatch, capsys) -> None:
    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **_kwargs):
        if "FROM vw_static_finding_surfaces_latest" in query:
            raise RuntimeError("view unavailable")
        if "FROM static_analysis_findings" in query:
            return {
                "high": 7,
                "med": 6,
                "low": 5,
                "info": 4,
            }
        raise AssertionError(query)

    monkeypatch.setattr(runs_dashboard, "run_sql", fake_run_sql)

    runs_dashboard._render_findings_summary("20260415-all-full", "org.example.app")
    out = capsys.readouterr().out
    assert "findings: H7/M6/L5/I4" in out


def test_render_permission_snapshot_requires_session_match(monkeypatch, capsys) -> None:
    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **_kwargs):
        if "FROM vw_static_risk_surfaces_latest" in query:
            return {
                "package_name": "org.example.app",
                "session_stamp": "20260426-signal-light",
                "permission_audit_grade": "C",
                "permission_audit_score_capped": 11,
                "permission_audit_dangerous_count": 4,
                "permission_audit_signature_count": 3,
                "permission_audit_vendor_count": 2,
            }
        raise AssertionError(query)

    monkeypatch.setattr(runs_dashboard, "run_sql", fake_run_sql)

    runs_dashboard._render_permission_snapshot("20260415-all-full", "org.example.app")
    out = capsys.readouterr().out
    assert "not linked to this session" in out


def test_render_permission_snapshot_reports_no_snapshot_when_view_query_errors(
    monkeypatch, capsys
) -> None:
    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **_kwargs):
        if "FROM vw_static_risk_surfaces_latest" in query:
            raise RuntimeError("view unavailable")
        raise AssertionError(query)

    monkeypatch.setattr(runs_dashboard, "run_sql", fake_run_sql)

    runs_dashboard._render_permission_snapshot("20260415-all-full", "org.example.app")
    out = capsys.readouterr().out
    assert "perm-audit (latest): (no snapshot)" in out
