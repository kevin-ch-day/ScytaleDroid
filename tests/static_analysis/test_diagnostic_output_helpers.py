from __future__ import annotations

from datetime import UTC
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import (
    db_masvs_summary,
    db_severity_table,
    db_verification,
    diagnostics,
    results_formatters,
)
from scytaledroid.Database.db_scripts import static_run_audit
from scytaledroid.StaticAnalysis.cli.persistence.reports import masvs_summary_report
from scytaledroid.Utils.System import output_prefs


def test_hash_prefix_short_value():
    assert results_formatters._hash_prefix("abcd") == "abcd"


def test_hash_prefix_long_value():
    assert results_formatters._hash_prefix("0123456789abcdef") == "0123…cdef"


def test_static_run_audit_derives_non_com_package_from_scope_label():
    assert static_run_audit._derive_package("Signal | org.thoughtcrime.securesms") == "org.thoughtcrime.securesms"
    assert static_run_audit._derive_package("org.thoughtcrime.securesms") == "org.thoughtcrime.securesms"
    assert static_run_audit._derive_package("All apps") is None


def test_static_run_audit_counts_permission_matrix_by_static_run_id():
    class _Cursor:
        def __init__(self):
            self.last_sql = None
            self.last_params = None

        def execute(self, sql, params=()):
            self.last_sql = sql
            self.last_params = params

        def fetchone(self):
            return (74,)

    cursor = _Cursor()
    table, count, status = static_run_audit._count_for_table(
        cursor,
        "static_permission_matrix",
        run_id=999,
        static_run_id=555,
        session="sess",
        static_run_ids=[555],
        is_group_scope=False,
    )
    assert table == "static_permission_matrix"
    assert count == 74
    assert status == "OK"
    assert "WHERE run_id IN" in (cursor.last_sql or "")
    assert cursor.last_params == (555,)


def test_group_diagnostic_warnings_dedupes():
    warnings = [
        ("Linkage", "pkg.alpha", "UNAVAILABLE: no run_map; no db link"),
        ("Linkage", "pkg.beta", "UNAVAILABLE: no run_map; no db link"),
        ("Identity", "pkg.alpha", "missing split"),
        ("Identity", "pkg.alpha", "missing split"),
    ]
    lines = diagnostics._group_diagnostic_warnings(warnings, max_packages=3)
    assert any("Linkage UNAVAILABLE: no run_map; no db link" in line for line in lines)
    assert any("Identity missing split" in line for line in lines)


def test_plan_provenance_requires_runids():
    lines = diagnostics._plan_provenance_lines(
        run_id_states=[True, False, True],
        run_signature_ok=True,
        artifact_set_ok=True,
    )
    assert lines[0].startswith("FAIL static_run_id present")
    assert any("resolve linkage" in line for line in lines)


def test_diagnostic_summary_populates_runid_for_db_lookup(monkeypatch):
    from datetime import datetime
    from pathlib import Path

    from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, ScopeSelection

    app = AppRunResult(package_name="com.example.app", category="test")
    app.app_label = "Example"
    app.run_signature = "sig"
    app.run_signature_version = "v1"
    app.identity_valid = True
    app.base_apk_sha256 = "a" * 64
    app.artifact_set_hash = "b" * 64
    app.discovered_artifacts = 1
    app.executed_artifacts = 1
    app.persisted_artifacts = 0

    outcome = RunOutcome(
        results=[app],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        scope=ScopeSelection("profile", "Test", tuple()),
        base_dir=Path("."),
    )

    monkeypatch.setattr(diagnostics, "load_run_map", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(diagnostics, "_fetch_db_linkage", lambda *_args, **_kwargs: (None, None))
    monkeypatch.setattr(
        diagnostics,
        "_fetch_db_linkage_by_signature",
        lambda *_args, **_kwargs: (
            {
                "static_run_id": 42,
                "pipeline_version": "2.0.0-alpha",
                "run_signature": "sig",
                "run_signature_version": "v1",
            },
            None,
        ),
    )

    captured: list[tuple[list[str], list[list[str]]]] = []

    def fake_render_table(headers, rows, *args, **kwargs):
        captured.append((headers, rows))

    monkeypatch.setattr(diagnostics.table_utils, "render_table", fake_render_table)

    diagnostics._render_diagnostic_app_summary(
        outcome,
        session_stamp="20260130-000000",
        compact_mode=True,
    )

    assert captured
    headers, rows = captured[0]
    assert headers[-2:] == ["RunID", "Sig"]
    assert rows[0][-2] == "42"
    assert rows[0][-1] == "sig"


def test_render_persistence_footer_prints_canonical_and_latest(monkeypatch, capsys):
    def fake_run_sql(query, params=None, fetch=None):
        sql = " ".join(str(query).split()).lower()
        if "select run_id from runs where session_stamp" in sql:
            return [(1,)]
        if "select id, coalesce" in sql:
            return [
                (719, "2026-02-05 00:00:00", 1, "COMPLETED", ""),
                (718, "2026-02-05 00:00:00", 0, "COMPLETED", ""),
            ]
        if "select session_label" in sql:
            return ("static-tiktok-20260205",)
        if "count(*) from static_analysis_runs" in sql:
            return (3,)
        if "where session_label" in sql and "is_canonical=1" in sql:
            return (718,)
        if "where session_label" in sql and "order by id desc" in sql:
            return (719,)
        return (0,)

    monkeypatch.setattr(db_verification.core_q, "run_sql", fake_run_sql)
    monkeypatch.setattr(db_verification, "_resolve_static_run_ids", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(db_verification, "collect_static_run_counts", lambda *_args, **_kwargs: None)

    db_verification._render_persistence_footer("20260205-000000")
    out = capsys.readouterr().out
    assert "canonical" in out
    assert "static_run_id=718" in out
    assert "latest" in out
    assert "static_run_id=719" in out
    assert "static_run.status=COMPLETED" in out


def test_render_db_masvs_summary_aggregates_all_static_ids(monkeypatch, capsys):
    class _Ctx:
        persistence_ready = True
        session_stamp = "sess-agg"

    monkeypatch.setattr(output_prefs, "get_run_context", lambda: _Ctx())
    monkeypatch.setattr(db_masvs_summary, "resolve_static_run_ids", lambda *_a, **_k: [41, 40, 39])

    calls = {"many": 0, "fallback": 0}

    def _many(ids):
        calls["many"] += 1
        assert ids == [41, 40, 39]
        return (
            41,
            [
                {
                    "area": "NETWORK",
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                    "cvss": {
                        "worst_score": 7.5,
                        "worst_severity": "High",
                        "worst_identifier": "correlation_engine",
                        "average_score": 7.5,
                        "band_counts": {"High": 1},
                    },
                    "quality": {"coverage_status": "ok"},
                }
            ],
        )

    def _fallback(*_a, **_k):
        calls["fallback"] += 1
        return None

    monkeypatch.setattr(db_masvs_summary, "fetch_db_masvs_summary_static_many", _many)
    monkeypatch.setattr(db_masvs_summary, "fetch_db_masvs_summary", _fallback)
    monkeypatch.setattr(db_masvs_summary, "compact_success_output_enabled", lambda: False)

    db_masvs_summary.render_db_masvs_summary()

    out = capsys.readouterr().out
    assert "DB MASVS Summary (latest_static_run_id=41; aggregated_runs=3)" in out
    assert calls["many"] == 1
    assert calls["fallback"] == 0


def test_render_db_severity_table_uses_canonical_target_sdk_lookup(monkeypatch):
    captured: list[tuple[list[str], list[list[str]]]] = []

    monkeypatch.setattr(db_severity_table, "resolve_static_run_ids", lambda *_args, **_kwargs: [42])
    monkeypatch.setattr(
        db_severity_table,
        "_per_app_severity_from_findings",
        lambda *_args, **_kwargs: [("org.thoughtcrime.securesms", "High", 1)],
    )

    def fake_run_sql(query, params=None, fetch=None, dictionary=False):
        sql = " ".join(str(query).split()).lower()
        if "from static_analysis_runs sar" in sql and "join app_versions av" in sql:
            return [{"package_name": "org.thoughtcrime.securesms", "target_sdk": 35}]
        raise AssertionError(f"unexpected SQL: {query}")

    monkeypatch.setattr(db_severity_table.core_q, "run_sql", fake_run_sql)
    monkeypatch.setattr(
        db_severity_table.table_utils,
        "render_table",
        lambda headers, rows, *args, **kwargs: captured.append((headers, rows)),
    )

    assert db_severity_table.render_db_severity_table("sess") is True
    assert captured
    assert captured[0][1][0][2] == "35"


def test_render_db_severity_table_limits_large_output_and_exports(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        db_severity_table,
        "resolve_static_run_ids",
        lambda *_args, **_kwargs: [42],
    )
    monkeypatch.setattr(
        db_severity_table,
        "_per_app_severity_from_findings",
        lambda *_args, **_kwargs: [
            (f"pkg.{idx:02d}", "High", idx) for idx in range(1, 26)
        ],
    )

    def fake_run_sql(query, params=None, fetch=None, dictionary=False):
        sql = " ".join(str(query).split()).lower()
        if "from static_analysis_runs sar" in sql and "join app_versions av" in sql:
            return [{"package_name": f"pkg.{idx:02d}", "target_sdk": 35} for idx in range(1, 26)]
        raise AssertionError(f"unexpected SQL: {query}")

    monkeypatch.setattr(db_severity_table.core_q, "run_sql", fake_run_sql)

    assert db_severity_table.render_db_severity_table("sess") is True
    out = capsys.readouterr().out
    assert "top 20 of 25 packages" in out
    assert "Full normalized findings table saved:" in out
    assert (tmp_path / "output" / "tables" / "sess_normalized_findings.csv").exists()


def test_fetch_masvs_matrix_prefers_canonical_latest_runs(monkeypatch):
    def fake_run_sql(query, params=None, fetch=None, dictionary=False):
        sql = " ".join(str(query).split()).lower()
        if "from static_analysis_runs sar" in sql and "preferred_static_run_id" in sql:
            return [
                {
                    "package_name": "org.thoughtcrime.securesms",
                    "app_label": "Signal",
                    "static_run_id": 42,
                    "session_stamp": "sess",
                    "scope_label": "Signal | org.thoughtcrime.securesms",
                    "version_name": "1.0",
                    "version_code": 100,
                    "target_sdk": 35,
                }
            ]
        if "from static_analysis_findings saf" in sql and "sum(case when lower(coalesce(saf.severity, '')) = 'high'" in sql:
            return [
                {
                    "static_run_id": 42,
                    "masvs": "NETWORK",
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                }
            ]
        if "from static_analysis_findings saf" in sql and "count(*) as occurrences" in sql:
            return [
                {
                    "static_run_id": 42,
                    "masvs": "NETWORK",
                    "severity": "High",
                    "identifier": "network_cleartext",
                    "occurrences": 1,
                }
            ]
        raise AssertionError(f"unexpected SQL: {query}")

    monkeypatch.setattr(masvs_summary_report.core_q, "run_sql", fake_run_sql)

    matrix = masvs_summary_report.fetch_masvs_matrix()
    signal = matrix["org.thoughtcrime.securesms"]
    assert signal["run_id"] == 42
    assert signal["status"]["NETWORK"] == "FAIL"
    assert signal["label"] == "Signal"
    assert signal["target_sdk"] == 35


def test_fetch_db_masvs_summary_static_many_prefers_canonical_findings(monkeypatch):
    def fake_run_sql(query, params=None, fetch=None, dictionary=False):
        sql = " ".join(str(query).split()).lower()
        if "from static_analysis_findings saf" in sql and "sum(case when lower(coalesce(saf.severity, ''))='high'" in sql:
            return [
                {"masvs": "PLATFORM", "high": 1, "medium": 2, "low": 0, "info": 0},
                {"masvs": "CRYPTO", "high": 0, "medium": 1, "low": 0, "info": 0},
            ]
        if "from static_analysis_findings saf" in sql and "saf.cvss_score as score" in sql:
            return [
                {"masvs": "PLATFORM", "score": 8.0, "identifier": "BASE-IPC-COMP-NO-ACL", "severity": "Medium"},
                {"masvs": "PLATFORM", "score": None, "identifier": "manifest_baseline", "severity": "High"},
                {"masvs": "CRYPTO", "score": 5.0, "identifier": "cipher_review", "severity": "Medium"},
            ]
        if "from static_analysis_findings saf" in sql and "count(*) as occurrences" in sql:
            return [
                {"masvs": "PLATFORM", "severity": "High", "identifier": "ipc_components", "occurrences": 1},
                {"masvs": "PLATFORM", "severity": "Medium", "identifier": "BASE-IPC-COMP-NO-ACL", "occurrences": 2},
                {"masvs": "CRYPTO", "severity": "Medium", "identifier": "cipher_review", "occurrences": 1},
            ]
        if "from findings" in sql or "from static_findings" in sql:
            raise AssertionError(f"unexpected legacy SQL: {query}")
        raise AssertionError(f"unexpected SQL: {query}")

    monkeypatch.setattr(masvs_summary_report.core_q, "run_sql", fake_run_sql)

    resolved, summary = masvs_summary_report.fetch_db_masvs_summary_static_many([42])
    assert resolved == 42
    platform = next(row for row in summary if row["area"] == "PLATFORM")
    crypto = next(row for row in summary if row["area"] == "CRYPTO")
    assert platform["high"] == 1
    assert platform["medium"] == 2
    assert platform["top_medium"]["descriptor"] == "BASE-IPC-COMP-NO-ACL"
    assert platform["cvss"]["worst_score"] == 8.0
    assert crypto["medium"] == 1
    assert crypto["cvss"]["worst_score"] == 5.0


def test_fetch_db_masvs_summary_prefers_linked_static_summary(monkeypatch):
    calls = {"static": 0}

    def fake_run_sql(query, params=None, fetch=None, dictionary=False):
        sql = " ".join(str(query).split()).lower()
        if "select distinct static_run_id from findings" in sql:
            return [(77,)]
        raise AssertionError(f"unexpected SQL: {query}")

    def fake_static(ids):
        calls["static"] += 1
        assert ids == [77]
        return (
            77,
            [
                {
                    "area": "PLATFORM",
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                    "cvss": {"worst_score": 8.0},
                    "quality": {"coverage_status": "ok"},
                }
            ],
        )

    monkeypatch.setattr(masvs_summary_report.core_q, "run_sql", fake_run_sql)
    monkeypatch.setattr(masvs_summary_report, "fetch_db_masvs_summary_static_many", fake_static)

    resolved, rows = masvs_summary_report.fetch_db_masvs_summary(501)
    assert resolved == 501
    assert calls["static"] == 1
    assert rows[0]["area"] == "PLATFORM"


def test_fetch_db_masvs_summary_none_does_not_touch_legacy_without_env(monkeypatch):
    def fake_run_sql(query, params=None, fetch=None, dictionary=False):
        sql = " ".join(str(query).split()).lower()
        if "from static_analysis_runs" in sql and "order by id desc limit 1" in sql:
            return None
        if "max(run_id)" in sql and "runs" in sql:
            raise AssertionError("legacy runs table must not be queried without SCYTALEDROID_ALLOW_LEGACY_MASVS_FALLBACK")
        raise AssertionError(f"unexpected SQL: {query}")

    monkeypatch.delenv("SCYTALEDROID_ALLOW_LEGACY_MASVS_FALLBACK", raising=False)
    monkeypatch.setattr(masvs_summary_report.core_q, "run_sql", fake_run_sql)

    assert masvs_summary_report.fetch_db_masvs_summary(None) is None


def test_render_persistence_footer_group_scope_ok_when_only_canonical_findings(monkeypatch, capsys):
    """Legacy ``runs`` / ``findings`` / ``buckets`` / ``metrics`` may be empty; session still OK."""
    audit = SimpleNamespace(
        counts={},
        is_group_scope=True,
        run_id=123,
        is_orphan=False,
        static_run_id=999,
    )

    def fake_run_sql(query, params=None, fetch=None):
        sql = " ".join(str(query).split()).lower()
        if "select run_id from runs where session_stamp" in sql:
            return []
        if "static_analysis_findings f" in sql and "join static_analysis_runs sar" in sql:
            return (2400,)
        if "select snapshot_id from permission_audit_snapshots where snapshot_key" in sql:
            return (1,)
        if "select count(*) from permission_audit_snapshots where static_run_id in" in sql:
            return (1,)
        if "select count(distinct snapshot_id) from permission_audit_apps where static_run_id in" in sql:
            return (1,)
        if "select count(*) from permission_audit_apps where static_run_id in" in sql:
            return (120,)
        if "from static_string_sample_sets" in sql:
            return None
        if "select count(*) from" in sql:
            return (10,)
        return (0,)

    monkeypatch.setattr(db_verification.core_q, "run_sql", fake_run_sql)
    monkeypatch.setattr(db_verification, "_resolve_static_run_ids", lambda *_args, **_kwargs: list(range(100, 220)))
    monkeypatch.setattr(db_verification, "collect_static_run_counts", lambda *_args, **_kwargs: audit)
    monkeypatch.setattr(db_verification, "_table_has_column", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(db_verification, "compact_success_output_enabled", lambda: False)

    db_verification._render_persistence_footer("20260502-all-full")
    out = capsys.readouterr().out
    assert "canonical_session_rows=2400" in out
    assert "db_verification" in out
    assert "ERROR (missing buckets, findings, metrics)" not in out
    assert "OK (canonical static persistence)" in out or "OK (group scope)" in out


def test_render_persistence_footer_derives_snapshot_count_from_permission_apps(monkeypatch, capsys):
    audit = SimpleNamespace(
        counts={},
        is_group_scope=True,
        run_id=123,
        is_orphan=False,
        static_run_id=41,
    )

    def fake_run_sql(query, params=None, fetch=None):
        sql = " ".join(str(query).split()).lower()
        if "select run_id from runs where session_stamp" in sql:
            return [(1,), (2,)]
        if "select snapshot_id from permission_audit_snapshots where snapshot_key" in sql:
            return None
        if "select count(*) from permission_audit_snapshots where static_run_id in" in sql:
            return (0,)
        if "select count(distinct snapshot_id) from permission_audit_apps where static_run_id in" in sql:
            return (4,)
        if "select count(*) from permission_audit_apps where static_run_id in" in sql:
            return (12,)
        if "from static_string_sample_sets" in sql:
            return None
        if "select count(*) from" in sql:
            return (0,)
        return (0,)

    monkeypatch.setattr(db_verification.core_q, "run_sql", fake_run_sql)
    monkeypatch.setattr(db_verification, "_resolve_static_run_ids", lambda *_args, **_kwargs: [41, 40, 39])
    monkeypatch.setattr(db_verification, "collect_static_run_counts", lambda *_args, **_kwargs: audit)
    monkeypatch.setattr(db_verification, "_table_has_column", lambda *_args, **_kwargs: True)

    db_verification._render_persistence_footer("sess-audit")
    out = capsys.readouterr().out
    assert "permission_audit_snapshots" in out
    assert "this_run=4" in out


def test_render_persistence_footer_explains_interrupted_permission_contract(monkeypatch, capsys):
    audit = SimpleNamespace(
        counts={"static_permission_matrix": (3, "OK"), "permission_audit_snapshots": (0, "OK")},
        is_group_scope=False,
        run_id=123,
        is_orphan=False,
        static_run_id=41,
    )

    def fake_run_sql(query, params=None, fetch=None):
        sql = " ".join(str(query).split()).lower()
        if "select run_id from runs where session_stamp" in sql:
            return [(123,)]
        if "select count(*) from static_permission_matrix where run_id in" in sql:
            return (3,)
        if "select count(*) from permission_audit_snapshots where static_run_id in" in sql:
            return (0,)
        if "select count(*) from permission_audit_apps where static_run_id in" in sql:
            return (0,)
        if "select session_label" in sql:
            return None
        if "from static_string_sample_sets" in sql:
            return None
        if "select count(*) from" in sql:
            return (0,)
        return (0,)

    monkeypatch.setattr(db_verification.core_q, "run_sql", fake_run_sql)
    monkeypatch.setattr(db_verification, "_resolve_static_run_ids", lambda *_args, **_kwargs: [41])
    monkeypatch.setattr(db_verification, "collect_static_run_counts", lambda *_args, **_kwargs: audit)
    monkeypatch.setattr(db_verification, "_table_has_column", lambda *_args, **_kwargs: True)

    db_verification._render_persistence_footer(
        "sess-interrupt",
        run_status="FAILED",
        abort_signal="SIGINT",
    )
    out = capsys.readouterr().out
    assert "permission_contract" in out
    assert "static_permission_matrix persisted before permission_audit snapshot refresh" in out
