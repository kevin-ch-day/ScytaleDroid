from __future__ import annotations

from datetime import UTC
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import (
    db_verification,
    diagnostics,
    results_formatters,
)
from scytaledroid.Utils.System import output_prefs


def test_hash_prefix_short_value():
    assert results_formatters._hash_prefix("abcd") == "abcd"


def test_hash_prefix_long_value():
    assert results_formatters._hash_prefix("0123456789abcdef") == "0123…cdef"


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
                (719, "2026-02-05 00:00:00", 1),
                (718, "2026-02-05 00:00:00", 0),
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


def test_render_db_masvs_summary_aggregates_all_static_ids(monkeypatch, capsys):
    class _Ctx:
        persistence_ready = True
        session_stamp = "sess-agg"

    monkeypatch.setattr(output_prefs, "get_run_context", lambda: _Ctx())
    monkeypatch.setattr(db_verification, "load_run_map", lambda *_a, **_k: {"apps": []})
    monkeypatch.setattr(db_verification, "extract_static_run_ids", lambda *_a, **_k: [41, 40, 39])

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

    monkeypatch.setattr(db_verification, "fetch_db_masvs_summary_static_many", _many)
    monkeypatch.setattr(db_verification, "fetch_db_masvs_summary", _fallback)

    db_verification._render_db_masvs_summary()

    out = capsys.readouterr().out
    assert "DB MASVS Summary (static_run_id=41)" in out
    assert calls["many"] == 1
    assert calls["fallback"] == 0


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
