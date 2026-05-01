from __future__ import annotations

import json

from scytaledroid.Database.db_func.static_analysis import static_findings
from scytaledroid.Database.db_func.static_analysis import string_analysis


class _NoopSession:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_secret_buckets_never_persist_raw_values(monkeypatch):
    inserted_rows: list[tuple[object, ...]] = []

    monkeypatch.setattr(string_analysis, "_IS_SQLITE", False)
    monkeypatch.setattr(string_analysis, "database_session", lambda: _NoopSession())
    monkeypatch.setattr(string_analysis, "_require_static_run_id", lambda *_a, **_k: None)
    monkeypatch.setattr(string_analysis, "run_sql", lambda *_a, **_k: None)
    monkeypatch.setattr(
        string_analysis,
        "run_sql_many",
        lambda _sql, rows: inserted_rows.extend(rows),
    )

    raw_secret = "AKIA_TEST_SECRET_123"
    _, inserted = string_analysis.replace_samples_full(
        summary_id=1,
        samples={"api_keys": [{"value": raw_secret, "src": "classes.dex"}]},
        static_run_id=22,
    )

    assert inserted == 1
    assert inserted_rows
    row = inserted_rows[0]
    assert row[3] == "[REDACTED]"
    assert row[12]
    assert raw_secret not in str(row)


def test_static_findings_redacts_secret_like_detail(monkeypatch):
    inserted_rows: list[tuple[object, ...]] = []

    monkeypatch.setattr(static_findings, "_IS_SQLITE", False)
    monkeypatch.setattr(static_findings, "database_session", lambda: _NoopSession())
    monkeypatch.setattr(static_findings, "_require_canonical_schema", lambda: None)
    monkeypatch.setattr(static_findings, "_require_static_run_id", lambda v: int(v or 0))

    def _run_sql(sql, params=None, fetch=None):
        sql_text = str(sql)
        if "DELETE FROM static_findings" in sql_text:
            return None
        if "INSERT INTO static_findings" in sql_text:
            inserted_rows.append(tuple(params or ()))
            return None
        return None

    monkeypatch.setattr(static_findings, "run_sql", _run_sql)

    jwt = (
        "eyJhbGciOiJSU0EtU0hBMjU2IiwidmVyIjoiMSJ9."
        "eyJhIjoiYiIsImMiOiJkIn0."
        "c2lnbmF0dXJlLXBhcnQ"
    )
    static_findings.replace_findings(
        summary_id=1,
        findings=(
            {
                "id": "f-1",
                "severity": "Medium",
                "title": "secret-like evidence",
                "evidence": {"detail": jwt, "path": "assets/api_key.txt"},
                "fix": "remove",
            },
        ),
        run_id=10,
        static_run_id=20,
    )

    assert inserted_rows
    ev_json = inserted_rows[0][6]
    payload = json.loads(str(ev_json))
    assert payload.get("detail") == "[REDACTED:JWT]"
