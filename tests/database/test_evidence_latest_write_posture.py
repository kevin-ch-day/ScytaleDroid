"""Unit tests for evidence latest-write posture SQL (no live DB)."""

from __future__ import annotations

from scytaledroid.Database.db_scripts import evidence_latest_write_posture as m


def test_recent_sqls_use_interval_hours() -> None:
    assert "interval 12 hour" in m.sql_recent_findings_total(12).lower()
    assert "interval 48 hour" in m.sql_recent_hash_missing_payload(48).lower()
    assert "left join static_finding_evidence_payloads ep" in (
        m.sql_recent_hash_missing_payload(48).lower()
    )
    assert "ep.evidence_hash is null" in m.sql_recent_hash_missing_payload(48).lower()


def test_unresolved_uses_json_extract_payload() -> None:
    sql = m.sql_recent_unresolved_on_latest_surface(1).lower()
    assert "json_extract(ep.evidence_json, '$')" in sql
    assert "vw_static_finding_surfaces_latest" in sql
