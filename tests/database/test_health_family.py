from __future__ import annotations

from scytaledroid.Database.db_utils.health_checks import inventory_checks
from scytaledroid.Database.db_utils.health_checks import queries
from scytaledroid.Database.db_utils.health_checks import summary as health_summary


def test_fetch_health_summary_includes_stale_static_batch_signals(monkeypatch) -> None:
    def _scalar(sql: str, *_args, **_kwargs):
        normalized = " ".join(sql.split())
        if "FROM ( SELECT sar.session_label FROM static_analysis_runs sar" in normalized:
            return 1
        if "FROM ( SELECT session_label FROM static_analysis_runs WHERE status='STARTED'" in normalized:
            return 1
        if "FROM static_analysis_runs sar LEFT JOIN static_analysis_findings saf" in normalized and "COUNT(*" in normalized:
            return 6
        if "WHERE status='RUNNING' AND ended_at_utc IS NULL" in normalized and "INTERVAL 1 DAY" not in normalized:
            return 1
        if "WHERE status='RUNNING' AND ended_at_utc IS NULL" in normalized and "INTERVAL 1 DAY" in normalized:
            return 0
        if "WHERE status IN ('COMPLETED','OK')" in normalized:
            return 2
        if "WHERE status='FAILED'" in normalized:
            return 3
        if "WHERE status='ABORTED'" in normalized:
            return 4
        if "SELECT COUNT(*) FROM static_analysis_runs WHERE status='STARTED'" in normalized:
            return 5
        if "FROM static_findings f LEFT JOIN static_findings_summary s" in normalized:
            return 7
        if "FROM static_string_samples x LEFT JOIN static_string_summary s" in normalized:
            return 8
        if "FROM static_string_selected_samples x LEFT JOIN static_string_summary s" in normalized:
            return 9
        if "FROM static_string_sample_sets x LEFT JOIN static_string_summary s" in normalized:
            return 10
        if "FROM permission_audit_apps a LEFT JOIN permission_audit_snapshots s" in normalized:
            return 11
        raise AssertionError(f"Unexpected SQL: {normalized}")

    monkeypatch.setattr(health_summary, "scalar", _scalar)

    summary = health_summary.fetch_health_summary()

    assert summary.running_total == 1
    assert summary.running_recent == 0
    assert summary.ok_recent == 2
    assert summary.failed_recent == 3
    assert summary.aborted_recent == 4
    assert summary.stale_started_rows == 5
    assert summary.stale_started_sessions == 1
    assert summary.stale_started_rows_without_downstream == 6
    assert summary.stale_started_sessions_without_downstream == 1
    assert summary.orphan_findings == 7
    assert summary.orphan_samples == 8
    assert summary.orphan_selected_samples == 9
    assert summary.orphan_sample_sets == 10
    assert summary.orphan_audit_apps == 11


def test_inventory_snapshot_checks_reports_catalog_token_and_apk_suffix_counts() -> None:
    def _scalar(query: str, params=()):
        lowered = " ".join(query.lower().split())
        if "where package_name like '%/%'" in lowered:
            return 0
        if "regexp '^[0-9]+$'" in lowered:
            return 1
        if "where package_name like '%.apk'" in lowered:
            return 2
        if "count(distinct a.package_name)" in lowered:
            return 0
        if "publisher_key = 'vendor_misc'" in lowered:
            return 0
        if "lower(convert(app_label using utf8mb4))" in lowered:
            return 0
        if "lower(convert(i.app_label using utf8mb4))" in lowered:
            return 0
        return 0

    rows: list[tuple[str, str, str | None]] = []

    def _print(level: str, label: str, detail: str | None = None) -> None:
        rows.append((level, label, detail))

    inventory_checks.run_inventory_snapshot_checks(
        scalar=_scalar,
        latest_snapshot_id=31,
        snapshot_headers_total=1,
        orphan_headers=0,
        latest_is_orphan=False,
        latest_rows=546,
        latest_expected=546,
        print_status_line=_print,
    )

    assert ("warn", "invalid catalog package tokens", "1") in rows
    assert ("warn", "catalog package_name with .apk suffix", "2") in rows


def test_fetch_latest_run_prefers_canonical_static_runs() -> None:
    seen: list[str] = []

    def fake_run_sql(query, *args, **kwargs):
        seen.append(query)
        return {
            "static_run_id": 557,
            "legacy_run_id": 564,
            "package_name": "org.thoughtcrime.securesms",
            "version_name": "8.6.2",
            "version_code": 168201,
            "target_sdk": 35,
            "created_at": "2026-04-28 05:00:00",
            "status": "COMPLETED",
            "session_stamp": "qa-signal-full-1",
        }

    row = queries.fetch_latest_run(fake_run_sql)
    assert row is not None
    assert row["static_run_id"] == 557
    assert row["legacy_run_id"] == 564
    assert row["package_name"] == "org.thoughtcrime.securesms"
    assert "FROM static_analysis_runs sar" in seen[0]


def test_fetch_latest_session_prefers_canonical_static_runs() -> None:
    seen: list[str] = []

    def fake_run_sql(query, *args, **kwargs):
        seen.append(query)
        return {
            "session_stamp": "qa-signal-full-1",
            "package_name": "org.thoughtcrime.securesms",
            "static_run_id": 557,
            "created_at": "2026-04-28 05:00:00",
        }

    row = queries.fetch_latest_session(fake_run_sql)
    assert row is not None
    assert row["session_stamp"] == "qa-signal-full-1"
    assert row["static_run_id"] == 557
    assert "FROM static_analysis_runs sar" in seen[0]
