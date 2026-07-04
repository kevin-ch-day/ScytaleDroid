from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scytaledroid.Database.db_queries.sql_typed_reads import (
    resolved_dynamic_session_static_run_id,
    resolved_static_run_started_at_utc,
    resolved_static_run_started_utc_text,
)
from scytaledroid.Database.db_utils.phase_a_read_parity import (
    collect_phase_a_read_parity,
    write_phase_a_read_parity_bundle,
)


def test_sql_typed_read_helpers_reference_replacement_columns() -> None:
    dynamic_expr = resolved_dynamic_session_static_run_id("ds")
    assert "ds.static_run_id_u" in dynamic_expr
    assert "cast(ds.static_run_id as unsigned)" in dynamic_expr.lower()

    started_expr = resolved_static_run_started_at_utc("sar")
    assert "sar.run_started_at_utc" in started_expr
    assert "str_to_date" in started_expr.lower()

    started_text = resolved_static_run_started_utc_text("sar")
    assert "date_format" in started_text.lower()
    assert "sar.run_started_utc" in started_text


def test_collect_phase_a_read_parity_and_write_bundle(tmp_path: Path) -> None:
    query_rows = {
        "schema_migrations.latest_schema_version_from_registry": {
            "schema_version_after": "0.3.3-typed-backfill"
        },
        "phase_a_read_parity.dynamic_summary": {
            "dynamic_sessions_total": 10,
            "legacy_static_run_id_present_rows": 3,
            "typed_static_run_id_present_rows": 3,
            "resolved_static_run_id_present_rows": 3,
            "legacy_static_run_linked_rows": 3,
            "typed_static_run_linked_rows": 3,
            "static_link_state_mismatch_rows": 0,
        },
        "phase_a_read_parity.dynamic_mismatch_samples": [],
        "phase_a_read_parity.static_summary": {
            "static_runs_total": 4,
            "legacy_parseable_started_rows": 4,
            "typed_started_rows": 4,
            "resolved_started_rows": 4,
            "started_at_parity_mismatch_rows": 0,
        },
        "phase_a_read_parity.static_mismatch_samples": [],
        "phase_a_read_parity.artifact_summary": {
            "dynamic_artifact_rows": 9,
            "uuid_like_dynamic_run_id_rows": 9,
            "typed_dynamic_run_uuid_rows": 9,
            "dynamic_run_uuid_parity_mismatch_rows": 0,
        },
        "phase_a_read_parity.artifact_mismatch_samples": [],
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=True, query_name=None):  # noqa: ANN001,ARG001
        return query_rows[query_name]

    report = collect_phase_a_read_parity(fake_run_sql, sample_limit=5)
    assert report["summary"]["parity_clean"] is True
    assert report["summary"]["live_schema_version"] == "0.3.3-typed-backfill"

    files = write_phase_a_read_parity_bundle(
        report, tmp_path, stem="phase_a_typed_read_parity_test"
    )
    payload = json.loads(
        (tmp_path / "phase_a_typed_read_parity_test.json").read_text(encoding="utf-8")
    )
    assert payload["summary"]["parity_clean"] is True
    assert files["json"].endswith("phase_a_typed_read_parity_test.json")


def test_report_phase_a_typed_read_parity_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_phase_a_typed_read_parity.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")
