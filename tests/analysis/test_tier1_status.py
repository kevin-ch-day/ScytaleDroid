from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Reporting import menu_actions


def _write_manifest(run_dir: Path, payload: dict[str, object]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def test_fetch_tier1_status_exposes_quota_named_evidence_counts_with_compat_aliases(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "output"
    data_dir = tmp_path / "data"
    dynamic_root = output_dir / "evidence" / "dynamic"

    _write_manifest(
        dynamic_root / "run-valid",
        {"dataset": {"tier": "dataset", "countable": True, "valid_dataset_run": True}},
    )
    _write_manifest(
        dynamic_root / "run-invalid",
        {"dataset": {"tier": "dataset", "countable": True, "valid_dataset_run": False}},
    )
    _write_manifest(
        dynamic_root / "run-supplemental",
        {"dataset": {"tier": "dataset", "countable": False, "valid_dataset_run": True}},
    )
    _write_manifest(
        dynamic_root / "run-other-tier",
        {"dataset": {"tier": "adhoc", "countable": True, "valid_dataset_run": True}},
    )

    monkeypatch.setattr(menu_actions.app_config, "OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(menu_actions.app_config, "DATA_DIR", str(data_dir))

    def fake_run_sql(sql, *args, **kwargs):  # noqa: ANN001
        if "SELECT version FROM schema_version" in sql:
            return {"version": "test-schema"}
        if "SELECT COUNT(*) AS cnt FROM dynamic_sessions WHERE tier='dataset'" in sql:
            return {"cnt": 12}
        if "SELECT COUNT(*) AS cnt FROM dynamic_sessions" in sql:
            return {"cnt": 14}
        if "SUM(CASE WHEN pcap_valid = 1 THEN 1 ELSE 0 END)" in sql:
            return {"valid_count": 9, "linked_count": 11}
        if "FROM dynamic_sessions ds" in sql and "telemetry_partial_samples" in sql:
            return {"cnt": 8}
        raise AssertionError(f"Unexpected SQL: {sql}")

    monkeypatch.setattr(menu_actions.core_q, "run_sql", fake_run_sql)

    status = menu_actions.fetch_tier1_status()

    assert status["db_dynamic_sessions_total"] == 14
    assert status["db_dynamic_sessions_dataset_tier"] == 12
    assert status["db_dynamic_sessions_dataset"] == 12
    assert status["evidence_packs_total"] == 4
    assert status["evidence_quota_eligible_packs"] == 2
    assert status["evidence_quota_valid_packs"] == 1
    assert status["evidence_dataset_packs"] == 2
    assert status["evidence_dataset_valid"] == 1
