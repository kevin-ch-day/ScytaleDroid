from __future__ import annotations

from pathlib import Path


def test_json_output_uses_static_prune_proposal(monkeypatch, tmp_path: Path) -> None:
    from scripts.db import report_artifact_registry_static_detached as subject

    class _FakeProposal:
        included_primary_reasons = ("truly_detached",)
        targeted_row_count = 2
        targeted_distinct_static_run_ids = 1
        targeted_static_run_ids = (101,)
        reason_counts = {"truly_detached": 2}
        artifact_type_counts = {"static_report": 2}
        path_family_counts = {"static_reports_latest": 2}
        oldest_created_at_utc = "2026-02-08 00:00:00"
        newest_created_at_utc = "2026-02-08 00:00:00"
        total_rows_before = 100
        static_dangling_before = 2
        dynamic_dangling_before = 0
        all_missing_static_run = True
        all_target_files_missing = True
        all_missing_canonical_refs = True
        all_missing_legacy_runs_overlap = True
        canonical_db_residue_count = 0
        legacy_runs_overlap_count = 0
        host_file_present_count = 0
        expected_count_match = None
        exact_sql_predicate = "x"
        sample_rows = ({"artifact_id": 1, "resolved_static_run_id": 101},)

    class _FakeCoreQ:
        def run_sql(self, *_args, **_kwargs):  # noqa: ANN002, ANN003, D401
            return []

    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.DB_CONFIG",
        {"engine": "mariadb"},
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_queries",
        _FakeCoreQ(),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.artifact_registry_static_prune.build_static_prune_proposal",
        lambda *_a, **_k: _FakeProposal(),
    )

    rc = subject.main(["--json"])
    assert rc == 0


def test_build_payload_shapes_output() -> None:
    from scripts.db import report_artifact_registry_static_detached as subject

    class _FakeProposal:
        included_primary_reasons = ("truly_detached",)
        targeted_row_count = 1
        targeted_distinct_static_run_ids = 1
        targeted_static_run_ids = (101,)
        reason_counts = {"truly_detached": 1}
        artifact_type_counts = {"static_report": 1}
        path_family_counts = {"static_reports_latest": 1}
        oldest_created_at_utc = "2026-02-08 00:00:00"
        newest_created_at_utc = "2026-02-08 00:00:00"
        total_rows_before = 100
        static_dangling_before = 1
        dynamic_dangling_before = 0
        all_missing_static_run = True
        all_target_files_missing = True
        all_missing_canonical_refs = True
        all_missing_legacy_runs_overlap = True
        canonical_db_residue_count = 0
        legacy_runs_overlap_count = 0
        host_file_present_count = 0
        expected_count_match = True
        exact_sql_predicate = "predicate"
        sample_rows = ({"artifact_id": 1},)

    payload = subject._build_payload(_FakeProposal())
    assert payload["report_type"] == "artifact_registry_static_detached_candidates"
    assert payload["targeted_row_count"] == 1
    assert payload["targeted_static_run_ids"] == [101]
    assert payload["sample_rows"] == [{"artifact_id": 1}]
