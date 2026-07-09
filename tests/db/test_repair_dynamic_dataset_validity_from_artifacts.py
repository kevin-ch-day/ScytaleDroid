from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.db import repair_dynamic_dataset_validity_from_artifacts as repair


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_policy_sync_candidate_detects_stale_non_idle_fields(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": True,
                "countable": True,
                "cohort_eligibility": "COUNTABLE",
                "baseline_not_idle": None,
            },
            "target": {"package_name": "com.zhiliaoapp.musically"},
            "operator": {"run_profile": "baseline_idle"},
        },
    )
    tracker_row = {
        "run_id": "run-1",
        "valid_dataset_run": True,
        "countable": False,
        "counts_toward_quota": False,
        "extra_run": 1,
        "cohort_eligibility": "EXTRA",
        "baseline_not_idle": True,
        "baseline_not_idle_reasons": ["BASELINE_BYTES_HIGH"],
        "exploratory_class": "BASELINE_NOT_IDLE",
    }

    row = repair._policy_sync_candidate_row(run_dir, tracker_row)

    assert row is not None
    assert row["repair_type"] == "policy_sync"
    assert row["package"] == "com.zhiliaoapp.musically"
    changed = set(str(row["changed_fields"]).split(","))
    assert {"countable", "baseline_not_idle", "exploratory_class", "cohort_eligibility"} <= changed


def test_sync_manifest_from_tracker_updates_non_idle_policy_fields(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-2"
    manifest_path = run_dir / "run_manifest.json"
    _write_json(
        manifest_path,
        {
            "dataset": {
                "valid_dataset_run": True,
                "countable": True,
                "cohort_eligibility": "COUNTABLE",
            }
        },
    )
    tracker_row = {
        "valid_dataset_run": True,
        "countable": False,
        "counts_toward_quota": False,
        "extra_run": 1,
        "cohort_eligibility": "EXTRA",
        "baseline_not_idle": True,
        "baseline_not_idle_reasons": ["BASELINE_BYTES_HIGH", "BASELINE_QUIC_MEDIA_HEAVY"],
        "exploratory_class": "BASELINE_NOT_IDLE",
    }

    changed = repair._sync_manifest_from_tracker(run_dir, tracker_row)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    dataset = payload["dataset"]

    assert changed is True
    assert dataset["countable"] is False
    assert dataset["counts_toward_quota"] is False
    assert dataset["extra_run"] == 1
    assert dataset["cohort_eligibility"] == "EXTRA"
    assert dataset["baseline_not_idle"] is True
    assert dataset["baseline_not_idle_reasons"] == [
        "BASELINE_BYTES_HIGH",
        "BASELINE_QUIC_MEDIA_HEAVY",
    ]
    assert dataset["exploratory_class"] == "BASELINE_NOT_IDLE"


def test_policy_sync_treats_missing_quota_defaults_as_equivalent(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-defaults"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": True,
                "countable": True,
                "cohort_eligibility": "COUNTABLE",
            },
            "target": {"package_name": "com.guardian"},
            "operator": {"run_profile": "baseline_idle"},
        },
    )
    tracker_row = {
        "run_id": "run-defaults",
        "valid_dataset_run": True,
        "countable": True,
        "counts_toward_quota": True,
        "extra_run": 0,
        "cohort_eligibility": "COUNTABLE",
    }

    assert repair._policy_sync_candidate_row(run_dir, tracker_row) is None


def test_policy_sync_treats_missing_tracker_optional_none_as_equivalent(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-optional-none"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": True,
                "countable": True,
                "cohort_eligibility": "COUNTABLE",
                "exploratory_class": None,
            },
            "target": {"package_name": "com.guardian"},
            "operator": {"run_profile": "baseline_idle"},
        },
    )
    tracker_row = {
        "run_id": "run-optional-none",
        "valid_dataset_run": True,
        "countable": True,
        "counts_toward_quota": True,
        "extra_run": 0,
        "cohort_eligibility": "COUNTABLE",
    }

    assert repair._policy_sync_candidate_row(run_dir, tracker_row) is None


def test_policy_sync_still_detects_missing_false_quota_flag(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-noncountable"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": True,
                "countable": False,
                "cohort_eligibility": "EXTRA",
            },
            "target": {"package_name": "com.guardian"},
            "operator": {"run_profile": "baseline_idle"},
        },
    )
    tracker_row = {
        "run_id": "run-noncountable",
        "valid_dataset_run": True,
        "countable": False,
        "counts_toward_quota": False,
        "extra_run": 1,
        "cohort_eligibility": "EXTRA",
    }

    row = repair._policy_sync_candidate_row(run_dir, tracker_row)

    assert row is not None
    changed = set(str(row["changed_fields"]).split(","))
    assert {"counts_toward_quota", "extra_run"} <= changed


def test_policy_sync_does_not_rewrite_aborted_discard_runs(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-aborted"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dataset": {
                "valid_dataset_run": False,
                "countable": False,
                "invalid_reason_code": "ABORTED_DISCARD",
                "cohort_eligibility": "EXCLUDED",
                "low_signal": True,
            },
            "target": {"package_name": "org.telegram.messenger"},
            "operator": {"run_profile": "interaction_manual", "messaging_activity": "voice_call"},
        },
    )
    tracker_row = {
        "run_id": "run-aborted",
        "valid_dataset_run": False,
        "countable": False,
        "invalid_reason_code": "INSUFFICIENT_DURATION",
        "cohort_eligibility": "EXCLUDED",
        "low_signal": False,
        "low_signal_reasons": [],
    }

    assert repair._policy_sync_candidate_row(run_dir, tracker_row) is None


def test_apply_repairs_refreshes_all_derived_artifacts_for_repaired_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "audit"
    run_dir = evidence_root / "run-1"
    manifest_path = run_dir / "run_manifest.json"
    _write_json(
        manifest_path,
        {
            "dynamic_run_id": "run-1",
            "dataset": {
                "valid_dataset_run": False,
                "countable": False,
                "invalid_reason_code": "PCAP_TOO_SMALL",
            },
            "target": {"package_name": "com.example.app"},
            "operator": {"run_profile": "baseline_idle"},
        },
    )

    monkeypatch.setattr(
        repair,
        "_read_json",
        lambda path: json.loads(path.read_text(encoding="utf-8")) if path.exists() else None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.recompute_dataset_tracker",
        lambda config: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.research_cohort_archive.resolve_dataset_plan_read_path",
        lambda: tmp_path / "tracker.json",
    )
    _write_json(tmp_path / "tracker.json", {"apps": {}})

    refresh_calls: list[dict[str, object]] = []

    def _fake_refresh_summaries(**kwargs):
        refresh_calls.append(kwargs)
        return {"runs_updated": 1}

    monkeypatch.setattr(
        "scripts.dynamic.refresh_analysis_summaries.refresh_summaries",
        _fake_refresh_summaries,
    )
    reindex_calls: list[Path] = []

    def _fake_reindex(run_dir: Path):
        reindex_calls.append(run_dir)
        return {"ok": True, "dynamic_run_id": run_dir.name}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.index_dynamic_evidence_pack_to_db",
        _fake_reindex,
    )

    rows = [
        {
            "repair_type": "validity_repair",
            "run_id": "run-1",
            "_validity": {
                "valid_dataset_run": True,
                "countable": True,
                "pcap_size_bytes": 123456,
                "actual_sampling_seconds": 240.0,
                "cohort_eligibility": "COUNTABLE",
            },
        }
    ]

    applied, synced, reindexed = repair._apply_repairs(
        evidence_root,
        output_dir,
        rows,
        explicit_run_ids=("run-1",),
    )

    assert applied == 1
    assert synced == 0
    assert reindexed == 1
    assert reindex_calls == [run_dir]
    assert len(refresh_calls) == 1
    assert refresh_calls[0]["root"] == evidence_root
    assert refresh_calls[0]["apply"] is True
    assert refresh_calls[0]["refresh_pcap_report"] is True
    assert refresh_calls[0]["refresh_pcap_features"] is True
    assert refresh_calls[0]["refresh_overlap"] is True
    assert refresh_calls[0]["run_ids"] == {"run-1"}


def test_apply_repairs_reindexes_explicit_run_id_even_when_no_manifest_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "audit"
    run_dir = evidence_root / "run-quiet"
    _write_json(
        run_dir / "run_manifest.json",
        {
            "dynamic_run_id": "run-quiet",
            "dataset": {"valid_dataset_run": True, "countable": True},
            "target": {"package_name": "org.thoughtcrime.securesms"},
            "operator": {"run_profile": "baseline_connected"},
        },
    )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.recompute_dataset_tracker",
        lambda config: None,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.research_cohort_archive.resolve_dataset_plan_read_path",
        lambda: tmp_path / "tracker.json",
    )
    _write_json(tmp_path / "tracker.json", {"apps": {}})
    monkeypatch.setattr(
        "scripts.dynamic.refresh_analysis_summaries.refresh_summaries",
        lambda **kwargs: {"runs_updated": 0},
    )

    reindex_calls: list[Path] = []

    def _fake_reindex(run_path: Path):
        reindex_calls.append(run_path)
        return {"ok": True, "dynamic_run_id": run_path.name}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.index_dynamic_evidence_pack_to_db",
        _fake_reindex,
    )

    applied, synced, reindexed = repair._apply_repairs(
        evidence_root,
        output_dir,
        rows=[],
        explicit_run_ids=("run-quiet",),
    )

    assert applied == 0
    assert synced == 0
    assert reindexed == 1
    assert reindex_calls == [run_dir]


def test_main_dry_run_does_not_refresh_tracker_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def _fake_refresh() -> None:
        calls.append("refresh")

    def _fake_candidates(evidence_root: Path, run_ids: set[str]):
        calls.append("candidates")
        assert evidence_root == tmp_path / "evidence"
        assert run_ids == {"run-1"}
        return []

    monkeypatch.setattr(repair, "_refresh_tracker_truth", _fake_refresh)
    monkeypatch.setattr(repair, "_candidate_rows", _fake_candidates)

    assert (
        repair.main(
            [
                "--evidence-root",
                str(tmp_path / "evidence"),
                "--output-dir",
                str(tmp_path / "audit"),
                "--run-id",
                "run-1",
            ]
        )
        == 0
    )

    assert calls == ["candidates"]
    summary = json.loads((tmp_path / "audit" / "summary.json").read_text(encoding="utf-8"))
    assert summary["tracker_refreshed_before_candidate_selection"] is False


def test_main_dry_run_refresh_tracker_option_runs_before_candidate_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    monkeypatch.setattr(repair, "_refresh_tracker_truth", lambda: calls.append("refresh"))
    monkeypatch.setattr(repair, "_candidate_rows", lambda evidence_root, run_ids: calls.append("candidates") or [])

    assert (
        repair.main(
            [
                "--evidence-root",
                str(tmp_path / "evidence"),
                "--output-dir",
                str(tmp_path / "audit"),
                "--run-id",
                "run-1",
                "--refresh-tracker",
            ]
        )
        == 0
    )

    assert calls == ["refresh", "candidates"]
    summary = json.loads((tmp_path / "audit" / "summary.json").read_text(encoding="utf-8"))
    assert summary["tracker_refreshed_before_candidate_selection"] is True


def test_main_apply_refreshes_tracker_before_candidate_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    rows = [
        {
            "repair_type": "policy_sync",
            "run_id": "run-1",
            "package": "org.thoughtcrime.securesms",
            "run_profile": "baseline_connected",
            "messaging_activity": "connected_idle",
            "current_valid_dataset_run": 1,
            "current_invalid_reason_code": "",
            "new_valid_dataset_run": 1,
            "new_invalid_reason_code": None,
            "changed_fields": "low_signal,low_signal_reasons",
        }
    ]

    def _fake_candidates(evidence_root: Path, run_ids: set[str]):
        calls.append("candidates")
        return rows

    def _fake_apply(evidence_root: Path, output_dir: Path, selected_rows, *, explicit_run_ids=()):
        calls.append("apply")
        assert selected_rows == rows
        assert explicit_run_ids == ["run-1"]
        return (0, 1, 1)

    monkeypatch.setattr(repair, "_refresh_tracker_truth", lambda: calls.append("refresh"))
    monkeypatch.setattr(repair, "_candidate_rows", _fake_candidates)
    monkeypatch.setattr(repair, "_apply_repairs", _fake_apply)

    assert (
        repair.main(
            [
                "--evidence-root",
                str(tmp_path / "evidence"),
                "--output-dir",
                str(tmp_path / "audit"),
                "--run-id",
                "run-1",
                "--apply",
            ]
        )
        == 0
    )

    assert calls == ["refresh", "candidates", "apply"]
    summary = json.loads((tmp_path / "audit" / "summary.json").read_text(encoding="utf-8"))
    assert summary["tracker_refreshed_before_candidate_selection"] is True
    assert summary["candidate_rows"] == 1
    assert summary["synced_manifest_rows"] == 1
    assert summary["reindexed_db_rows"] == 1
