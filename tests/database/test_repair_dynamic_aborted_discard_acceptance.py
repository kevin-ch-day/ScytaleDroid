from __future__ import annotations

import json
from pathlib import Path

from scripts.db import repair_dynamic_aborted_discard_acceptance as repair


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _manifest(*, invalid_reason: str = "ABORTED_DISCARD") -> dict[str, object]:
    return {
        "dynamic_run_id": "run-1",
        "status": "degraded",
        "target": {"package_name": "com.example.app"},
        "dataset": {
            "valid_dataset_run": False,
            "countable": False,
            "invalid_reason_code": invalid_reason,
            "technical_validity": "VALID",
            "pcap_available": True,
            "pcap_size_bytes": 123456,
            "window_count": 40,
            "low_signal": False,
        },
        "operator": {
            "run_profile": "interaction_manual",
            "tier": "dataset",
            "counts_toward_completion": True,
            "interrupted": True,
            "interrupted_reason": "ABORTED_DISCARD",
            "script_exit_code": 130,
        },
    }


def _connected_signal_manifest() -> dict[str, object]:
    payload = _manifest()
    payload["target"] = {"package_name": "org.thoughtcrime.securesms"}
    dataset = payload["dataset"]
    assert isinstance(dataset, dict)
    dataset.update(
        {
            "low_signal": True,
            "low_signal_reasons": ["PCAP_BYTES_LOW", "PCAP_PACKETS_LOW", "DOMAINS_LOW"],
        }
    )
    operator = payload["operator"]
    assert isinstance(operator, dict)
    operator.update(
        {
            "run_profile": "baseline_connected",
            "messaging_activity": "connected_idle",
            "target_duration_s": 180,
        }
    )
    return payload


def test_candidate_blocks_non_aborted_discard_reason(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run-1"
    _write_json(run_dir / "run_manifest.json", _manifest(invalid_reason="PCAP_TOO_SMALL"))
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 123456,
            "window_count": 40,
            "actual_sampling_seconds": 240.0,
        },
    )

    row = repair._candidate(run_dir)

    assert row["status"] == "blocked"
    assert row["reason"] == "current_invalid_reason_is_not_aborted_discard"


def test_candidate_accepts_valid_quota_run_with_stale_operator_discard_marker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run-1"
    manifest = _manifest(invalid_reason="")
    dataset = manifest["dataset"]
    assert isinstance(dataset, dict)
    dataset.update(
        {
            "valid_dataset_run": True,
            "countable": False,
            "invalid_reason_code": None,
            "paper_exclusion_primary_reason_code": "EXCLUDED_BASELINE_PROTOCOL_LEGACY",
        }
    )
    operator = manifest["operator"]
    assert isinstance(operator, dict)
    operator.update({"run_profile": "baseline_connected", "messaging_activity": "connected_idle"})
    _write_json(run_dir / "run_manifest.json", manifest)
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 123456,
            "window_count": 40,
            "actual_sampling_seconds": 240.0,
        },
    )

    row = repair._candidate(run_dir)

    assert row["status"] == "candidate"
    assert row["reason"] == "valid_run_with_stale_aborted_discard_marker"


def test_candidate_blocks_valid_stale_operator_discard_when_not_quota_intended(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run-1"
    manifest = _manifest(invalid_reason="")
    dataset = manifest["dataset"]
    assert isinstance(dataset, dict)
    dataset.update({"valid_dataset_run": True, "invalid_reason_code": None})
    operator = manifest["operator"]
    assert isinstance(operator, dict)
    operator["counts_toward_completion"] = False
    _write_json(run_dir / "run_manifest.json", manifest)
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 123456,
            "window_count": 40,
            "actual_sampling_seconds": 240.0,
        },
    )

    row = repair._candidate(run_dir)

    assert row["status"] == "blocked"
    assert row["reason"] == "run_was_not_quota_intended"


def test_candidate_allows_recomputed_non_low_signal_connected_baseline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run-1"
    _write_json(run_dir / "run_manifest.json", _connected_signal_manifest())
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 12647,
            "window_count": 49,
            "actual_sampling_seconds": 251.9,
        },
    )
    monkeypatch.setattr(
        repair,
        "_low_signal_repairable_after_recheck",
        lambda _run_dir, *, package_name, run_profile: True,
    )

    row = repair._candidate(run_dir)

    assert row["status"] == "candidate"


def test_dry_run_reports_candidate_without_mutating(tmp_path: Path, monkeypatch) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "audit"
    run_dir = evidence_root / "run-1"
    manifest = _manifest()
    _write_json(run_dir / "run_manifest.json", manifest)
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 123456,
            "window_count": 40,
            "actual_sampling_seconds": 240.0,
        },
    )

    summary = repair.run(
        run_id="run-1",
        evidence_root=evidence_root,
        output_dir=output_dir,
        apply=False,
        reason="test",
    )
    after = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))

    assert summary["candidate_rows"] == 1
    assert summary["applied_rows"] == 0
    assert after == manifest
    assert (output_dir / "actions.csv").exists()
    assert (output_dir / "summary.json").exists()


def test_apply_accepts_run_refreshes_tracker_summary_and_db(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "audit"
    run_dir = evidence_root / "run-1"
    _write_json(run_dir / "run_manifest.json", _manifest())
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 123456,
            "window_count": 40,
            "actual_sampling_seconds": 240.0,
            "min_pcap_bytes": 50000,
            "min_window_count": 20,
        },
    )
    monkeypatch.setattr(
        repair,
        "_tracker_row_for_run",
        lambda _run_id, _package_name: {
            "valid_dataset_run": True,
            "countable": True,
            "counts_toward_quota": True,
            "invalid_reason_code": None,
            "cohort_eligibility": "COUNTABLE",
        },
    )

    tracker_calls: list[object] = []
    refresh_calls: list[dict[str, object]] = []
    db_calls: list[Path] = []

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.recompute_dataset_tracker",
        lambda config: tracker_calls.append(config),
    )
    monkeypatch.setattr(
        "scripts.dynamic.refresh_analysis_summaries.refresh_summaries",
        lambda **kwargs: refresh_calls.append(kwargs) or {"runs_updated": 1},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.index_dynamic_evidence_pack_to_db",
        lambda path: db_calls.append(path) or {"ok": True, "dynamic_run_id": path.name},
    )

    summary = repair.run(
        run_id="run-1",
        evidence_root=evidence_root,
        output_dir=output_dir,
        apply=True,
        reason="operator confirmed accidental discard",
    )
    after = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))

    assert summary["applied_rows"] == 1
    assert after["status"] == "success"
    assert after["dataset"]["valid_dataset_run"] is True
    assert after["dataset"]["countable"] is True
    assert after["dataset"]["invalid_reason_code"] is None
    assert after["operator"]["interrupted"] is False
    assert after["operator"]["script_exit_code"] == 0
    assert after["operator"]["accepted_after_discard_repair"] is True
    assert tracker_calls
    assert refresh_calls[0]["run_ids"] == {"run-1"}
    assert db_calls == [run_dir]
    assert (output_dir / "manifest_backups" / "run-1.run_manifest.before.json").exists()


def test_apply_connected_baseline_restores_protocol_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "audit"
    run_dir = evidence_root / "run-1"
    _write_json(run_dir / "run_manifest.json", _connected_signal_manifest())
    monkeypatch.setattr(
        repair,
        "_technical_validity",
        lambda _run_dir, _payload: {
            "valid_dataset_run": True,
            "invalid_reason_code": None,
            "pcap_size_bytes": 12647,
            "window_count": 49,
            "actual_sampling_seconds": 251.9,
            "min_pcap_bytes": 10000,
            "min_window_count": 20,
            "low_signal": False,
            "low_signal_reasons": [],
        },
    )
    monkeypatch.setattr(
        repair,
        "_low_signal_repairable_after_recheck",
        lambda _run_dir, *, package_name, run_profile: True,
    )
    monkeypatch.setattr(
        repair,
        "_tracker_row_for_run",
        lambda _run_id, _package_name: {
            "valid_dataset_run": True,
            "countable": True,
            "counts_toward_quota": True,
            "invalid_reason_code": None,
            "cohort_eligibility": "COUNTABLE",
            "paper_eligible": True,
            "low_signal": False,
            "low_signal_reasons": [],
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.recompute_dataset_tracker",
        lambda config: None,
    )
    monkeypatch.setattr(
        "scripts.dynamic.refresh_analysis_summaries.refresh_summaries",
        lambda **kwargs: {"runs_updated": 1},
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.index_dynamic_evidence_pack_to_db",
        lambda path: {"ok": True, "dynamic_run_id": path.name},
    )

    summary = repair.run(
        run_id="run-1",
        evidence_root=evidence_root,
        output_dir=output_dir,
        apply=True,
        reason="operator confirmed accidental discard",
    )
    after = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))

    assert summary["applied_rows"] == 1
    assert after["operator"]["baseline_protocol_id"] == "baseline_connected_v2"
    assert after["operator"]["baseline_protocol_version"] == 2
    assert isinstance(after["operator"]["baseline_protocol_hash"], str)
    assert after["dataset"]["low_signal"] is False
