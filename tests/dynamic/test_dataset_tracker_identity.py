from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap import dataset_tracker as tracker
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    _apply_quota_marking,
    _should_ignore_stale_explicit_noncountable,
    recompute_dataset_tracker,
    update_dataset_tracker,
)


def test_recompute_dataset_tracker_preserves_manifest_dataset_fields(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "run_manifest_version": 1,
                "dynamic_run_id": "run-1",
                "created_at": "2026-06-29T00:00:00+00:00",
                "started_at": "2026-06-29T00:01:00+00:00",
                "ended_at": "2026-06-29T00:05:00+00:00",
                "status": "success",
                "dataset": {
                    "valid_dataset_run": True,
                    "countable": False,
                    "cohort_eligibility": "EXTRA",
                },
                "target": {"package_name": "com.example.app"},
                "operator": {"tier": "dataset", "run_profile": "interaction_manual"},
                "scenario": {"id": "basic_usage"},
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.app_config.OUTPUT_DIR",
        str(tmp_path / "output"),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.resolve_dataset_plan_read_path",
        lambda: tmp_path / "dataset_plan.json",
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.write_dataset_plan_payload",
        lambda payload: tmp_path / "dataset_plan.json",
    )

    def _capture_update(manifest, _run_dir, *, config=None, event_logger=None):
        captured["dataset"] = dict(manifest.dataset)
        return tmp_path / "dataset_plan.json"

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.update_dataset_tracker",
        _capture_update,
    )

    recompute_dataset_tracker()

    assert captured["dataset"] == {
        "valid_dataset_run": True,
        "countable": False,
        "cohort_eligibility": "EXTRA",
    }


def test_normalize_tracker_refreshes_stale_script_template_mismatch(monkeypatch) -> None:
    def fake_refresh(row: dict[str, object]) -> bool:
        row["paper_eligible"] = True
        row["paper_exclusion_primary_reason_code"] = None
        row["paper_exclusion_all_reason_codes"] = []
        return True

    monkeypatch.setattr(tracker, "_refresh_paper_eligibility_in_place", fake_refresh)
    payload = {
        "apps": {
            "com.example.app": {
                "runs": [
                    {
                        "run_id": "run-1",
                        "run_profile": "interaction_scripted",
                        "valid_dataset_run": True,
                        "paper_eligible": False,
                        "paper_exclusion_primary_reason_code": "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH",
                        "paper_exclusion_all_reason_codes": ["EXCLUDED_SCRIPT_TEMPLATE_MISMATCH"],
                    }
                ]
            }
        }
    }
    dirty = [False]

    normalized = tracker._normalize_tracker_payload(payload, DatasetTrackerConfig(), dirty=dirty)
    row = normalized["apps"]["com.example.app"]["runs"][0]

    assert dirty == [True]
    assert row["paper_eligible"] is True
    assert row["paper_exclusion_primary_reason_code"] is None
    assert row["paper_exclusion_all_reason_codes"] == []


def test_normalize_tracker_refreshes_invalid_run_cached_as_eligible(monkeypatch) -> None:
    def fake_refresh(row: dict[str, object]) -> bool:
        row["paper_eligible"] = False
        row["paper_exclusion_primary_reason_code"] = "EXCLUDED_INCOMPLETE_ARTIFACT_SET"
        row["paper_exclusion_all_reason_codes"] = ["EXCLUDED_INCOMPLETE_ARTIFACT_SET"]
        return True

    monkeypatch.setattr(tracker, "_refresh_paper_eligibility_in_place", fake_refresh)
    payload = {
        "apps": {
            "com.example.app": {
                "runs": [
                    {
                        "run_id": "run-1",
                        "run_profile": "interaction_manual",
                        "valid_dataset_run": False,
                        "invalid_reason_code": "PCAP_MISSING",
                        "paper_eligible": True,
                        "paper_exclusion_primary_reason_code": None,
                        "paper_exclusion_all_reason_codes": [],
                    }
                ]
            }
        }
    }
    dirty = [False]

    normalized = tracker._normalize_tracker_payload(payload, DatasetTrackerConfig(), dirty=dirty)
    row = normalized["apps"]["com.example.app"]["runs"][0]

    assert dirty == [True]
    assert row["paper_eligible"] is False
    assert row["paper_exclusion_primary_reason_code"] == "EXCLUDED_INCOMPLETE_ARTIFACT_SET"


def test_should_ignore_stale_explicit_noncountable_for_repaired_quota_run() -> None:
    assert (
        _should_ignore_stale_explicit_noncountable(
            {
                "countable": False,
                "valid_dataset_run": False,
                "invalid_reason_code": "PCAP_MISSING",
            },
            {
                "counts_toward_completion": True,
                "run_profile": "baseline_connected",
            },
            {
                "valid_dataset_run": True,
                "invalid_reason_code": None,
            },
            {"low_signal": False},
        )
        is True
    )

    assert (
        _should_ignore_stale_explicit_noncountable(
            {
                "countable": False,
                "valid_dataset_run": True,
            },
            {"counts_toward_completion": True, "run_profile": "baseline_idle"},
            {"valid_dataset_run": True},
            {"low_signal": False},
        )
        is True
    )

    assert (
        _should_ignore_stale_explicit_noncountable(
            {
                "countable": False,
                "valid_dataset_run": False,
            },
            {"counts_toward_completion": False},
            {"valid_dataset_run": True},
            {"low_signal": False},
        )
        is False
    )

    assert (
        _should_ignore_stale_explicit_noncountable(
            {
                "countable": False,
                "valid_dataset_run": True,
                "low_signal": True,
            },
            {
                "counts_toward_completion": True,
                "run_profile": "baseline_idle",
            },
            {"valid_dataset_run": True},
            {"low_signal": False},
        )
        is True
    )


def test_quota_marking_promotes_stale_noncountable_baselines_into_empty_slots() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": f"b{idx}",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "extra_run": 0,
                "low_signal": False,
                "baseline_not_idle": False,
                "started_at": f"2026-06-30T0{idx}:00:00+00:00",
            }
            for idx in range(1, 4)
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert all(by_id[f"b{idx}"]["counts_toward_quota"] is True for idx in range(1, 4))
    assert all(by_id[f"b{idx}"]["countable"] is True for idx in range(1, 4))
    assert app_entry["extra_valid_runs"] == 0


def test_quota_marking_counts_app_active_no_touch_baseline_but_keeps_low_signal_supplemental() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "not-idle",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "extra_run": 1,
                "low_signal": False,
                "baseline_not_idle": True,
                "started_at": "2026-06-30T01:00:00+00:00",
            },
            {
                "run_id": "low",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "extra_run": 0,
                "low_signal": True,
                "baseline_not_idle": False,
                "started_at": "2026-06-30T02:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["not-idle"]["counts_toward_quota"] is True
    assert by_id["not-idle"]["countable"] is True
    assert by_id["not-idle"]["extra_run"] == 0
    assert by_id["low"]["counts_toward_quota"] is False
    assert by_id["low"]["countable"] is False
    assert by_id["low"]["extra_run"] == 1
    assert app_entry["extra_valid_runs"] == 1


def test_update_dataset_tracker_reclassifies_repaired_quota_baseline_from_extra_to_counted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    tracker_path = tmp_path / "dataset_plan.json"
    tracker_path.write_text(
        json.dumps(
            {
                "apps": {
                    "com.example.connectedmsg": {
                        "runs": [
                            {
                                "run_id": "b1",
                                "run_profile": "baseline_connected",
                                "valid_dataset_run": True,
                                "paper_eligible": True,
                                "countable": True,
                                "counts_toward_quota": True,
                                "started_at": "2026-06-29T01:00:00+00:00",
                                "ended_at": "2026-06-29T01:08:00+00:00",
                            },
                            {
                                "run_id": "b2",
                                "run_profile": "baseline_connected",
                                "valid_dataset_run": True,
                                "paper_eligible": True,
                                "countable": True,
                                "counts_toward_quota": True,
                                "started_at": "2026-06-29T02:00:00+00:00",
                                "ended_at": "2026-06-29T02:08:00+00:00",
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-3"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 20712
    (capture_dir / "scytaledroid_run-3.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-3.pcap",
                "resolved_pcap_name": "scytaledroid_run-3.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 50000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {"netstats_bytes_in_total": 5340, "netstats_bytes_out_total": 7268}
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 480.0,
                        "packet_count": 199,
                        "data_size_bytes": pcap_bytes,
                    }
                },
                "protocol_hierarchy": [{"protocol": "tls", "bytes": pcap_bytes}],
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {},
                "proxies": {},
                "quality": {
                    "report_status": "ok",
                    "pcap_enrichment": {"status": "ok"},
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.resolve_dataset_plan_read_path",
        lambda: tracker_path,
    )

    def _write_payload(payload):
        tracker_path.write_text(json.dumps(payload), encoding="utf-8")
        return tracker_path

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.write_dataset_plan_payload",
        _write_payload,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker._derive_paper_eligibility_fields",
        lambda *args, **kwargs: {
            "paper_eligible": True,
            "paper_exclusion_primary_reason_code": None,
            "paper_exclusion_all_reason_codes": [],
        },
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.scope_tracker_runs_to_active_identity",
        lambda _pkg, runs, resolve_tracker_run_identity_fn=None: {"active_runs": list(runs)},
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-3",
        created_at="2026-06-30T00:00:00Z",
        started_at="2026-06-30T00:00:00Z",
        ended_at="2026-06-30T00:08:00Z",
        status="degraded",
        dataset={
            "countable": False,
            "valid_dataset_run": False,
            "invalid_reason_code": "PCAP_MISSING",
        },
        target={"package_name": "com.example.connectedmsg"},
        operator={
            "tier": "dataset",
            "run_profile": "baseline_connected",
            "run_sequence": 3,
            "interaction_level": "minimal",
            "counts_toward_completion": True,
        },
        scenario={"id": "paper3_profile_v3"},
        observers=[
            ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")
        ],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    update_dataset_tracker(manifest, run_dir, config=DatasetTrackerConfig())

    payload = json.loads(tracker_path.read_text(encoding="utf-8"))
    runs = payload["apps"]["com.example.connectedmsg"]["runs"]
    by_id = {row["run_id"]: row for row in runs}

    assert by_id["run-3"]["valid_dataset_run"] is True
    assert by_id["run-3"]["counts_toward_quota"] is True
    assert by_id["run-3"]["countable"] is True
    assert by_id["run-3"]["extra_run"] == 0


def test_update_dataset_tracker_reclassifies_rich_social_idle_baseline_from_low_signal_to_counted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    tracker_path = tmp_path / "dataset_plan.json"
    tracker_path.write_text(
        json.dumps(
            {
                "apps": {
                    "com.twitter.android": {
                        "runs": [
                            {
                                "run_id": "b1",
                                "run_profile": "baseline_idle",
                                "valid_dataset_run": True,
                                "paper_eligible": True,
                                "countable": True,
                                "counts_toward_quota": True,
                                "version_code": "312031000",
                                "base_apk_sha256": "sha-current",
                                "started_at": "2026-07-02T01:00:00+00:00",
                                "ended_at": "2026-07-02T01:08:00+00:00",
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    run_dir = tmp_path / "output" / "evidence" / "dynamic" / "run-2"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 151_384
    (capture_dir / "scytaledroid_run-2.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-2.pcap",
                "resolved_pcap_name": "scytaledroid_run-2.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": True,
                "min_pcap_bytes": 50_000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {"netstats_bytes_in_total": 31_192, "netstats_bytes_out_total": 45_825}
                }
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capture_duration_s": 449.187322,
                "packet_count": 729,
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 449.187322,
                        "packet_count": 729,
                        "data_size_bytes": 139_696,
                    }
                },
                "protocol_hierarchy": [{"protocol": "tls", "bytes": 151_384}],
                "no_traffic_observed": 0,
                "tls_fingerprints": {
                    "client_hello_count": 12,
                    "unique_ja4_count": 4,
                },
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "capture_duration_s": 449.187322,
                    "data_size_bytes": 139_696,
                    "packet_count": 729,
                },
                "proxies": {
                    "unique_domains_topn": 7,
                    "unique_ja4_count": 4,
                    "tls_client_hello_count": 12,
                },
                "quality": {
                    "report_status": "ok",
                    "pcap_valid": True,
                },
                "service_context": {
                    "summary": {
                        "service_count": 3,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.resolve_dataset_plan_read_path",
        lambda: tracker_path,
    )

    def _write_payload(payload):
        tracker_path.write_text(json.dumps(payload), encoding="utf-8")
        return tracker_path

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker.write_dataset_plan_payload",
        _write_payload,
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker._derive_paper_eligibility_fields",
        lambda *args, **kwargs: {
            "paper_eligible": True,
            "paper_exclusion_primary_reason_code": None,
            "paper_exclusion_all_reason_codes": [],
        },
    )
    original_apply_quota_marking = tracker._apply_quota_marking

    def _apply_without_identity_lock(app_entry, cfg, *, package_name=None):
        return original_apply_quota_marking(
            app_entry,
            cfg,
            package_name=package_name,
            scope_tracker_runs_to_active_identity_fn=lambda _pkg, runs, resolve_tracker_run_identity_fn=None: {
                "active_runs": list(runs)
            },
        )

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.dataset_tracker._apply_quota_marking",
        _apply_without_identity_lock,
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-2",
        created_at="2026-07-02T00:00:00Z",
        started_at="2026-07-02T00:00:00Z",
        ended_at="2026-07-02T00:08:00Z",
        status="success",
        dataset={
            "countable": False,
            "valid_dataset_run": True,
            "low_signal": True,
            "low_signal_reasons": ["PCAP_BYTES_LOW", "PCAP_PACKETS_LOW"],
        },
        target={
            "package_name": "com.twitter.android",
            "version_code": "312031000",
            "run_identity": {
                "version_code": "312031000",
                "base_apk_sha256": "sha-current",
            },
        },
        operator={
            "tier": "dataset",
            "run_profile": "baseline_idle",
            "run_sequence": 2,
            "interaction_level": "minimal",
            "counts_toward_completion": True,
        },
        scenario={"id": "paper3_profile_v3"},
        observers=[ObserverRecord(observer_id="pcapdroid_capture", status="ok")],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    update_dataset_tracker(manifest, run_dir, config=DatasetTrackerConfig())

    payload = json.loads(tracker_path.read_text(encoding="utf-8"))
    runs = payload["apps"]["com.twitter.android"]["runs"]
    by_id = {row["run_id"]: row for row in runs}

    assert by_id["run-2"]["valid_dataset_run"] is True
    assert by_id["run-2"]["low_signal"] is False
    assert by_id["run-2"]["low_signal_reasons"] == []
    assert by_id["run-2"]["counts_toward_quota"] is True
    assert by_id["run-2"]["countable"] is True
    assert by_id["run-2"]["extra_run"] == 0
