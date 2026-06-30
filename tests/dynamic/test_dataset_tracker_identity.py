from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    BASELINE_REQUIRED,
    INTERACTION_REQUIRED,
    TOTAL_REQUIRED_PER_APP,
    DatasetTrackerConfig,
    _should_ignore_stale_explicit_noncountable,
    _apply_quota_marking,
    _known_identity_value,
    evaluate_dataset_validity,
    recompute_dataset_tracker,
    update_dataset_tracker,
)
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, ObserverRecord, RunManifest


def test_known_identity_value_skips_unknown_placeholders() -> None:
    assert _known_identity_value("UNKNOWN", None, "abc123") == "abc123"
    assert _known_identity_value("", "none", "null") is None


def test_research_dataset_alpha_quota_defaults_are_explicit() -> None:
    cfg = DatasetTrackerConfig()

    assert BASELINE_REQUIRED == 3
    assert INTERACTION_REQUIRED == 4
    assert TOTAL_REQUIRED_PER_APP == 7
    assert cfg.baseline_required == 3
    assert cfg.interactive_required == 4


def test_interaction_before_baseline_quota_is_supplemental() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T01:00:00+00:00",
            },
            {
                "run_id": "i1",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T02:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T03:00:00+00:00",
            },
            {
                "run_id": "b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T04:00:00+00:00",
            },
            {
                "run_id": "i2",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T05:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["b1"]["counts_toward_quota"] is True
    assert by_id["i1"]["counts_toward_quota"] is False
    assert by_id["i1"]["extra_run"] == 1
    assert by_id["b2"]["counts_toward_quota"] is True
    assert by_id["b3"]["counts_toward_quota"] is True
    assert by_id["i2"]["counts_toward_quota"] is True
    assert app_entry["quota_met"] is False


def test_quota_marking_scopes_current_build_separately_from_legacy_runs() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "legacy-b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "311990001",
                "base_apk_sha256": "legacysha",
                "started_at": "2026-06-15T01:00:00+00:00",
            },
            {
                "run_id": "legacy-b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "311990001",
                "base_apk_sha256": "legacysha",
                "started_at": "2026-06-15T02:00:00+00:00",
            },
            {
                "run_id": "legacy-b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "311990001",
                "base_apk_sha256": "legacysha",
                "started_at": "2026-06-15T03:00:00+00:00",
            },
            {
                "run_id": "current-b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "312021000",
                "base_apk_sha256": "currentsha",
                "started_at": "2026-06-26T01:00:00+00:00",
            },
            {
                "run_id": "current-b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "312021000",
                "base_apk_sha256": "currentsha",
                "started_at": "2026-06-26T02:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(
        app_entry,
        cfg,
        package_name="com.twitter.android",
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        scope_tracker_runs_to_active_identity_fn=lambda _pkg, runs, resolve_tracker_run_identity_fn: {
            "active_identity": ("312021000", "currentsha"),
            "active_runs": [r for r in runs if r.get("base_apk_sha256") == "currentsha"],
            "valid_runs": list(runs),
            "legacy_runs": [r for r in runs if r.get("base_apk_sha256") == "legacysha"],
            "legacy_valid": 3,
            "legacy_builds": 1,
        },
    )

    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["legacy-b1"]["counts_toward_quota"] is False
    assert by_id["legacy-b1"]["extra_run"] == 0
    assert by_id["legacy-b2"]["counts_toward_quota"] is False
    assert by_id["legacy-b3"]["counts_toward_quota"] is False
    assert by_id["current-b1"]["counts_toward_quota"] is True
    assert by_id["current-b2"]["counts_toward_quota"] is True
    assert app_entry["quota_met"] is False
    assert app_entry["extra_valid_runs"] == 0


def test_low_signal_baseline_idle_is_supplemental_extra_not_countable() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "low_signal": False,
                "started_at": "2026-06-28T01:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "low_signal": False,
                "started_at": "2026-06-28T02:00:00+00:00",
            },
            {
                "run_id": "b3-low",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "low_signal": True,
                "low_signal_reasons": ["PCAP_BYTES_LOW"],
                "started_at": "2026-06-28T03:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["b1"]["counts_toward_quota"] is True
    assert by_id["b2"]["counts_toward_quota"] is True
    assert by_id["b3-low"]["counts_toward_quota"] is False
    assert by_id["b3-low"]["countable"] is False
    assert by_id["b3-low"]["extra_run"] == 1
    assert by_id["b3-low"]["cohort_eligibility"] == "EXTRA"
    assert app_entry["extra_valid_runs"] == 1


def test_explicit_non_countable_interactive_run_stays_supplemental() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T01:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T02:00:00+00:00",
            },
            {
                "run_id": "b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T03:00:00+00:00",
            },
            {
                "run_id": "i1",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T04:00:00+00:00",
            },
            {
                "run_id": "i2-extra",
                "run_profile": "interaction_manual",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "cohort_eligibility": "EXTRA",
                "started_at": "2026-06-29T05:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["i1"]["counts_toward_quota"] is True
    assert by_id["i2-extra"]["counts_toward_quota"] is False
    assert by_id["i2-extra"]["countable"] is False
    assert by_id["i2-extra"]["extra_run"] == 1
    assert by_id["i2-extra"]["cohort_eligibility"] == "EXTRA"
    assert app_entry["extra_valid_runs"] == 1
    assert app_entry["quota_met"] is False


def test_explicit_countable_interactive_runs_survive_recompute_ordering() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T01:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T02:00:00+00:00",
            },
            {
                "run_id": "b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T03:00:00+00:00",
            },
            {
                "run_id": "i1",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T04:00:00+00:00",
            },
            {
                "run_id": "i2",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T05:00:00+00:00",
            },
            {
                "run_id": "i3-extra",
                "run_profile": "interaction_manual",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "cohort_eligibility": "EXTRA",
                "started_at": "2026-06-29T06:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["i1"]["counts_toward_quota"] is True
    assert by_id["i2"]["counts_toward_quota"] is True
    assert by_id["i1"]["countable"] is True
    assert by_id["i2"]["countable"] is True
    assert by_id["i3-extra"]["counts_toward_quota"] is False
    assert by_id["i3-extra"]["countable"] is False
    assert by_id["i3-extra"]["extra_run"] == 1
    assert app_entry["extra_valid_runs"] == 1
    assert app_entry["quota_met"] is False


def test_recompute_dataset_tracker_preserves_manifest_dataset_fields(tmp_path: Path, monkeypatch) -> None:
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

    monkeypatch.setattr("scytaledroid.DynamicAnalysis.pcap.dataset_tracker.app_config.OUTPUT_DIR", str(tmp_path / "output"))
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


def test_should_ignore_stale_explicit_noncountable_for_repaired_quota_run() -> None:
    assert _should_ignore_stale_explicit_noncountable(
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
    ) is True

    assert _should_ignore_stale_explicit_noncountable(
        {
            "countable": False,
            "valid_dataset_run": True,
        },
        {"counts_toward_completion": True},
        {"valid_dataset_run": True},
    ) is False

    assert _should_ignore_stale_explicit_noncountable(
        {
            "countable": False,
            "valid_dataset_run": False,
        },
        {"counts_toward_completion": False},
        {"valid_dataset_run": True},
    ) is False


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
        json.dumps({"telemetry": {"stats": {"netstats_bytes_in_total": 5340, "netstats_bytes_out_total": 7268}}}),
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
        observers=[ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")],
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


def test_evaluate_dataset_validity_uses_summary_netstats_when_entry_omits_total(tmp_path: Path) -> None:
    run_dir = tmp_path / "dynamic" / "run-1"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "summary.json").write_text(
        json.dumps(
            {
                "telemetry": {
                    "stats": {
                        "netstats_bytes_in_total": 1_500_000,
                        "netstats_bytes_out_total": 250_000,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "report_status": "ok",
                "capinfos": {
                    "parsed": {
                        "capture_duration_s": 240.0,
                        "packet_count": 4096,
                        "data_size_bytes": 512_000,
                    }
                },
                "protocol_hierarchy": [{"protocol": "ip", "bytes": 4096, "frames": 16}],
                "no_traffic_observed": 0,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(json.dumps({"metrics": {}, "proxies": {}}), encoding="utf-8")

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-28T00:00:00Z",
        operator={
            "run_profile": "baseline_idle",
            "run_sequence": 1,
            "interaction_level": "minimal",
        },
    )

    validity = evaluate_dataset_validity(
        run_dir,
        manifest,
        {"pcap_size_bytes": 512_000},
        DatasetTrackerConfig(),
    )

    assert validity["valid_dataset_run"] is True
    assert validity["netstats_observed_bytes"] == 1_750_000


def test_evaluate_dataset_validity_treats_small_existing_pcap_as_too_small_not_missing(tmp_path: Path) -> None:
    run_dir = tmp_path / "dynamic" / "run-1"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 20712
    (capture_dir / "scytaledroid_run-1.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-1.pcap",
                "resolved_pcap_name": "scytaledroid_run-1.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 50000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"netstats_bytes_in_total": 5340, "netstats_bytes_out_total": 7268}}}),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps({"report_status": "ok", "capinfos": {"parsed": {"capture_duration_s": 480.0, "packet_count": 199, "data_size_bytes": pcap_bytes}}}),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(json.dumps({"metrics": {}, "proxies": {}}), encoding="utf-8")

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-30T00:00:00Z",
        operator={"run_profile": "baseline_idle", "run_sequence": 3, "interaction_level": "minimal"},
        observers=[ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is False
    assert validity["invalid_reason_code"] == "PCAP_TOO_SMALL"
    assert validity.get("pcap_size_bytes") is None or validity.get("pcap_size_bytes") == pcap_bytes


def test_evaluate_dataset_validity_accepts_small_connected_baseline_above_connected_floor(tmp_path: Path) -> None:
    run_dir = tmp_path / "dynamic" / "run-2"
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    analysis_dir = run_dir / "analysis"
    capture_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = 20712
    (capture_dir / "scytaledroid_run-2.pcap").write_bytes(b"x" * pcap_bytes)
    (capture_dir / "pcapdroid_capture_meta.json").write_text(
        json.dumps(
            {
                "pcap_name": "scytaledroid_run-2.pcap",
                "resolved_pcap_name": "scytaledroid_run-2.pcap",
                "pcap_size_bytes": pcap_bytes,
                "pcap_valid": False,
                "min_pcap_bytes": 50000,
            }
        ),
        encoding="utf-8",
    )
    (analysis_dir / "summary.json").write_text(
        json.dumps({"telemetry": {"stats": {"netstats_bytes_in_total": 5340, "netstats_bytes_out_total": 7268}}}),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_report.json").write_text(
        json.dumps({"report_status": "ok", "capinfos": {"parsed": {"capture_duration_s": 480.0, "packet_count": 199, "data_size_bytes": pcap_bytes}}, "protocol_hierarchy": [{"protocol": "tls", "bytes": pcap_bytes}]}),
        encoding="utf-8",
    )
    (analysis_dir / "pcap_features.json").write_text(
        json.dumps({"metrics": {}, "proxies": {}, "quality": {"report_status": "ok", "pcap_enrichment": {"status": "ok"}}}),
        encoding="utf-8",
    )

    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-2",
        created_at="2026-06-30T00:00:00Z",
        scenario={"id": "paper3_profile_v3"},
        operator={"run_profile": "baseline_connected", "run_sequence": 3, "interaction_level": "minimal"},
        observers=[ObserverRecord(observer_id="pcapdroid_capture", status="failed", error="too small")],
        artifacts=[
            ArtifactRecord(
                relative_path="artifacts/pcapdroid_capture/pcapdroid_capture_meta.json",
                type="pcapdroid_capture_meta",
                produced_by="pcapdroid_capture",
            )
        ],
    )

    validity = evaluate_dataset_validity(run_dir, manifest, {}, DatasetTrackerConfig())

    assert validity["valid_dataset_run"] is True
    assert validity["invalid_reason_code"] is None
    assert validity["min_pcap_bytes"] == 20_000
    assert validity.get("pcap_size_bytes") == pcap_bytes
