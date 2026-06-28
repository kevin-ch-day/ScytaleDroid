from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    BASELINE_REQUIRED,
    INTERACTION_REQUIRED,
    TOTAL_REQUIRED_PER_APP,
    DatasetTrackerConfig,
    _apply_quota_marking,
    _known_identity_value,
    evaluate_dataset_validity,
)
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest


def test_known_identity_value_skips_unknown_placeholders() -> None:
    assert _known_identity_value("UNKNOWN", None, "abc123") == "abc123"
    assert _known_identity_value("", "none", "null") is None


def test_research_dataset_alpha_quota_defaults_are_explicit() -> None:
    cfg = DatasetTrackerConfig()

    assert BASELINE_REQUIRED == 3
    assert INTERACTION_REQUIRED == 2
    assert TOTAL_REQUIRED_PER_APP == 5
    assert cfg.baseline_required == 3
    assert cfg.interactive_required == 2


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
