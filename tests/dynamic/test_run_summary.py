from __future__ import annotations

import json
from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionResult
from scytaledroid.DynamicAnalysis import run_summary
from scytaledroid.DynamicAnalysis.run_summary import _build_evidence_lines, print_run_summary
from scytaledroid.Utils.DisplayUtils import colors


def _blocked_result(tmp_path) -> DynamicSessionResult:
    return DynamicSessionResult(
        package_name="com.example.app",
        duration_seconds=30,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="blocked",
        notes="Dynamic execution blocked by plan validation.",
        errors=["fallback blocker", "secondary blocker"],
        dynamic_run_id="run-123",
        evidence_path=str(tmp_path),
    )


def test_print_run_summary_surfaces_plan_validation_blocker_from_event(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "plan.validation",
        "details": {
            "validation_result": "FAIL",
            "reasons": ["missing required fields: run_signature"],
            "warnings": ["base_apk_sha256 mismatch"],
            "summary": {
                "reason_count": 1,
                "warning_count": 1,
                "mismatch_count": 2,
                "db_row_found": True,
                "has_static_link": True,
            },
        },
    }
    (notes_dir / "run_events.jsonl").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation." in out
    assert "missing required fields: run_signature" in out
    assert "mismatches=2" in out
    assert "warnings=1" in out


def test_print_run_summary_falls_back_to_result_errors_when_event_missing(tmp_path, capsys) -> None:
    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation. fallback blocker" in out


def test_print_run_summary_separates_run_mode_from_wall_clock(tmp_path, capsys) -> None:
    print_run_summary(_blocked_result(tmp_path), "Cohort")

    out = colors.strip(capsys.readouterr().out)
    assert "Run mode" in out
    assert "Cohort" in out
    assert "Session wall-clock" in out
    assert "Cohort (30s)" not in out


def test_print_run_summary_distinguishes_missing_tools_blockers(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "preflight.tools_missing",
        "details": {
            "missing_tools": ["tshark", "capinfos"],
            "tier": "dataset",
        },
    }
    (notes_dir / "run_events.jsonl").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked: missing required host tools." in out
    assert "missing_tools=tshark,capinfos" in out


def test_print_run_summary_ignores_malformed_event_lines_when_resolving_blocker(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    valid_payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "plan.validation",
        "details": {
            "validation_result": "FAIL",
            "reasons": ["unsupported run_signature_version: v0"],
            "warnings": [],
            "summary": {
                "reason_count": 1,
                "warning_count": 0,
                "mismatch_count": 0,
                "db_row_found": True,
                "has_static_link": False,
            },
        },
    }
    (notes_dir / "run_events.jsonl").write_text(
        "{not-json}\n" + json.dumps(valid_payload) + "\n",
        encoding="utf-8",
    )

    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation." in out
    assert "unsupported run_signature_version: v0" in out


def test_build_evidence_lines_prefers_pcap_failure_summary_from_manifest(capsys) -> None:
    lines = _build_evidence_lines(
        run_dir=None,
        summary_payload={
            "capture": {
                "pcap_valid": False,
                "pcap_size_bytes": 0,
                "capture_mode": "app_only",
                "min_pcap_bytes": 50000,
            }
        },
        pcap_report=None,
        pcap_features=None,
        artifacts=[],
        manifest={
            "dataset": {
                "pcap_failure_summary": "Network traffic was observed by Android netstats, but the PCAP capture artifact is empty or unavailable."
            }
        },
    )

    out = colors.strip(capsys.readouterr().out)
    assert "Network traffic was observed by Android netstats" in out
    assert "PCAP invalid (0B < 50000B)" not in out
    assert lines[0] == "PCAP: app_only | 0B | invalid"


def test_countability_detail_keeps_baseline_connected_countable_when_low_signal(monkeypatch) -> None:
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.whatsapp": {
                    "runs": [
                        {
                            "run_id": "run-wa-1",
                            "run_profile": "baseline_connected",
                            "valid_dataset_run": True,
                            "countable": True,
                            "low_signal": True,
                            "paper_exclusion_primary_reason_code": None,
                        }
                    ]
                }
            }
        },
    )
    monkeypatch.setattr(
        run_summary,
        "_load_manifest",
        lambda _path: {
            "dataset": {
                "low_signal": True,
            }
        },
    )

    detail = run_summary._countability_detail("com.whatsapp", "run-wa-1")

    assert detail == "source=tracker_quota_marking, countable=true"


def test_countability_detail_marks_baseline_idle_low_signal_as_nonquota(monkeypatch) -> None:
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.example.idle": {
                    "runs": [
                        {
                            "run_id": "run-idle-1",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "countable": False,
                            "low_signal": True,
                            "paper_exclusion_primary_reason_code": None,
                        }
                    ]
                }
            }
        },
    )
    monkeypatch.setattr(
        run_summary,
        "_load_manifest",
        lambda _path: {
            "dataset": {
                "low_signal": True,
            }
        },
    )

    detail = run_summary._countability_detail("com.example.idle", "run-idle-1")

    assert detail == "source=low_signal_policy, countable=false, reason=LOW_SIGNAL_IDLE"


def test_countability_detail_marks_baseline_not_idle_as_nonquota(monkeypatch) -> None:
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.facebook.katana": {
                    "runs": [
                        {
                            "run_id": "run-fb-1",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "countable": False,
                            "extra_run": 1,
                            "baseline_not_idle": True,
                            "paper_exclusion_primary_reason_code": None,
                        }
                    ]
                }
            }
        },
    )
    monkeypatch.setattr(
        run_summary,
        "_load_manifest",
        lambda _path: {
            "dataset": {
                "baseline_not_idle": True,
            }
        },
    )

    detail = run_summary._countability_detail("com.facebook.katana", "run-fb-1")

    assert detail == "source=baseline_activity_policy, countable=false, reason=BASELINE_NOT_IDLE"


def test_countability_detail_prefers_tracker_non_idle_truth_over_stale_manifest(monkeypatch) -> None:
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.facebook.katana": {
                    "runs": [
                        {
                            "run_id": "run-fb-1",
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "countable": False,
                            "baseline_not_idle": True,
                        }
                    ]
                }
            }
        },
    )
    monkeypatch.setattr(
        run_summary,
        "_load_manifest",
        lambda _path: {
            "dataset": {
                "baseline_not_idle": False,
            }
        },
    )

    detail = run_summary._countability_detail("com.facebook.katana", "run-fb-1")

    assert detail == "source=baseline_activity_policy, countable=false, reason=BASELINE_NOT_IDLE"


def test_print_run_summary_explains_baseline_not_idle_extra(monkeypatch, tmp_path, capsys) -> None:
    run_id = "run-fb-1"
    run_dir = tmp_path / run_id
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {"package_name": "com.facebook.katana"},
                "operator": {"run_profile": "baseline_idle", "interaction_level": "minimal"},
                "dataset": {
                    "valid_dataset_run": True,
                    "countable": False,
                    "extra_run": 1,
                    "baseline_not_idle": True,
                    "technical_validity": "VALID",
                    "protocol_compliance": "COMPLIANT",
                    "cohort_eligibility": "EXTRA",
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps({"capinfos": {"parsed": {"capture_duration_s": 240.0, "data_size_bytes": 9_600_000}}}),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_features.json").write_text(
        json.dumps(
            {
                "metrics": {
                    "bytes_per_second_avg": 40_000.0,
                    "bytes_per_second_p95": 410_000.0,
                },
                "proxies": {"quic_ratio": 0.72},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.facebook.katana": {
                    "valid_runs": 4,
                    "target_runs": 7,
                    "runs": [
                        {
                            "run_id": run_id,
                            "run_profile": "baseline_idle",
                            "valid_dataset_run": True,
                            "countable": False,
                            "extra_run": 1,
                            "baseline_not_idle": True,
                            "baseline_not_idle_reasons": [
                                "BASELINE_BYTES_HIGH",
                                "BASELINE_QUIC_MEDIA_HEAVY",
                                "BASELINE_P95_BURSTY",
                            ],
                            "technical_validity": "VALID",
                            "protocol_compliance": "COMPLIANT",
                            "cohort_eligibility": "EXTRA",
                        }
                    ],
                }
            }
        },
    )
    monkeypatch.setattr(run_summary.prompt_utils, "prompt_yes_no", lambda *_a, **_k: False)
    result = DynamicSessionResult(
        package_name="com.facebook.katana",
        duration_seconds=240,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="success",
        dynamic_run_id=run_id,
        evidence_path=str(run_dir),
    )

    print_run_summary(result, "Cohort")

    out = colors.strip(capsys.readouterr().out)
    assert "excluded from idle-baseline quota because runtime traffic exceeded idle-baseline limits" in out
    assert "Reasons" in out
    assert "total bytes crossed the idle-baseline limit" in out
    assert "QUIC-heavy transport crossed the idle-baseline limit" in out
    assert "Retained as" in out
    assert "non-idle baseline evidence" in out
    assert "Included in idle ML pool" in out
    assert "no" in out
    assert "Duration" in out
    assert "Total bytes" in out
    assert "MB" in out
    assert "Avg bytes/sec" in out
    assert "40,000 B/s" in out
    assert "P95 bytes/sec" in out
    assert "410,000 B/s" in out
    assert "QUIC ratio" in out
    assert "0.72" in out
    assert "Threshold crossed" in out
    assert "total bytes, QUIC ratio, p95 bytes/sec" in out
    assert "Repeat with stricter idle behavior if quota progress is needed." in out


def test_countability_label_treats_manual_extra_run_as_extra_not_exploratory() -> None:
    label = run_summary._countability_label(
        {
            "valid_dataset_run": True,
            "countable": False,
            "low_signal": False,
            "cohort_eligibility": "EXTRA",
            "paper_exclusion_primary_reason_code": None,
        },
        "interaction_manual",
    )

    assert label == "NO (extra run)"


def test_countability_label_keeps_manual_non_cohort_reason_when_explicit() -> None:
    label = run_summary._countability_label(
        {
            "valid_dataset_run": True,
            "countable": False,
            "low_signal": False,
            "cohort_eligibility": "SUPPLEMENTAL_VALID",
            "paper_exclusion_primary_reason_code": "EXCLUDED_MANUAL_NON_COHORT",
        },
        "interaction_manual",
    )

    assert label == "NO (manual exploratory)"
