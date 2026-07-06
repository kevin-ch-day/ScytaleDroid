from __future__ import annotations

import json
from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis import run_summary
from scytaledroid.DynamicAnalysis.core.session import DynamicSessionResult
from scytaledroid.Utils.DisplayUtils import colors


def test_countability_detail_keeps_baseline_connected_countable_when_low_signal(
    monkeypatch,
) -> None:
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


def test_print_run_summary_explains_quiet_connected_messaging_baseline(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    run_id = "run-signal-1"
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {"package_name": "org.thoughtcrime.securesms"},
                "operator": {
                    "run_profile": "baseline_connected",
                    "interaction_level": "minimal",
                    "messaging_activity": "connected_idle",
                },
                "dataset": {
                    "valid_dataset_run": True,
                    "countable": True,
                    "low_signal": True,
                    "technical_validity": "VALID",
                    "protocol_compliance": "COMPLIANT",
                    "cohort_eligibility": "COUNTABLE",
                    "min_pcap_bytes": 10000,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_summary, "resolve_evidence_path", lambda _p: run_dir)
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "org.thoughtcrime.securesms": {
                    "valid_runs": 1,
                    "target_runs": 7,
                    "runs": [
                        {
                            "run_id": run_id,
                            "run_profile": "baseline_connected",
                            "valid_dataset_run": True,
                            "countable": True,
                            "counts_toward_quota": True,
                            "low_signal": True,
                            "paper_exclusion_primary_reason_code": None,
                        }
                    ],
                }
            }
        },
    )
    monkeypatch.setattr(run_summary, "_load_summary", lambda _run_dir: None)
    monkeypatch.setattr(run_summary, "_load_engine_summary", lambda _run_dir: None)
    monkeypatch.setattr(run_summary, "_load_json", lambda _path: None)
    monkeypatch.setattr(run_summary.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: False)

    started_at = datetime(2026, 7, 6, 6, 8, 12, tzinfo=UTC)
    result = DynamicSessionResult(
        package_name="org.thoughtcrime.securesms",
        duration_seconds=250,
        started_at=started_at,
        ended_at=started_at,
        status="success",
        dynamic_run_id=run_id,
        evidence_path=str(run_dir),
    )

    run_summary.print_run_summary(result, "Cohort")
    out = capsys.readouterr().out

    assert "Counts toward quota" in out
    assert "YES (baseline_connected)" in out
    assert "Messaging note" in out
    assert "low traffic alone does not mean the baseline failed" in out


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


def test_countability_detail_prefers_tracker_non_idle_truth_over_stale_manifest(
    monkeypatch,
) -> None:
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
                "target": {"package_name": "com.example.idle"},
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
        json.dumps(
            {"capinfos": {"parsed": {"capture_duration_s": 240.0, "data_size_bytes": 9_600_000}}}
        ),
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
                "startup_profile": {
                    "summary": {
                        "startup_byte_share": 0.91,
                        "post_start_median_bytes_per_min": 18_704.0,
                        "startup_dominant": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.example.idle": {
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
        package_name="com.example.idle",
        duration_seconds=240,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="success",
        dynamic_run_id=run_id,
        evidence_path=str(run_dir),
    )

    run_summary.print_run_summary(result, "Cohort")

    out = colors.strip(capsys.readouterr().out)
    assert (
        "excluded from idle-baseline quota because runtime traffic exceeded idle-baseline limits"
        in out
    )
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
    assert "Traffic shape" in out
    assert "startup-burst then quiet-tail" in out
    assert "Startup byte share" in out
    assert "91.0%" in out
    assert "Post-start median" in out
    assert "18,704 B/min" in out
    assert "Threshold crossed" in out
    assert "total bytes, QUIC ratio, p95 bytes/sec" in out
    assert "Repeat with stricter idle behavior if quota progress is needed." in out


def test_print_run_summary_gives_social_feed_specific_next_baseline_guidance(
    monkeypatch, tmp_path, capsys
) -> None:
    run_id = "run-x-1"
    run_dir = tmp_path / run_id
    (run_dir / "analysis").mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {"package_name": "com.twitter.android"},
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
        json.dumps(
            {"capinfos": {"parsed": {"capture_duration_s": 240.0, "data_size_bytes": 9_600_000}}}
        ),
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
                "startup_profile": {
                    "summary": {
                        "startup_byte_share": 0.947,
                        "post_start_median_bytes_per_min": 18_704.0,
                        "startup_dominant": True,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        run_summary,
        "load_dataset_tracker",
        lambda: {
            "apps": {
                "com.twitter.android": {
                    "valid_runs": 2,
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
        package_name="com.twitter.android",
        duration_seconds=240,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="success",
        dynamic_run_id=run_id,
        evidence_path=str(run_dir),
    )

    run_summary.print_run_summary(result, "Cohort")

    out = colors.strip(capsys.readouterr().out)
    assert "Pattern hint" in out
    assert "large startup/feed-media burst followed by a quieter tail" in out
    assert (
        "Retry on profile, settings, bookmarks, lists, or another stable non-feed/non-video X screen if quota progress is needed."
        in out
    )


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


def test_print_run_summary_does_not_mislabel_invalid_missing_pcap_as_low_signal(
    monkeypatch, tmp_path, capsys
) -> None:
    run_id = "run-signal-1"
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "target": {"package_name": "org.thoughtcrime.securesms"},
                "operator": {"run_profile": "baseline_idle", "interaction_level": "minimal"},
                "dataset": {
                    "valid_dataset_run": False,
                    "countable": False,
                    "invalid_reason_code": "PCAP_MISSING",
                    "technical_validity": "INVALID",
                    "protocol_compliance": "COMPLIANT",
                    "cohort_eligibility": "EXCLUDED",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_summary.prompt_utils, "prompt_yes_no", lambda *_a, **_k: False)
    monkeypatch.setattr(run_summary, "_load_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(run_summary, "_load_engine_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(run_summary, "_load_db_persistence_status", lambda *_a, **_k: None)

    result = DynamicSessionResult(
        package_name="org.thoughtcrime.securesms",
        duration_seconds=180,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="failed",
        dynamic_run_id=run_id,
        evidence_path=str(run_dir),
    )

    run_summary.print_run_summary(result, "Cohort")

    out = colors.strip(capsys.readouterr().out)
    assert "Dataset verdict" in out
    assert "INVALID: PCAP_MISSING" in out
    assert "LOW_SIGNAL_IDLE" not in out
    assert "retained, not quota-counted" not in out
