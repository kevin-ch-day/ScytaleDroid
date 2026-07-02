from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.baseline_activity import compute_baseline_activity_for_run


def _write_features(tmp_path: Path, payload: dict) -> Path:
    run_dir = tmp_path / "run"
    analysis = run_dir / "analysis"
    analysis.mkdir(parents=True)
    path = analysis / "pcap_features.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return run_dir


def test_baseline_activity_flags_reddit_like_heavy_idle_capture(tmp_path: Path) -> None:
    run_dir = _write_features(
        tmp_path,
        {
            "metrics": {
                "capture_duration_s": 240.0,
                "data_size_bytes": 31_000_000,
                "bytes_per_sec": 129_000.0,
                "bytes_per_second_p95": 700_000.0,
            },
            "proxies": {
                "quic_ratio": 0.95,
            },
        },
    )

    decision = compute_baseline_activity_for_run(
        run_dir,
        package_name="com.reddit.frontpage",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["baseline_not_idle"] is True
    assert "BASELINE_BYTES_HIGH" in decision["baseline_not_idle_reasons"]
    assert "BASELINE_QUIC_MEDIA_HEAVY" in decision["baseline_not_idle_reasons"]
    assert decision["exploratory_class"] == "BASELINE_NOT_IDLE"


def test_baseline_activity_ignores_non_baseline_profiles(tmp_path: Path) -> None:
    run_dir = _write_features(
        tmp_path,
        {
            "metrics": {"capture_duration_s": 240.0, "data_size_bytes": 40_000_000, "bytes_per_sec": 200_000.0},
            "proxies": {"quic_ratio": 0.9},
        },
    )

    decision = compute_baseline_activity_for_run(
        run_dir,
        package_name="com.reddit.frontpage",
        run_profile="interaction_scripted",
    )

    assert decision is None


def test_baseline_activity_keeps_quiet_idle_baseline(tmp_path: Path) -> None:
    run_dir = _write_features(
        tmp_path,
        {
            "metrics": {
                "capture_duration_s": 240.0,
                "data_size_bytes": 2_500_000,
                "bytes_per_sec": 10_000.0,
                "bytes_per_second_p95": 40_000.0,
            },
            "proxies": {
                "quic_ratio": 0.2,
            },
        },
    )

    decision = compute_baseline_activity_for_run(
        run_dir,
        package_name="com.reddit.frontpage",
        run_profile="baseline_idle",
    )

    assert decision is not None
    assert decision["baseline_not_idle"] is False
    assert decision["baseline_not_idle_reasons"] == []
