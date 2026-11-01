"""Held-out calibration: whole-session allocation, calibrated comparators, test-only exceedance."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.ml import heldout_calibration as hc


def _windows(rng: random.Random, *, count: int, packets: float, bytes_per_packet: float, spread: float = 0.1):
    rows = []
    for index in range(count):
        p = max(0, int(rng.gauss(packets, packets * spread)))
        rows.append({
            "window_start_s": index * 5.0,
            "window_end_s": index * 5.0 + 10.0,
            "packet_count": p,
            "byte_count": int(p * bytes_per_packet),
            "avg_packet_size_bytes": bytes_per_packet,
        })
    return tuple(rows)


def _sessions(seed: int = 7, *, per_group: int = 8, groups: tuple[str, ...] = ("app.a", "app.b")):
    rng = random.Random(seed)
    sessions = []
    for group in groups:
        for index in range(per_group):
            sessions.append(hc.Session(
                session_id=f"{group}-s{index:02d}", group=group, mode="baseline",
                windows=_windows(rng, count=40, packets=20, bytes_per_packet=400),
                window_size_s=10.0, day=f"2026-11-{(index % 3) + 1:02d}",
            ))
        sessions.append(hc.Session(
            session_id=f"{group}-interactive", group=group, mode="interactive",
            windows=_windows(rng, count=40, packets=60, bytes_per_packet=900), window_size_s=10.0,
        ))
    return sessions


def test_allocation_is_whole_session_deterministic_and_group_balanced():
    sessions = _sessions()
    first = hc.allocate_sessions(sessions, seed="seed-1")
    again = hc.allocate_sessions(sessions, seed="seed-1")
    other = hc.allocate_sessions(sessions, seed="seed-2")
    assert first == again
    assert first.partitions != other.partitions
    all_ids = [sid for ids in first.partitions.values() for sid in ids]
    assert len(all_ids) == len(set(all_ids)) == 16
    for group in ("app.a", "app.b"):
        for name in hc.PARTITIONS:
            assert any(sid.startswith(group) for sid in first.partitions[name]), (group, name)
    assert len(first.partitions["fit"]) == 8 and len(first.partitions["calibrate"]) == 4 and len(first.partitions["test"]) == 4
    assert {reason for _sid, reason in first.excluded} == {"mode=interactive"}
    manifest = first.to_dict()
    assert manifest["unit"] == "whole_session_before_windowing"


def test_allocation_refuses_too_few_sessions_bad_fractions_and_duplicates():
    sessions = _sessions(per_group=2)
    with pytest.raises(ValueError, match="at least 3"):
        hc.allocate_sessions(sessions, seed="s")
    with pytest.raises(ValueError, match="sum to 1"):
        hc.allocate_sessions(_sessions(), seed="s", fractions={"fit": 0.5, "calibrate": 0.5, "test": 0.5})
    duplicated = _sessions() + [_sessions()[0]]
    with pytest.raises(ValueError, match="duplicate"):
        hc.allocate_sessions(duplicated, seed="s")
    with pytest.raises(ValueError, match="no baseline sessions"):
        hc.allocate_sessions([s for s in _sessions() if s.mode != "baseline"], seed="s")


def test_thresholds_come_from_calibrate_partition_and_exceedance_from_test_only(tmp_path: Path):
    sessions = _sessions()
    report = hc.run_heldout_calibration(sessions, seed="seed-1", output_dir=tmp_path)
    allocation = report["allocation"]["partitions"]
    assert report["in_sample"] is False
    assert {row["session_id"] for row in report["test_sessions"]} == set(allocation["test"])
    assert not ({row["session_id"] for row in report["test_sessions"]} & set(allocation["fit"]))
    assert report["calibration"]["session_ids"] == allocation["calibrate"]
    assert report["calibration"]["percentile"] == 95.0
    for name in hc.COMPARATORS:
        assert report["calibration"]["thresholds"][name] > 0
        # Baseline test sessions drawn from the same distribution exceed near the nominal rate.
        fraction = report["test_totals"][name]["exceedance_fraction"]
        assert 0.0 <= fraction <= 0.2, (name, fraction)
    written = json.loads((tmp_path / "heldout_calibration.json").read_text())
    assert written["statement"].startswith("exceedance is stated on held-out test sessions only")
    assert json.loads((tmp_path / "allocation_manifest.json").read_text())["seed"] == "seed-1"


def test_interactive_session_scored_against_calibrated_thresholds_exceeds():
    sessions = _sessions()
    by_id = {s.session_id: s for s in sessions}
    allocation = hc.allocate_sessions(sessions, seed="seed-1")
    comparators = hc.fit_comparators(by_id, allocation)
    calibrated = hc.calibrate_thresholds(by_id, allocation, comparators)
    heavy = by_id["app.a-interactive"]
    scores = comparators.scores(heavy)
    for name in ("packet_rate", "byte_rate", "robust_distance"):
        above = sum(1 for v in scores[name] if v > calibrated.thresholds[name])
        assert above / len(scores[name]) > 0.9, name
    with pytest.raises(ValueError, match="percentile"):
        hc.calibrate_thresholds(by_id, allocation, comparators, percentile=100.0)


def test_in_sample_query_mode_path_is_untouched():
    from scytaledroid.DynamicAnalysis.ml import query_mode_runner

    assert callable(query_mode_runner.run_ml_query_mode)
    assert "heldout" not in query_mode_runner.__doc__.lower() if query_mode_runner.__doc__ else True
