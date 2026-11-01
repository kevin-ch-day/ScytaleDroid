"""Opt-in held-out calibration for dynamic telemetry windows.

The existing query-mode path (``query_mode_runner.run_ml_query_mode``) fits
and thresholds on the same training windows. This module is a separate,
opt-in path: whole sessions are allocated to fit / calibrate / held-out test
partitions *before* windowing, simple comparators are fitted on the fit
partition, their thresholds are set on the calibrate partition, and
exceedance is reported on held-out test sessions only. Nothing here reads a
device, writes into a sealed evidence pack or changes the in-sample path.
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONTRACT = "heldout_calibration_v1"
PARTITIONS = ("fit", "calibrate", "test")
COMPARATORS = ("packet_rate", "byte_rate", "robust_distance")
DEFAULT_FRACTIONS = {"fit": 0.5, "calibrate": 0.25, "test": 0.25}
DEFAULT_CALIBRATION_PERCENTILE = 95.0
ROBUST_FEATURES = ("packet_count", "byte_count", "avg_packet_size_bytes")
MIN_SESSIONS_PER_PARTITION = 1


@dataclass(frozen=True)
class Session:
    """One capture session: an unsplittable allocation unit."""

    session_id: str
    group: str
    mode: str
    windows: tuple[Mapping[str, Any], ...]
    window_size_s: float
    day: str | None = None

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("session_id is required")
        if self.mode not in {"baseline", "interactive", "unknown"}:
            raise ValueError(f"unsupported session mode: {self.mode}")
        if self.window_size_s <= 0:
            raise ValueError("window_size_s must be positive")


@dataclass(frozen=True)
class Allocation:
    seed: str
    fractions: Mapping[str, float]
    partitions: Mapping[str, tuple[str, ...]]
    excluded: tuple[tuple[str, str], ...] = ()

    def partition_of(self, session_id: str) -> str | None:
        for name, ids in self.partitions.items():
            if session_id in ids:
                return name
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": CONTRACT,
            "seed": self.seed,
            "fractions": dict(self.fractions),
            "partitions": {name: list(ids) for name, ids in self.partitions.items()},
            "excluded": [{"session_id": sid, "reason": reason} for sid, reason in self.excluded],
            "unit": "whole_session_before_windowing",
        }


def _stable_rank(seed: str, session_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{session_id}".encode()).hexdigest()


def allocate_sessions(
    sessions: Sequence[Session],
    *,
    seed: str,
    fractions: Mapping[str, float] | None = None,
) -> Allocation:
    """Allocate whole baseline sessions per group to fit / calibrate / test.

    Allocation is deterministic for a seed: sessions are ordered by a keyed
    hash of their id, then split per group by the fractions. Interactive and
    unknown sessions are excluded from allocation (they are never a baseline
    reference) and listed with the reason. Every partition must receive at
    least one session in every group, otherwise allocation refuses.
    """
    fractions = dict(fractions or DEFAULT_FRACTIONS)
    if set(fractions) != set(PARTITIONS) or any(v <= 0 for v in fractions.values()):
        raise ValueError("fractions must name fit, calibrate and test with positive values")
    total = sum(fractions.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError("fractions must sum to 1")
    seen: set[str] = set()
    excluded: list[tuple[str, str]] = []
    by_group: dict[str, list[Session]] = {}
    for session in sessions:
        if session.session_id in seen:
            raise ValueError(f"duplicate session_id: {session.session_id}")
        seen.add(session.session_id)
        if session.mode != "baseline":
            excluded.append((session.session_id, f"mode={session.mode}"))
            continue
        if not session.windows:
            excluded.append((session.session_id, "no_windows"))
            continue
        by_group.setdefault(session.group, []).append(session)
    if not by_group:
        raise ValueError("no baseline sessions with windows to allocate")
    partitions: dict[str, list[str]] = {name: [] for name in PARTITIONS}
    for group in sorted(by_group):
        ordered = sorted(by_group[group], key=lambda s: _stable_rank(seed, s.session_id))
        count = len(ordered)
        if count < len(PARTITIONS) * MIN_SESSIONS_PER_PARTITION:
            raise ValueError(
                f"group {group!r} has {count} baseline sessions; "
                f"at least {len(PARTITIONS)} are needed for whole-session allocation"
            )
        fit_n = max(MIN_SESSIONS_PER_PARTITION, int(math.floor(count * fractions["fit"])))
        cal_n = max(MIN_SESSIONS_PER_PARTITION, int(math.floor(count * fractions["calibrate"])))
        test_n = count - fit_n - cal_n
        if test_n < MIN_SESSIONS_PER_PARTITION:
            test_n = MIN_SESSIONS_PER_PARTITION
            fit_n = count - cal_n - test_n
        if fit_n < MIN_SESSIONS_PER_PARTITION:
            raise ValueError(f"group {group!r}: fractions leave no fit session")
        ids = [s.session_id for s in ordered]
        partitions["fit"].extend(ids[:fit_n])
        partitions["calibrate"].extend(ids[fit_n:fit_n + cal_n])
        partitions["test"].extend(ids[fit_n + cal_n:])
    return Allocation(
        seed=seed,
        fractions=fractions,
        partitions={name: tuple(ids) for name, ids in partitions.items()},
        excluded=tuple(excluded),
    )


def _rate(window: Mapping[str, Any], key: str, window_size_s: float) -> float:
    return float(window.get(key) or 0) / float(window_size_s)


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        raise ValueError("percentile of an empty sequence")
    ordered = sorted(float(v) for v in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * (q / 100.0)
    lower = int(math.floor(position))
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


@dataclass(frozen=True)
class RobustReference:
    medians: Mapping[str, float]
    mads: Mapping[str, float]

    def distance(self, window: Mapping[str, Any]) -> float:
        parts = []
        for feature in ROBUST_FEATURES:
            value = float(window.get(feature) or 0.0)
            mad = self.mads[feature]
            scale = mad if mad > 0 else 1.0
            parts.append(abs(value - self.medians[feature]) / scale)
        return max(parts) if parts else 0.0


def fit_robust_reference(windows: Iterable[Mapping[str, Any]]) -> RobustReference:
    columns: dict[str, list[float]] = {feature: [] for feature in ROBUST_FEATURES}
    for window in windows:
        for feature in ROBUST_FEATURES:
            columns[feature].append(float(window.get(feature) or 0.0))
    if not columns[ROBUST_FEATURES[0]]:
        raise ValueError("robust reference needs at least one window")
    medians = {feature: statistics.median(values) for feature, values in columns.items()}
    mads = {
        feature: statistics.median([abs(v - medians[feature]) for v in values])
        for feature, values in columns.items()
    }
    return RobustReference(medians=medians, mads=mads)


@dataclass(frozen=True)
class Comparators:
    """Fitted on the fit partition; scores are comparable across partitions."""

    reference: RobustReference
    fit_session_ids: tuple[str, ...]
    fit_windows: int

    def scores(self, session: Session) -> dict[str, list[float]]:
        return {
            "packet_rate": [_rate(w, "packet_count", session.window_size_s) for w in session.windows],
            "byte_rate": [_rate(w, "byte_count", session.window_size_s) for w in session.windows],
            "robust_distance": [self.reference.distance(w) for w in session.windows],
        }


def fit_comparators(sessions: Mapping[str, Session], allocation: Allocation) -> Comparators:
    fit_ids = allocation.partitions["fit"]
    windows = [w for sid in fit_ids for w in sessions[sid].windows]
    return Comparators(
        reference=fit_robust_reference(windows),
        fit_session_ids=tuple(fit_ids),
        fit_windows=len(windows),
    )


@dataclass(frozen=True)
class CalibratedThresholds:
    percentile: float
    thresholds: Mapping[str, float]
    calibrate_session_ids: tuple[str, ...]
    calibrate_windows: int
    calibrate_exceedance: Mapping[str, float] = field(default_factory=dict)


def calibrate_thresholds(
    sessions: Mapping[str, Session],
    allocation: Allocation,
    comparators: Comparators,
    *,
    percentile: float = DEFAULT_CALIBRATION_PERCENTILE,
) -> CalibratedThresholds:
    """Set each comparator's threshold at a percentile of calibrate-partition scores."""
    if not 50.0 <= percentile < 100.0:
        raise ValueError("calibration percentile must be in [50, 100)")
    cal_ids = allocation.partitions["calibrate"]
    pooled: dict[str, list[float]] = {name: [] for name in COMPARATORS}
    for sid in cal_ids:
        for name, values in comparators.scores(sessions[sid]).items():
            pooled[name].extend(values)
    thresholds = {name: _percentile(values, percentile) for name, values in pooled.items()}
    exceedance = {
        name: (sum(1 for v in values if v > thresholds[name]) / len(values)) if values else math.nan
        for name, values in pooled.items()
    }
    return CalibratedThresholds(
        percentile=percentile,
        thresholds=thresholds,
        calibrate_session_ids=tuple(cal_ids),
        calibrate_windows=sum(len(values) for values in pooled.values()) // len(COMPARATORS),
        calibrate_exceedance=exceedance,
    )


def heldout_exceedance(
    sessions: Mapping[str, Session],
    allocation: Allocation,
    comparators: Comparators,
    calibrated: CalibratedThresholds,
) -> dict[str, Any]:
    """Exceedance on held-out test sessions only; never on fit or calibrate."""
    rows = []
    totals: dict[str, list[int]] = {name: [0, 0] for name in COMPARATORS}
    for sid in allocation.partitions["test"]:
        session = sessions[sid]
        scores = comparators.scores(session)
        row: dict[str, Any] = {
            "session_id": sid,
            "group": session.group,
            "day": session.day,
            "windows": len(session.windows),
            "partition": "test",
        }
        for name in COMPARATORS:
            values = scores[name]
            above = sum(1 for v in values if v > calibrated.thresholds[name])
            row[name] = {
                "windows_above": above,
                "exceedance_fraction": (above / len(values)) if values else None,
                "max_score": max(values) if values else None,
            }
            totals[name][0] += above
            totals[name][1] += len(values)
        rows.append(row)
    return {
        "contract": CONTRACT,
        "statement": "exceedance is stated on held-out test sessions only; fit and calibrate sessions are excluded",
        "in_sample": False,
        "allocation": allocation.to_dict(),
        "fit": {"session_ids": list(comparators.fit_session_ids), "windows": comparators.fit_windows,
                "robust_reference": {"medians": dict(comparators.reference.medians), "mads": dict(comparators.reference.mads)}},
        "calibration": {
            "percentile": calibrated.percentile,
            "session_ids": list(calibrated.calibrate_session_ids),
            "windows": calibrated.calibrate_windows,
            "thresholds": dict(calibrated.thresholds),
            "calibrate_partition_exceedance": dict(calibrated.calibrate_exceedance),
        },
        "test_sessions": rows,
        "test_totals": {
            name: {
                "windows_above": above,
                "windows": total,
                "exceedance_fraction": (above / total) if total else None,
            }
            for name, (above, total) in totals.items()
        },
    }


def run_heldout_calibration(
    sessions: Sequence[Session],
    *,
    seed: str,
    output_dir: Path | None = None,
    fractions: Mapping[str, float] | None = None,
    percentile: float = DEFAULT_CALIBRATION_PERCENTILE,
) -> dict[str, Any]:
    """Allocate, fit, calibrate and report; optionally write the two JSON outputs."""
    allocation = allocate_sessions(sessions, seed=seed, fractions=fractions)
    by_id = {s.session_id: s for s in sessions}
    comparators = fit_comparators(by_id, allocation)
    calibrated = calibrate_thresholds(by_id, allocation, comparators, percentile=percentile)
    report = heldout_exceedance(by_id, allocation, comparators, calibrated)
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "allocation_manifest.json").write_text(
            json.dumps(allocation.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output_dir / "heldout_calibration.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return report


__all__ = [
    "COMPARATORS",
    "CONTRACT",
    "PARTITIONS",
    "Allocation",
    "CalibratedThresholds",
    "Comparators",
    "Session",
    "allocate_sessions",
    "calibrate_thresholds",
    "fit_comparators",
    "heldout_exceedance",
    "run_heldout_calibration",
]
