"""Audit helpers for permission risk runs.

This module collects snapshot-level statistics and per-app audit payloads
when the permission analysis profile is executed. The resulting artefacts are
written to ``data/audit/<snapshot_id>/`` so analysts can review score inputs
before changing any weighting configuration.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
import json
import math
import os
import traceback
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any

from scytaledroid.Utils.evidence_store import filesystem_safe_slug
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.artifact_registry import record_artifacts
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.ops.operation_result import OperationResult

from .signal_evidence import persist_signal_observations


@dataclass
class AppSignals:
    """Boolean signal flags extracted from manifest permissions."""

    camera: bool = False
    microphone: bool = False
    precise_location: bool = False
    background_location: bool = False
    overlay: bool = False
    contacts: bool = False
    calendar: bool = False
    sensors: bool = False
    activity_recognition: bool = False
    calls: bool = False
    sms: bool = False
    storage_broad: bool = False
    bt_triad: bool = False
    notifications: bool = False
    ads_attr: bool = False
    screen_capture: bool = False
    usage_stats: bool = False
    query_all_packages: bool = False
    accessibility_binding: bool = False
    notif_listener: bool = False
    exact_alarms: bool = False
    request_install: bool = False
    clipboard_bg: bool = False

    def as_dict(self) -> dict[str, bool]:
        return self.__dict__.copy()


SignalMapping = Mapping[str, bool]


def compute_signal_flags(
    *,
    groups: Mapping[str, int],
    permissions: Iterable[str],
    vendor_present: bool,
) -> AppSignals:
    """Derive boolean signal flags using group strengths and permission names."""

    perms = {perm.upper() for perm in permissions}

    def has_any(*candidates: str) -> bool:
        return any(name.upper() in perms for name in candidates)

    return AppSignals(
        camera=groups.get("CAM", 0) >= 1,
        microphone=groups.get("MIC", 0) >= 1,
        precise_location=groups.get("LOC", 0) >= 1 or has_any("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_MEDIA_LOCATION"),
        background_location=has_any("ACCESS_BACKGROUND_LOCATION"),
        overlay=groups.get("OVR", 0) >= 1,
        contacts=groups.get("CNT", 0) >= 1,
        calendar=groups.get("CAL", 0) >= 1,
        sensors=groups.get("SENS", 0) >= 1,
        activity_recognition=groups.get("ACT", 0) >= 1,
        calls=groups.get("PHN", 0) >= 1,
        sms=groups.get("SMS", 0) >= 1,
        storage_broad=has_any("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"),
        bt_triad=groups.get("BT", 0) >= 1,
        notifications=groups.get("NOT", 0) >= 1,
        ads_attr=vendor_present,
        screen_capture=has_any("MEDIA_CONTENT_CONTROL", "CAPTURE_VIDEO_OUTPUT", "CAPTURE_SECURE_VIDEO_OUTPUT"),
        usage_stats=has_any("PACKAGE_USAGE_STATS"),
        query_all_packages=has_any("QUERY_ALL_PACKAGES"),
        accessibility_binding=has_any("BIND_ACCESSIBILITY_SERVICE"),
        notif_listener=has_any("BIND_NOTIFICATION_LISTENER_SERVICE"),
        exact_alarms=has_any("SCHEDULE_EXACT_ALARM"),
        request_install=has_any("REQUEST_INSTALL_PACKAGES"),
        clipboard_bg=has_any("READ_CLIPBOARD_IN_BACKGROUND"),
    )


def _percentile(sorted_values: Sequence[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if pct <= 0:
        return float(sorted_values[0])
    if pct >= 100:
        return float(sorted_values[-1])
    rank = (pct / 100) * (len(sorted_values) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(sorted_values[low])
    weight = rank - low
    return float(sorted_values[low] * (1 - weight) + sorted_values[high] * weight)


def _percentile_summary(values: Sequence[float]) -> dict[str, float]:
    ordered = sorted(float(v) for v in values if v is not None)
    if not ordered:
        return {key: 0.0 for key in ("p10", "p25", "p50", "p75", "p90", "p95", "max")}
    return {
        "p10": _percentile(ordered, 10),
        "p25": _percentile(ordered, 25),
        "p50": _percentile(ordered, 50),
        "p75": _percentile(ordered, 75),
        "p90": _percentile(ordered, 90),
        "p95": _percentile(ordered, 95),
        "max": float(ordered[-1]),
    }


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _sdk_bucket(value: Any) -> str:
    try:
        ivalue = int(value)
    except Exception:
        return "unknown"
    if ivalue <= 29:
        return "≤29"
    if 30 <= ivalue <= 32:
        return "30-32"
    if ivalue == 33:
        return "33"
    if ivalue == 34:
        return "34"
    if ivalue >= 35:
        return "≥35"
    return "unknown"


def _combo_definitions() -> Mapping[str, Any]:
    return {
        "overlay_plus_notifications": lambda g: g.get("OVR", 0) >= 1 and g.get("NOT", 0) >= 1,
        "location_plus_bluetooth": lambda g: g.get("LOC", 0) >= 1 and g.get("BT", 0) >= 1,
        "camera_plus_mic": lambda g: g.get("CAM", 0) >= 1 and g.get("MIC", 0) >= 1,
        "contacts_plus_sms": lambda g: g.get("CNT", 0) >= 1 and g.get("SMS", 0) >= 1,
    }


def _pearson(values_a: Sequence[float], values_b: Sequence[float]) -> float:
    if len(values_a) != len(values_b) or not values_a:
        return 0.0
    mean_a = mean(values_a)
    mean_b = mean(values_b)
    numerator = sum(
        (a - mean_a) * (b - mean_b) for a, b in zip(values_a, values_b, strict=False)
    )
    denom_a = math.sqrt(sum((a - mean_a) ** 2 for a in values_a))
    denom_b = math.sqrt(sum((b - mean_b) ** 2 for b in values_b))
    if denom_a == 0 or denom_b == 0:
        return 0.0
    return numerator / (denom_a * denom_b)


def _rank(values: Sequence[float]) -> list[float]:
    pairs = sorted((value, index) for index, value in enumerate(values))
    ranks = [0.0] * len(values)
    i = 0
    while i < len(pairs):
        j = i
        total = 0.0
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            total += j + 1
            j += 1
        avg_rank = total / (j - i)
        for k in range(i, j):
            ranks[pairs[k][1]] = avg_rank
        i = j
    return ranks


def _spearman(values_a: Sequence[float], values_b: Sequence[float]) -> float:
    if len(values_a) != len(values_b) or not values_a:
        return 0.0
    ranked_a = _rank(values_a)
    ranked_b = _rank(values_b)
    return _pearson(ranked_a, ranked_b)


@dataclass
class _AppAccumulator:
    package: str
    label: str
    cohort: str
    sdk: Mapping[str, Any]
    counts: Mapping[str, int]
    groups: Mapping[str, int]
    signals: SignalMapping
    declared_in: Mapping[str, str]
    declared_permissions: Sequence[str]
    score_detail: dict[str, Any]
    combos: Sequence[Mapping[str, Any]]
    contributions: Mapping[str, float]


@dataclass
class PermissionAuditAccumulator:
    """Collects per-run audit data and writes structured artefacts."""

    scope_label: str
    scope_type: str
    total_groups: int
    snapshot_id: str
    base_output_dir: Path = Path("data/audit")
    apps: list[_AppAccumulator] = field(default_factory=list)
    cohort_counts: MutableMapping[str, int] = field(default_factory=dict)
    permission_presence: MutableMapping[str, dict[str, Any]] = field(default_factory=dict)
    signal_presence: MutableMapping[str, dict[str, Any]] = field(default_factory=dict)
    combo_presence: MutableMapping[str, dict[str, Any]] = field(default_factory=dict)
    grade_counts: MutableMapping[str, dict[str, int]] = field(default_factory=dict)
    sdk_histogram: MutableMapping[str, int] = field(default_factory=dict)
    legacy_counters: MutableMapping[str, int] = field(default_factory=dict)
    dangerous_counts: list[int] = field(default_factory=list)
    signature_counts: list[int] = field(default_factory=list)
    oem_counts: list[int] = field(default_factory=list)
    score_raws: list[float] = field(default_factory=list)
    score_cappeds: list[float] = field(default_factory=list)
    feature_shares_by_cohort: MutableMapping[str, list[Mapping[str, float]]] = field(default_factory=dict)

    def add_app(
        self,
        *,
        package: str,
        label: str,
        cohort: str,
        sdk: Mapping[str, Any],
        counts: Mapping[str, int],
        groups: Mapping[str, int],
        declared_in: Mapping[str, str],
        declared_permissions: Sequence[str],
        score_detail: dict[str, Any],
        vendor_present: bool,
    ) -> None:
        """Register an app profile for audit output."""

        signals = compute_signal_flags(
            groups=groups,
            permissions=declared_permissions,
            vendor_present=vendor_present,
        ).as_dict()

        combos = self._evaluate_combos(groups)
        for combo in combos:
            combo.setdefault("package", package)
            combo.setdefault("label", label)
        score_detail.setdefault("combos_fired", combos)
        score_detail.setdefault("combo_total", 0.0)
        score_detail.setdefault("surprises", [])
        score_detail.setdefault("surprise_total", 0.0)
        score_detail.setdefault("legacy_penalties", [])
        score_detail.setdefault("legacy_total", 0.0)
        score_detail.setdefault("vendor_modifier", 0.0)
        score_detail.setdefault("modernization_credit", 0.0)
        score_detail.setdefault("hard_gates_triggered", [])
        score_detail.setdefault("grade_basis", "fixed_thresholds")
        score_detail.setdefault("expected_mask_hit", [])
        score_detail.setdefault("unexpected_signals", [])

        contributions = self._compute_component_shares(score_detail)
        score_detail.setdefault("component_shares", contributions)

        self.apps.append(
            _AppAccumulator(
                package=package,
                label=label,
                cohort=cohort,
                sdk=sdk,
                counts=counts,
                groups=dict(groups),
                signals=signals,
                declared_in=declared_in,
                declared_permissions=list(declared_permissions),
                score_detail=score_detail,
                combos=combos,
                contributions=contributions,
            )
        )

        self._update_counters(cohort, sdk, counts, signals, declared_in, combos, score_detail, contributions)

    # ------------------------------
    # Aggregation helpers
    # ------------------------------

    def _update_counters(
        self,
        cohort: str,
        sdk: Mapping[str, Any],
        counts: Mapping[str, int],
        signals: SignalMapping,
        declared_in: Mapping[str, str],
        combos: Sequence[Mapping[str, Any]],
        score_detail: Mapping[str, Any],
        contributions: Mapping[str, float],
    ) -> None:
        self.cohort_counts[cohort] = self.cohort_counts.get(cohort, 0) + 1
        grade = str(score_detail.get("grade", "?"))
        cohort_grades = self.grade_counts.setdefault(cohort, {})
        cohort_grades[grade] = cohort_grades.get(grade, 0) + 1
        bucket = _sdk_bucket(sdk.get("target"))
        self.sdk_histogram[bucket] = self.sdk_histogram.get(bucket, 0) + 1

        for perm in declared_in.keys():
            entry = self.permission_presence.setdefault(perm, {"count": 0, "cohorts": {}})
            entry["count"] += 1
            cohort_map = entry.setdefault("cohorts", {})
            cohort_map[cohort] = cohort_map.get(cohort, 0) + 1

        for signal_name, present in signals.items():
            if not present:
                continue
            entry = self.signal_presence.setdefault(signal_name, {"count": 0, "cohorts": {}})
            entry["count"] += 1
            cohort_map = entry.setdefault("cohorts", {})
            cohort_map[cohort] = cohort_map.get(cohort, 0) + 1

        for combo in combos:
            name = combo.get("name", "")
            if not name:
                continue
            entry = self.combo_presence.setdefault(name, {"count": 0, "apps": []})
            entry["count"] += 1
            entry["apps"].append({
                "package": combo.get("package"),
                "label": combo.get("label"),
                "score": float(score_detail.get("score_capped", 0.0)),
            })

        target = sdk.get("target")
        perms_set = set(declared_in.keys())
        has_read_external = "READ_EXTERNAL_STORAGE" in perms_set
        has_write_external = "WRITE_EXTERNAL_STORAGE" in perms_set
        has_manage_external = "MANAGE_EXTERNAL_STORAGE" in perms_set
        has_scoped_media = any(name.startswith("READ_MEDIA_") for name in perms_set)
        if isinstance(target, (int, str)):
            try:
                target_val = int(target)
            except Exception:
                target_val = None
        else:
            target_val = None
        if target_val is not None and target_val < 33:
            if has_read_external:
                self.legacy_counters["read_external_pre33"] = self.legacy_counters.get("read_external_pre33", 0) + 1
            if has_write_external:
                self.legacy_counters["write_external_pre33"] = self.legacy_counters.get("write_external_pre33", 0) + 1
        if has_manage_external:
            self.legacy_counters["manage_external"] = self.legacy_counters.get("manage_external", 0) + 1
        if has_scoped_media and not (has_read_external or has_write_external or has_manage_external):
            self.legacy_counters["scoped_media_only"] = self.legacy_counters.get("scoped_media_only", 0) + 1

        self.dangerous_counts.append(int(counts.get("dangerous", 0)))
        self.signature_counts.append(int(counts.get("signature", 0)))
        self.oem_counts.append(int(counts.get("oem", counts.get("vendor", 0))))
        self.score_raws.append(float(score_detail.get("score_raw", 0.0)))
        self.score_cappeds.append(float(score_detail.get("score_capped", 0.0)))

        cohort_shares = self.feature_shares_by_cohort.setdefault(cohort, [])
        cohort_shares.append(contributions)

    def _evaluate_combos(self, groups: Mapping[str, int]) -> list[dict[str, Any]]:
        combos = []
        for name, predicate in _combo_definitions().items():
            try:
                fired = bool(predicate(groups))
            except Exception:
                fired = False
            if fired:
                combos.append({"name": name, "bonus": 0.0})
        return combos

    def _compute_component_shares(self, score_detail: Mapping[str, Any]) -> dict[str, float]:
        score = float(score_detail.get("score_capped") or score_detail.get("score_raw") or 0.0)
        if score <= 0:
            return {"signals": 0.0, "combos": 0.0, "surprises": 0.0, "legacy": 0.0, "oem": 0.0, "credit": 0.0}
        return {
            "signals": _safe_div(float(score_detail.get("signal_score_subtotal", 0.0)), score),
            "combos": _safe_div(float(score_detail.get("combo_total", 0.0)), score),
            "surprises": _safe_div(float(score_detail.get("surprise_total", 0.0)), score),
            "legacy": _safe_div(float(score_detail.get("legacy_total", 0.0)), score),
            "oem": _safe_div(float(score_detail.get("vendor_modifier", 0.0)), score),
            "credit": _safe_div(float(score_detail.get("modernization_credit", 0.0)), score),
        }

    # ------------------------------
    # Finalisation and output
    # ------------------------------

    def finalize(self) -> dict[str, Any]:
        apps_in_scope = len(self.apps)
        signal_expectations = self._compute_signal_expectations()
        for app in self.apps:
            expected = [signal for signal in app.signals if app.signals[signal] and signal_expectations[app.cohort]["expected"].get(signal, 0.0) >= 0.6]
            unexpected = [signal for signal in app.signals if app.signals[signal] and signal_expectations[app.cohort]["expected"].get(signal, 0.0) <= 0.2]
            app.score_detail["expected_mask_hit"] = expected
            app.score_detail["unexpected_signals"] = unexpected

        write_files = os.environ.get("SCY_AUDIT_WRITE_FILES", "1") != "0"
        snapshot_dir = self.base_output_dir / filesystem_safe_slug(self.snapshot_id)
        apps_dir = snapshot_dir / "apps"
        if write_files:
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            apps_dir.mkdir(parents=True, exist_ok=True)

        if write_files:
            for app in self.apps:
                record = {
                    "app": {
                        "abbr": self._abbr(app.label),
                        "name": app.label,
                        "package": app.package,
                        "cohort": app.cohort,
                    },
                    "sdk": {"min": app.sdk.get("min"), "target": app.sdk.get("target")},
                    "counts": {
                        "dangerous": int(app.counts.get("dangerous", 0)),
                        "signature": int(app.counts.get("signature", 0)),
                        "oem": int(app.counts.get("oem", app.counts.get("vendor", 0))),
                    },
                    "signals": dict(app.signals),
                    "origins": {"declared_in": dict(app.declared_in)},
                    "scoring": dict(app.score_detail),
                    "baselines": {
                        "expected_mask_hit": list(app.score_detail.get("expected_mask_hit", [])),
                        "unexpected_signals": list(app.score_detail.get("unexpected_signals", [])),
                    },
                }
                app_path = apps_dir / f"{app.package}.json"
                with app_path.open("w", encoding="utf-8") as handle:
                    json.dump(record, handle, indent=2, sort_keys=True)

        snapshot_payload = self._build_snapshot_payload(apps_in_scope)
        snapshot_path = snapshot_dir / "snapshot.json"
        if write_files:
            with snapshot_path.open("w", encoding="utf-8") as handle:
                json.dump(snapshot_payload, handle, indent=2, sort_keys=True)

        correlation_path = snapshot_dir / "correlation.csv"
        if write_files:
            self._write_correlations(correlation_path)

        snapshot_payload["paths"] = {
            "snapshot": str(snapshot_path) if write_files else None,
            "apps_dir": str(apps_dir) if write_files else None,
            "correlation_csv": str(correlation_path) if write_files else None,
        }
        return snapshot_payload

    # ------------------------------
    # Snapshot builders
    # ------------------------------

    def _build_snapshot_payload(self, apps_in_scope: int) -> dict[str, Any]:
        session_value = self.snapshot_id
        if isinstance(self.snapshot_id, str) and self.snapshot_id.startswith("perm-audit:app:"):
            session_value = self.snapshot_id[len("perm-audit:app:") :]
        inventory = {
            "apps_total": self.total_groups,
            "apps_in_scope": apps_in_scope,
            "cohort_counts": dict(sorted(self.cohort_counts.items())),
            "sdk_targets_hist": dict(sorted(self.sdk_histogram.items())),
        }

        permissions = []
        for name, stats in sorted(self.permission_presence.items(), key=lambda item: item[0]):
            count = stats.get("count", 0)
            permissions.append(
                {
                    "name": name,
                    "apps_requesting": count,
                    "prevalence_pct": round(_safe_div(count, apps_in_scope) * 100, 2),
                    "cohort_prevalence_pct": {
                        cohort: round(_safe_div(value, self.cohort_counts.get(cohort, 0)) * 100, 2)
                        for cohort, value in sorted(stats.get("cohorts", {}).items())
                    },
                }
            )

        signals = []
        for name, stats in sorted(self.signal_presence.items(), key=lambda item: item[0]):
            count = stats.get("count", 0)
            signals.append(
                {
                    "name": name,
                    "apps_requesting": count,
                    "prevalence_pct": round(_safe_div(count, apps_in_scope) * 100, 2),
                    "cohort_prevalence_pct": {
                        cohort: round(_safe_div(value, self.cohort_counts.get(cohort, 0)) * 100, 2)
                        for cohort, value in sorted(stats.get("cohorts", {}).items())
                    },
                }
            )

        combos = []
        for name, stats in sorted(self.combo_presence.items(), key=lambda item: item[0]):
            count = stats.get("count", 0)
            top_apps = sorted(stats.get("apps", []), key=lambda item: item.get("score", 0), reverse=True)[:10]
            combos.append(
                {
                    "name": name,
                    "apps_fired": count,
                    "prevalence_pct": round(_safe_div(count, apps_in_scope) * 100, 2),
                    "top_apps": top_apps,
                }
            )

        distributions = {
            "dangerous": _percentile_summary(self.dangerous_counts),
            "signature": _percentile_summary(self.signature_counts),
            "oem": _percentile_summary(self.oem_counts),
            "score_raw": _percentile_summary(self.score_raws),
            "score_capped": _percentile_summary(self.score_cappeds),
        }

        grade_mix = {
            cohort: dict(sorted(grades.items())) for cohort, grades in sorted(self.grade_counts.items())
        }

        feature_averages = {}
        for cohort, entries in self.feature_shares_by_cohort.items():
            totals = {"signals": 0.0, "combos": 0.0, "surprises": 0.0, "legacy": 0.0, "oem": 0.0, "credit": 0.0}
            for entry in entries:
                for key in totals:
                    totals[key] += float(entry.get(key, 0.0))
            feature_averages[cohort] = {key: round(_safe_div(value, len(entries)), 4) for key, value in totals.items()}

        rarity_ranks = self._signal_rarity(signals, apps_in_scope)
        outliers = self._cohort_outliers()

        payload = {
            "snapshot_id": self.snapshot_id,
            "session": session_value,
            "scope": self.scope_type,
            "scope_type": self.scope_type,
            "scope_label": self.scope_label,
            "inventory": inventory,
            "permission_prevalence": {"permissions": permissions, "signals": signals},
            "distributions": distributions,
            "grade_mix": grade_mix,
            "combos": combos,
            "legacy_vs_modern": dict(sorted(self.legacy_counters.items())),
            "feature_contributions": {"by_cohort": feature_averages},
            "rarity_ranks": rarity_ranks,
            "outliers": outliers,
        }
        return payload

    def _signal_rarity(self, signals: list[dict[str, Any]], apps_in_scope: int) -> dict[str, float]:
        if not apps_in_scope or not signals:
            return {}
        sorted_signals = sorted(signals, key=lambda item: item.get("prevalence_pct", 0))
        rarity: dict[str, float] = {}
        for index, item in enumerate(sorted_signals):
            rarity[item["name"]] = round(_safe_div(index, len(sorted_signals) - 1) * 100 if len(sorted_signals) > 1 else 0.0, 2)
        return rarity

    def _compute_signal_expectations(self) -> dict[str, dict[str, dict[str, float]]]:
        expectations: dict[str, dict[str, dict[str, float]]] = {}
        for cohort, total in self.cohort_counts.items():
            cohort_signals = {}
            for signal_name, stats in self.signal_presence.items():
                cohort_count = stats.get("cohorts", {}).get(cohort, 0)
                cohort_signals[signal_name] = _safe_div(cohort_count, total) if total else 0.0
            expectations[cohort] = {"expected": cohort_signals}
        return expectations

    def _cohort_outliers(self) -> list[dict[str, Any]]:
        outliers: list[dict[str, Any]] = []
        by_cohort: dict[str, list[_AppAccumulator]] = {}
        for app in self.apps:
            by_cohort.setdefault(app.cohort, []).append(app)
        for cohort, members in by_cohort.items():
            scores = [float(item.score_detail.get("score_capped", 0.0)) for item in members]
            if not scores:
                continue
            avg = mean(scores)
            variance = mean([(score - avg) ** 2 for score in scores]) if len(scores) > 1 else 0.0
            stddev = math.sqrt(variance)
            if stddev == 0:
                continue
            for app, score in zip(members, scores, strict=False):
                z = (score - avg) / stddev
                if z >= 1.5:
                    outliers.append(
                        {
                            "cohort": cohort,
                            "package": app.package,
                            "label": app.label,
                            "score": round(score, 3),
                            "z_score": round(z, 2),
                        }
                    )
        outliers.sort(key=lambda item: item.get("z_score", 0), reverse=True)
        return outliers[:5]

    def _write_correlations(self, destination: Path) -> None:
        if not self.apps:
            destination.write_text("", encoding="utf-8")
            return
        feature_vectors: dict[str, list[float]] = {
            "score_capped": [float(app.score_detail.get("score_capped", 0.0)) for app in self.apps],
            "dangerous": [float(app.counts.get("dangerous", 0)) for app in self.apps],
            "signature": [float(app.counts.get("signature", 0)) for app in self.apps],
            "oem": [float(app.counts.get("oem", app.counts.get("vendor", 0))) for app in self.apps],
        }
        for signal in sorted(self.signal_presence.keys()):
            feature_vectors[f"signal_{signal}"] = [1.0 if app.signals.get(signal, False) else 0.0 for app in self.apps]
        for name in sorted(self.combo_presence.keys()):
            feature_vectors[f"combo_{name}"] = [1.0 if any(combo.get("name") == name for combo in app.combos) else 0.0 for app in self.apps]

        headers = sorted(feature_vectors.keys())
        lines = ["feature,feature_cmp,pearson,spearman\n"]
        for i, left in enumerate(headers):
            for right in headers[i + 1 :]:
                pearson = _pearson(feature_vectors[left], feature_vectors[right])
                spearman = _spearman(feature_vectors[left], feature_vectors[right])
                lines.append(f"{left},{right},{pearson:.6f},{spearman:.6f}\n")
        destination.write_text("".join(lines), encoding="utf-8")

    def _abbr(self, name: str) -> str:
        token = "".join(ch for ch in name if ch.isalnum())
        if not token:
            return "APP"
        up = token.upper()
        head = up[0]
        tail = up[1:]
        trimmed = "".join(ch for ch in tail if ch not in "AEIOU")
        return (head + trimmed)[:5]

    # ------------------------------
    # Optional DB persistence
    # ------------------------------

    def persist_to_db(self, snapshot_payload: dict[str, Any]) -> OperationResult:
        """Persist snapshot + per-app audit data into DB.

        Returns an OperationResult containing the snapshot_id on success.
        """
        try:
            from scytaledroid.Database.db_core import database_session

            inventory = snapshot_payload.get("inventory", {}) if isinstance(snapshot_payload, dict) else {}
            apps_total = int(inventory.get("apps_in_scope") or self.total_groups or 0)
            meta_str = json.dumps(snapshot_payload)
            run_id = snapshot_payload.get("run_id") if isinstance(snapshot_payload, dict) else None
            static_run_id = snapshot_payload.get("static_run_id") if isinstance(snapshot_payload, dict) else None
            session_stamp = (
                snapshot_payload.get("session_stamp")
                if isinstance(snapshot_payload, dict)
                else None
            )
            run_map_payload = snapshot_payload.get("run_map") if isinstance(snapshot_payload, dict) else None
            run_map_required = bool(snapshot_payload.get("run_map_required")) if isinstance(snapshot_payload, dict) else False
            allow_partial = bool(snapshot_payload.get("allow_partial_audit")) if isinstance(snapshot_payload, dict) else False
            if not session_stamp and isinstance(snapshot_payload, dict):
                session_stamp = snapshot_payload.get("session")
            try:
                run_id = int(run_id) if run_id is not None else None
            except Exception:
                log.warning(
                    f"permission audit run_id could not be coerced: {run_id!r}",
                    category="db",
                )
                run_id = None
            try:
                static_run_id = int(static_run_id) if static_run_id is not None else None
            except Exception:
                log.warning(
                    f"permission audit static_run_id could not be coerced: {static_run_id!r}",
                    category="db",
                )
                static_run_id = None
            if static_run_id is None:
                log.warning(
                    "static_run_id missing for permission audit snapshot; rows will not be keyed to static run",
                    category="db",
                )
            def _extract_run_map(payload: Any) -> dict[str, int]:
                if not isinstance(payload, dict):
                    return {}
                by_package = payload.get("by_package")
                if isinstance(by_package, dict):
                    extracted: dict[str, int] = {}
                    for pkg, entry in by_package.items():
                        if not pkg or not isinstance(entry, dict):
                            continue
                        srid = entry.get("static_run_id")
                        if isinstance(srid, int):
                            extracted[pkg] = srid
                        elif isinstance(srid, str) and srid.isdigit():
                            extracted[pkg] = int(srid)
                    return extracted
                apps = payload.get("apps")
                if not isinstance(apps, list):
                    return {}
                extracted = {}
                for entry in apps:
                    if not isinstance(entry, dict):
                        continue
                    pkg = entry.get("package") or entry.get("package_name")
                    srid = entry.get("static_run_id")
                    if not pkg or srid is None:
                        continue
                    try:
                        extracted[str(pkg)] = int(srid)
                    except Exception:
                        continue
                return extracted

            static_run_id_map: dict[str, int] = _extract_run_map(run_map_payload)
            missing_run_ids = [app.package for app in self.apps if app.package not in static_run_id_map]
            if run_map_required and (not static_run_id_map or missing_run_ids):
                log.error(
                    "Permission audit run map missing required entries; aborting persistence.",
                    category="db",
                )
                return OperationResult.failure(
                    user_message="Permission audit run map missing; cannot safely link audit.",
                    error_code="perm_audit_run_map_missing",
                    context={
                        "missing_packages": missing_run_ids,
                        "session_stamp": session_stamp,
                    },
                )
            header_columns = ["snapshot_key", "scope_label", "run_id", "static_run_id", "apps_total", "metadata"]
            header_values = [
                self.snapshot_id,
                self.scope_label,
                run_id if run_id is not None else None,
                static_run_id,
                apps_total,
                meta_str,
            ]
            header_placeholders = ["%s", "%s", "%s", "%s", "%s", "%s"]
            def _persist_snapshot() -> OperationResult:
                static_run_id_local = static_run_id
                update_clause = ", ".join(
                    f"{col}=VALUES({col})" for col in header_columns if col != "snapshot_key"
                )
                header_sql = (
                    "INSERT INTO permission_audit_snapshots ("
                    + ", ".join(header_columns)
                    + ") VALUES ("
                    + ",".join(header_placeholders)
                    + ")"
                    + (" ON DUPLICATE KEY UPDATE " + update_clause if update_clause else "")
                )

                try:
                    core_q.run_sql(header_sql, tuple(header_values))
                    row = core_q.run_sql(
                        "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key=%s",
                        (self.snapshot_id,),
                        fetch="one",
                    )
                    if not row or not row[0]:
                        raise RuntimeError("Permission audit snapshot insert did not return an id")
                    sid = int(row[0])
                except Exception:  # pragma: no cover - defensive
                    log.error(
                        "Failed to persist permission_audit_snapshots "
                        f"(snapshot_key={self.snapshot_id} scope={self.scope_label} "
                        f"run_id={run_id} static_run_id={static_run_id_local})\n"
                        + traceback.format_exc(),
                        category="db",
                    )
                    return OperationResult.failure(
                        user_message="Permission audit snapshot persistence failed.",
                        error_code="perm_audit_snapshot_insert_failed",
                        context={
                            "snapshot_key": self.snapshot_id,
                            "scope_label": self.scope_label,
                            "run_id": run_id,
                            "static_run_id": static_run_id_local,
                        },
                    )

                # Populate evidence metadata once snapshot.json exists.
                snapshot_path = None
                if isinstance(snapshot_payload, dict):
                    paths = snapshot_payload.get("paths", {})
                    if isinstance(paths, dict):
                        snapshot_path = paths.get("snapshot")
                if snapshot_path:
                    try:
                        snap_path = Path(snapshot_path)
                        if snap_path.is_file():
                            sha256 = hashlib.sha256(snap_path.read_bytes()).hexdigest()
                            relpath: str
                            try:
                                relpath = str(snap_path.resolve().relative_to(Path.cwd().resolve()))
                            except Exception:
                                relpath = str(snap_path)
                            core_q.run_sql(
                                """
                                UPDATE permission_audit_snapshots
                                SET evidence_relpath=%s, evidence_sha256=%s
                                WHERE snapshot_id=%s
                                """,
                                (relpath, sha256, sid),
                            )
                            if static_run_id_local is not None:
                                record_artifacts(
                                    run_id=str(static_run_id_local),
                                    run_type="static",
                                    artifacts=[
                                        {
                                            "path": str(snap_path),
                                            "type": "permission_audit_snapshot",
                                            "sha256": sha256,
                                            "size_bytes": snap_path.stat().st_size,
                                            "created_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                                            "origin": "host",
                                            "pull_status": "n/a",
                                        }
                                    ],
                                    origin="host",
                                    pull_status="n/a",
                                )
                    except Exception:
                        log.warning(
                            "Failed to update permission audit snapshot evidence metadata",
                            category="db",
                        )

                try:
                    row = core_q.run_sql(
                        "SELECT static_run_id FROM permission_audit_snapshots WHERE snapshot_id=%s",
                        (sid,),
                        fetch="one",
                    )
                    if row and row[0] is not None:
                        static_run_id_local = int(row[0])
                except Exception:
                    pass

                evidence_base = Path("evidence") / "static_runs"
                app_failures = 0
                run_id_cache: dict[str, int | None] = {}
                run_id_map: dict[str, int] = dict(static_run_id_map)
                if missing_run_ids and not allow_partial and run_map_required:
                    log.error(
                        "Permission audit missing static_run_id for one or more apps.",
                        category="db",
                    )
                    return OperationResult.failure(
                        user_message="Permission audit missing static_run_id; cannot persist safely.",
                        error_code="perm_audit_static_run_id_missing",
                        context={
                            "missing_packages": missing_run_ids,
                            "session_stamp": session_stamp,
                        },
                    )
                for app in self.apps:
                    app_static_run_id = run_id_map.get(app.package, static_run_id_local)
                    if app_static_run_id is None and not allow_partial and run_map_required:
                        log.error(
                            "Permission audit missing static_run_id for app; aborting snapshot persistence.",
                            category="db",
                        )
                        return OperationResult.failure(
                            user_message="Permission audit missing static_run_id for app.",
                            error_code="perm_audit_app_static_run_id_missing",
                            context={
                                "package": app.package,
                                "session_stamp": session_stamp,
                            },
                        )
                    sd = dict(app.score_detail or {})
                    score_raw = float(sd.get("score_raw", sd.get("score_3dp", 0.0)) or 0.0)
                    score_capped = float(sd.get("score_capped", score_raw) or score_raw)
                    grade = str(sd.get("grade") or "")
                    declared_permissions = sorted(set(app.declared_permissions or ()))
                    details_obj = {
                        "groups": dict(app.groups or {}),
                        "signals": dict(app.signals or {}),
                        "score_detail": sd,
                        "cohort": app.cohort,
                        "sdk": dict(app.sdk or {}),
                        "declared_in": dict(app.declared_in or {}),
                        "declared_permissions": declared_permissions,
                        "declared_permissions_count": len(declared_permissions),
                        "contributions": dict(app.contributions or {}),
                        "combos": list(app.combos or ()),
                    }
                    details = json.dumps(details_obj)

                    # Explicit column order to avoid misalignment/truncation errors.
                    # Column order must match permission_audit_apps schema:
                    # snapshot_id, static_run_id, package_name, app_label, run_id, ...
                    app_columns = ["snapshot_id"]
                    app_values = [int(sid)]
                    app_placeholders = ["%s"]

                    app_columns.append("static_run_id")
                    app_values.append(app_static_run_id)
                    app_placeholders.append("%s")

                    app_columns.extend(
                        [
                            "package_name",
                            "app_label",
                        ]
                    )
                    app_values.extend([app.package, app.label])
                    app_placeholders.extend(["%s", "%s"])

                    app_run_id = run_id
                    if app_run_id is None and session_stamp and app.package:
                        cached = run_id_cache.get(app.package)
                        if cached is None and app.package not in run_id_cache:
                            try:
                                row = core_q.run_sql(
                                    """
                                    SELECT run_id
                                    FROM runs
                                    WHERE session_stamp=%s AND package=%s
                                    ORDER BY run_id DESC
                                    LIMIT 1
                                    """,
                                    (session_stamp, app.package),
                                    fetch="one",
                                )
                                cached = int(row[0]) if row and row[0] else None
                            except Exception:
                                cached = None
                            run_id_cache[app.package] = cached
                        app_run_id = cached
                    app_columns.append("run_id")
                    app_values.append(app_run_id if app_run_id is not None else None)
                    app_placeholders.append("%s")

                    app_columns.extend(
                        [
                            "score_raw",
                            "score_capped",
                            "grade",
                            "dangerous_count",
                            "signature_count",
                            "vendor_count",
                            "combos_total",
                            "surprises_total",
                            "legacy_total",
                            "vendor_modifier",
                            "modernization_credit",
                            "details",
                        ]
                    )
                    app_values.extend(
                        [
                            score_raw,
                            score_capped,
                            grade,
                            int(app.counts.get("dangerous", 0) if app.counts else 0),
                            int(app.counts.get("signature", 0) if app.counts else 0),
                            int(app.counts.get("oem", app.counts.get("vendor", 0)) if app.counts else 0),
                            float(sd.get("combo_total", 0.0) or 0.0),
                            float(sd.get("surprise_total", 0.0) or 0.0),
                            float(sd.get("legacy_total", 0.0) or 0.0),
                            float(sd.get("vendor_modifier", 0.0) or 0.0),
                            float(sd.get("modernization_credit", 0.0) or 0.0),
                            details,
                        ]
                    )
                    app_placeholders.extend(["%s"] * 12)

                    update_clause = ", ".join(
                        f"{col}=VALUES({col})" for col in app_columns if col != "snapshot_id"
                    )
                    sql = (
                        "INSERT INTO permission_audit_apps ("
                        + ", ".join(app_columns)
                        + ") VALUES ("
                        + ",".join(app_placeholders)
                        + ")"
                        + (" ON DUPLICATE KEY UPDATE " + update_clause if update_clause else "")
                    )

                    try:
                        core_q.run_sql(sql, tuple(app_values))
                    except Exception:  # pragma: no cover - defensive
                        app_failures += 1
                        log.error(
                            "Failed to persist permission_audit_apps "
                            f"(snapshot_id={sid} package={app.package} run_id={run_id} "
                            f"static_run_id={static_run_id})\n"
                            + traceback.format_exc(),
                            category="db",
                        )
                        continue

                    if app_static_run_id is not None:
                        persist_signal_observations(
                            core_q=core_q,
                            log=log,
                            evidence_base=evidence_base,
                            app=app,
                            app_static_run_id=app_static_run_id,
                        )


                try:
                    core_q.run_sql(
                        """
                        UPDATE permission_audit_snapshots
                        SET apps_total = (
                          SELECT COUNT(*) FROM permission_audit_apps WHERE snapshot_id=%s
                        )
                        WHERE snapshot_id=%s
                        """,
                        (sid, sid),
                    )
                except Exception:
                    log.warning(
                        "Failed to refresh permission_audit_snapshots.apps_total",
                        category="db",
                    )


                context = {
                    "snapshot_id": int(sid),
                    "snapshot_key": self.snapshot_id,
                    "run_id": run_id,
                    "static_run_id": static_run_id,
                    "expected_app_rows": len(self.apps),
                    "persisted_app_rows": len(self.apps) - app_failures,
                    "failed_app_rows": app_failures,
                }
                if app_failures:
                    return OperationResult.partial(
                        user_message="Permission audit app persistence partially failed.",
                        error_code="perm_audit_apps_partial",
                        context=context,
                    )
                return OperationResult.success(context=context)

            with database_session() as db:
                with db.transaction():
                    return _persist_snapshot()
        except Exception:
            payload = {}
            if isinstance(snapshot_payload, dict):
                payload = {
                    "snapshot_key": snapshot_payload.get("snapshot_id"),
                    "session_stamp": snapshot_payload.get("session"),
                    "scope_label": snapshot_payload.get("scope_label"),
                    "run_id": snapshot_payload.get("run_id"),
                    "static_run_id": snapshot_payload.get("static_run_id"),
                }
            logging_engine.get_error_logger().exception(
                "Permission audit persistence failed",
                extra=logging_engine.ensure_trace(
                    {"event": "permission_audit.persist_failed", **payload}
                ),
            )
            return OperationResult.failure(
                user_message="Permission audit persistence failed.",
                error_code="perm_audit_persist_exception",
                context=payload,
            )


__all__ = ["PermissionAuditAccumulator", "compute_signal_flags", "AppSignals"]
