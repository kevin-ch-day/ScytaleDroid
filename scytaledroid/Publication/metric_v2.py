"""Corrected publication metric aggregation (v2).

Historical publication outputs remain frozen v1. This module is an additive
research method: it does not write over CARS/ICECCO CSVs.

Corrections versus v1:
- analytic eligibility is applied before median/stat computation
- missing measurements are omitted (not coerced to 0)
- unknown/missing baseline assessment is not classified as strict_idle
- component exposure prefers finding_id / rule_id over title substrings
- each aggregate records denominator, source, and snapshot identity
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from statistics import median
from typing import Any

METRIC_METHOD_V1 = "v1"
METRIC_METHOD_V2 = "v2"

_UNGUARDED_FINDING_PREFIXES = (
    "ipc_activity_open_",
    "ipc_activity-alias_open_",
    "ipc_service_open_",
    "ipc_receiver_open_",
    "ipc_activity_permission_weak_",
    "ipc_activity-alias_permission_weak_",
    "ipc_service_weak_permission_",
    "ipc_receiver_weak_permission_",
    "ipc_provider_world_",
    "ipc_provider_unprotected_read_",
    "ipc_provider_unprotected_write_",
    "provider_world_",
    "provider_unprotected_read_",
    "provider_unprotected_write_",
)

_KIND_PREFIXES = (
    ("ipc_activity-alias_", "activity_alias"),
    ("ipc_activity_", "activity"),
    ("ipc_service_", "service"),
    ("ipc_receiver_", "receiver"),
    ("ipc_provider_", "provider"),
    ("provider_", "provider"),
)


def classify_dynamic_evidence_v2(row: Mapping[str, Any]) -> str:
    """Classify a dynamic run without inventing strict_idle from missing baseline."""

    if not _eligible_dynamic_row(row):
        return "ineligible"
    profile = str(row.get("run_profile") or row.get("operator_run_profile") or "").strip().lower()
    if "interaction" in profile or "interactive" in profile:
        return "interactive"
    baseline_state = row.get("baseline_assessment")
    if baseline_state in {None, ""} and row.get("baseline_not_idle") is None:
        if "idle" in profile or profile.startswith("baseline"):
            return "unknown_baseline"
        return "unknown"
    baseline_not_idle = bool(row.get("baseline_not_idle"))
    if "idle" in profile or profile.startswith("baseline"):
        return "qfg" if baseline_not_idle else "strict_idle"
    return "unknown"


def _eligible_dynamic_row(row: Mapping[str, Any]) -> bool:
    if row.get("analytic_eligible") is False:
        return False
    if str(row.get("status") or "").strip().upper() not in {"", "COMPLETED"}:
        return False
    if row.get("valid_dataset_run") is False:
        return False
    if row.get("countable") is False:
        return False
    return True


def _numeric(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return number


def median_of_observed(values: Sequence[object]) -> dict[str, Any]:
    observed = [number for number in (_numeric(value) for value in values) if number is not None]
    return {
        "median": median(observed) if observed else None,
        "n_observed": len(observed),
        "n_missing": sum(1 for value in values if _numeric(value) is None),
        "n_input": len(values),
        "missing_treated_as_zero": False,
    }


def component_exposure_from_findings_v2(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    exported: dict[str, set[str]] = {
        "activity": set(),
        "activity_alias": set(),
        "service": set(),
        "receiver": set(),
        "provider": set(),
    }
    unguarded: set[tuple[str, str]] = set()
    used_rule_ids = 0
    used_title_fallback = 0
    for row in findings:
        kind, name, via_rule = _component_identity_v2(row)
        if kind is None or not name:
            continue
        if via_rule:
            used_rule_ids += 1
        else:
            used_title_fallback += 1
        exported.setdefault(kind, set()).add(name)
        if _is_unguarded_v2(row):
            unguarded.add((kind, name))
    return {
        "exported_activities": len(exported["activity"]),
        "exported_activity_aliases": len(exported["activity_alias"]),
        "exported_services": len(exported["service"]),
        "exported_receivers": len(exported["receiver"]),
        "exported_providers": len(exported["provider"]),
        "unguarded_ipc_components": len(unguarded),
        "identity_source_rule_id_count": used_rule_ids,
        "identity_source_title_fallback_count": used_title_fallback,
    }


def _component_identity_v2(row: Mapping[str, Any]) -> tuple[str | None, str, bool]:
    token = str(row.get("finding_id") or row.get("rule_id") or "").strip()
    for prefix, kind in _KIND_PREFIXES:
        if token.startswith(prefix):
            name = token[len(prefix) :]
            for extra in (
                "open_",
                "permission_weak_",
                "weak_permission_",
                "permission_",
                "world_",
                "unprotected_read_",
                "unprotected_write_",
            ):
                if name.startswith(extra):
                    name = name[len(extra) :]
                    break
            return kind, name, True
    title = str(row.get("title") or "").lower()
    if "exported activity alias" in title:
        return "activity_alias", str(row.get("title") or ""), False
    if "exported activity" in title:
        return "activity", str(row.get("title") or ""), False
    if "exported service" in title:
        return "service", str(row.get("title") or ""), False
    if "exported receiver" in title:
        return "receiver", str(row.get("title") or ""), False
    if "exported provider" in title:
        return "provider", str(row.get("title") or ""), False
    return None, "", False


def _is_unguarded_v2(row: Mapping[str, Any]) -> bool:
    token = str(row.get("finding_id") or row.get("rule_id") or "").strip()
    if any(token.startswith(prefix) for prefix in _UNGUARDED_FINDING_PREFIXES):
        return True
    title = str(row.get("title") or "").lower()
    return "without permission" in title or "unprotected" in title or "weak guard" in title


def aggregate_dynamic_metrics_v2(
    rows: Sequence[Mapping[str, Any]],
    *,
    field: str,
    snapshot_id: str,
    source: str,
) -> dict[str, Any]:
    eligible = [row for row in rows if _eligible_dynamic_row(row)]
    classified: dict[str, list[Mapping[str, Any]]] = {}
    for row in eligible:
        classified.setdefault(classify_dynamic_evidence_v2(row), []).append(row)
    by_class: dict[str, dict[str, Any]] = {}
    for cls, members in classified.items():
        stats = median_of_observed([member.get(field) for member in members])
        stats["class"] = cls
        stats["denominator"] = len(members)
        by_class[cls] = stats
    return {
        "method": METRIC_METHOD_V2,
        "field": field,
        "source": source,
        "snapshot_id": snapshot_id,
        "n_input": len(rows),
        "n_eligible": len(eligible),
        "n_ineligible": len(rows) - len(eligible),
        "eligibility_applied_before_median": True,
        "by_class": by_class,
    }


def compare_metric_methods(
    *,
    v1_result: object,
    v2_result: object,
    reason: str,
) -> dict[str, Any]:
    changed = v1_result != v2_result
    return {
        "v1": v1_result,
        "v2": v2_result,
        "numeric_changed": changed,
        "reason": reason,
        "frozen_outputs_modified": False,
    }


__all__ = [
    "METRIC_METHOD_V1",
    "METRIC_METHOD_V2",
    "aggregate_dynamic_metrics_v2",
    "classify_dynamic_evidence_v2",
    "compare_metric_methods",
    "component_exposure_from_findings_v2",
    "median_of_observed",
]
