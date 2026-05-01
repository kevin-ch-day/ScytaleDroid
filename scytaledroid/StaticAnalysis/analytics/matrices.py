"""Matrix builders and novelty indicators for detector findings."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, MutableMapping, Sequence
from math import log2

from ..core.findings import Badge, DetectorResult, MasvsCategory


def build_finding_matrices(
    results: Sequence[DetectorResult],
) -> tuple[Mapping[str, Mapping[str, Mapping[str, int]]], Mapping[str, float]]:
    """Return serialisable matrices and novelty indicators for detector findings."""

    severity_by_category: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    severity_by_detector: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    category_by_section: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    status_by_detector: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    tag_by_severity: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    guard_strength_matrix: MutableMapping[str, Counter[str]] = defaultdict(Counter)

    severity_totals: Counter[str] = Counter()
    category_totals: Counter[str] = Counter()

    for result in results:
        detector = result.detector_id or "unknown"
        section = result.section_key or detector
        status_by_detector[detector][result.status.value] += 1

        for finding in result.findings:
            severity = finding.severity_gate.value
            category = finding.category_masvs.value

            severity_by_category[category][severity] += 1
            severity_by_detector[detector][severity] += 1
            category_by_section[section][category] += 1
            status_by_detector[detector][finding.status.value] += 1

            severity_totals[severity] += 1
            category_totals[category] += 1

            for tag in finding.tags:
                tag_by_severity[str(tag)][severity] += 1

            guard_value = _extract_guard_metric(finding.metrics)
            if guard_value:
                guard_strength_matrix[guard_value][severity] += 1

    matrices: dict[str, Mapping[str, Mapping[str, int]]] = {
        "severity_by_category": _serialise_nested_counter(severity_by_category),
        "severity_by_detector": _serialise_nested_counter(severity_by_detector),
        "category_by_section": _serialise_nested_counter(category_by_section),
        "status_by_detector": _serialise_nested_counter(status_by_detector),
    }

    tag_matrix = _serialise_nested_counter(tag_by_severity)
    if tag_matrix:
        matrices["tags_by_severity"] = tag_matrix

    guard_matrix = _serialise_nested_counter(guard_strength_matrix)
    if guard_matrix:
        matrices["guard_strength_by_severity"] = guard_matrix

    indicators: dict[str, float] = {}
    severity_entropy = _entropy(severity_totals)
    if severity_entropy is not None:
        indicators["severity_entropy"] = severity_entropy
    category_entropy = _entropy(category_totals)
    if category_entropy is not None:
        indicators["category_entropy"] = category_entropy
    coverage_ratio = _coverage_ratio(category_totals)
    if coverage_ratio is not None:
        indicators["masvs_coverage_ratio"] = coverage_ratio

    if severity_entropy is not None or category_entropy is not None:
        novelty_index = _novelty_index(
            severity_entropy or 0.0,
            category_entropy or 0.0,
            coverage_ratio or 0.0,
        )
        indicators["novelty_index"] = novelty_index

    return matrices, indicators


def _extract_guard_metric(metrics: Mapping[str, object] | None) -> str | None:
    if not isinstance(metrics, Mapping):
        return None
    for key in ("protection_level", "guard", "acl_strength"):
        value = metrics.get(key)
        if value is None:
            continue
        if isinstance(value, Badge):
            value = value.value
        text = str(value).strip()
        if text:
            return text.lower()
    return None


def _serialise_nested_counter(
    data: MutableMapping[str, Counter[str]] | Mapping[str, Counter[str]]
) -> Mapping[str, Mapping[str, int]]:
    serialised: dict[str, Mapping[str, int]] = {}
    for row_key, counter in data.items():
        filtered = {
            str(col_key): int(count)
            for col_key, count in counter.items()
            if int(count)
        }
        if filtered:
            serialised[str(row_key)] = dict(sorted(filtered.items()))
    return dict(sorted(serialised.items()))


def _entropy(counter: Counter[str]) -> float | None:
    total = sum(counter.values())
    if total <= 0:
        return None
    entropy_value = 0.0
    for count in counter.values():
        if count <= 0:
            continue
        probability = count / total
        entropy_value -= probability * log2(probability)
    return round(entropy_value, 4)


def _coverage_ratio(counter: Counter[str]) -> float | None:
    if not counter:
        return None
    non_zero = sum(1 for value in counter.values() if value > 0)
    if non_zero == 0:
        return 0.0
    total_categories = len(MasvsCategory)
    return round(non_zero / total_categories, 4)


def _novelty_index(
    severity_entropy: float,
    category_entropy: float,
    coverage_ratio: float,
) -> float:
    weighted = severity_entropy * 0.5 + category_entropy * 0.35 + coverage_ratio * 0.15
    return round(weighted, 4)


__all__ = ["build_finding_matrices"]