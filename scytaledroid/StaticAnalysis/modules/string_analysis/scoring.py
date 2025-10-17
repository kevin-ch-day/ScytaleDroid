"""Scoring helpers for String Intelligence observations."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableMapping, Sequence

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from .schema import (
    CategoryRollup,
    FinalAssessment,
    Observation,
    Scorecard,
    TestResult,
    hash_weights,
)


_GRADE_BANDS: tuple[tuple[float, str], ...] = (
    (2.0, "A"),
    (4.0, "B"),
    (6.0, "C"),
    (8.0, "D"),
    (10.0, "F"),
)
_CONFIDENCE_FACTORS: Mapping[str, float] = {"high": 1.0, "medium": 0.6, "low": 0.3}
_CONFIDENCE_UNCERTAINTY: Mapping[str, float] = {"high": 0.1, "medium": 0.2, "low": 0.3}
_LOCAL_HOST_MARKERS = {"localhost", "127.0.0.1"}
_DEV_MARKER_TAG = "dev-marker"


@dataclass(frozen=True)
class TestDefinition:
    """Configuration metadata for a single SNI test."""

    test_id: str
    name: str
    category: str
    base: float
    description: str


@dataclass(frozen=True)
class CategoryDefinition:
    """Metadata describing a score roll-up category."""

    key: str
    label: str
    aggregation: str = "max"


@dataclass(frozen=True)
class TestCatalog:
    """Collection of tests and categories used for scoring."""

    tests: Mapping[str, TestDefinition]
    categories: Mapping[str, CategoryDefinition]

    def get(self, test_id: str) -> TestDefinition:
        return self.tests[test_id]


@dataclass(frozen=True)
class ProfileCatalog:
    """Risk profile weight definitions."""

    profiles: Mapping[str, Mapping[str, float]]

    def get_weights(self, profile: str) -> Mapping[str, float]:
        if profile not in self.profiles:
            raise KeyError(f"Unknown profile '{profile}'")
        return self.profiles[profile]


def _grade(score: float) -> str:
    for limit, grade in _GRADE_BANDS:
        if score <= limit:
            return grade
    return "F"


def _clamp(score: float) -> float:
    return max(0.0, min(10.0, score))


def _confidence_factor(observations: Sequence[Observation]) -> float:
    if not observations:
        return 0.0
    return max(_CONFIDENCE_FACTORS.get(obs.confidence, 0.3) for obs in observations)


def _confidence_uncertainty(observations: Sequence[Observation]) -> float:
    if not observations:
        return 0.0
    return max(_CONFIDENCE_UNCERTAINTY.get(obs.confidence, 0.3) for obs in observations)


def _prevalence_bonus(observations: Sequence[Observation]) -> float:
    if len(observations) <= 1:
        return 0.0
    return min(1.0, 0.2 * (len(observations) - 1))


def _is_private_ip(host: str | None) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    if host_lower in _LOCAL_HOST_MARKERS:
        return True
    try:
        import ipaddress

        ip = ipaddress.ip_address(host_lower)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False


def _is_non_local_domain(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.lower()
    if lowered in _LOCAL_HOST_MARKERS:
        return False
    if lowered.endswith(".local") or lowered.endswith(".lan") or lowered.endswith(".test"):
        return False
    return not _is_private_ip(lowered)


def _evaluate_cleartext(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No non-local cleartext endpoints detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    tags_joined = [set(obs.tags) for obs in observations]
    if any("websocket" in tags for tags in tags_joined):
        adjustments += 1.0
    if any("auth-adjacent" in tags for tags in tags_joined):
        adjustments += 1.0
    if any("nsc-blocked" in tags for tags in tags_joined):
        adjustments -= 2.0

    exposure = 1.0
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Detected {len(observations)} non-local cleartext endpoint(s)"
    grade = _grade(score)
    evidence = tuple(obs.evidence for obs in observations)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_ip_literal(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No IP literal endpoints detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any(not _is_private_ip(obs.host) for obs in observations):
        adjustments += 2.0
    exposure = 1.0
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Detected {len(observations)} endpoint(s) using IP literals"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_graph_protocol(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No GraphQL or gRPC indicators detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any("cleartext" in obs.tags for obs in observations):
        adjustments += 2.0
    if any("pinning" in obs.tags for obs in observations):
        adjustments -= 1.0
    exposure = 0.8
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Protocol hints for GraphQL/gRPC observed ({len(observations)} hits)"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_redirector(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No redirector endpoints detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any("cleartext" in obs.tags for obs in observations):
        adjustments += 1.0
    exposure = 0.8
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Detected {len(observations)} redirector endpoint(s)"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_aws_pair(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No AWS access key pairs detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if len({obs.src for obs in observations}) > 1:
        adjustments += 1.0
    if any("auth-adjacent" in obs.tags for obs in observations):
        adjustments += 1.0
    if any("test" in (obs.context or "").lower() for obs in observations):
        adjustments -= 2.0
    exposure = 1.0
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"AWS key pair exposed in client assets ({len(observations)} hit(s))"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_auth_token(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No Authorization tokens detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any("bearer-context" in obs.tags for obs in observations):
        adjustments += 1.0
    if any(_DEV_MARKER_TAG in obs.tags for obs in observations):
        adjustments -= 1.0
    exposure = 1.0
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Authorization tokens exposed ({len(observations)} hit(s))"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_encoded(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No high-signal encoded blobs detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any(obs.decoded and ("http://" in obs.decoded or "https://" in obs.decoded) for obs in observations):
        adjustments += 1.0
    exposure = 0.7
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Base64 blobs decode into potential secrets ({len(observations)} hit(s))"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_cloud(observations: Sequence[Observation], definition: TestDefinition, *, presign_keywords: Sequence[str] = ()) -> TestResult:
    if not observations:
        rationale = "No cloud storage surfaces detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if presign_keywords and any(
        any(keyword.lower() in (obs.context or "").lower() for keyword in presign_keywords)
        for obs in observations
    ):
        adjustments += 2.0
    exposure = 0.6
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Cloud storage surface references discovered ({len(observations)} hit(s))"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_feature_flags(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No feature flags referencing remote URLs detected"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any("cleartext" in obs.tags for obs in observations):
        adjustments += 2.0
    exposure = 0.7
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Feature flags point to remote endpoints ({len(observations)} hit(s))"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _evaluate_entropy(observations: Sequence[Observation], definition: TestDefinition) -> TestResult:
    if not observations:
        rationale = "No high-entropy secrets near auth markers"
        return TestResult(
            test_id=definition.test_id,
            name=definition.name,
            category=definition.category,
            score=0.0,
            grade="A",
            rationale=rationale,
            observations=tuple(),
            evidence=tuple(),
            uncertainty=0.0,
        )

    adjustments = 0.0
    if any(obs.src.startswith("assets/") for obs in observations):
        adjustments += 1.0
    exposure = 0.5
    confidence = _confidence_factor(observations)
    prevalence = _prevalence_bonus(observations)
    score = _clamp(definition.base + adjustments + exposure + confidence + prevalence)
    rationale = f"Entropy spikes near sensitive keywords ({len(observations)} hit(s))"
    evidence = tuple(obs.evidence for obs in observations)
    grade = _grade(score)
    uncertainty = _confidence_uncertainty(observations)
    return TestResult(
        test_id=definition.test_id,
        name=definition.name,
        category=definition.category,
        score=score,
        grade=grade,
        rationale=rationale,
        observations=tuple(observations),
        evidence=evidence,
        uncertainty=uncertainty,
    )


def _assign_observations(observations: Sequence[Observation]) -> MutableMapping[str, list[Observation]]:
    mapping: MutableMapping[str, list[Observation]] = {}
    for obs in observations:
        tags = set(obs.tags)
        if "endpoint" in tags and "cleartext" in tags and _is_non_local_domain(obs.host):
            mapping.setdefault("SNI-N001", []).append(obs)
        if "endpoint" in tags and "ip-literal" in tags:
            mapping.setdefault("SNI-N002", []).append(obs)
        if "endpoint" in tags and ("graphql" in tags or "grpc" in tags):
            mapping.setdefault("SNI-N003", []).append(obs)
        if "redirector" in tags:
            mapping.setdefault("SNI-N004", []).append(obs)
        if "aws-pair" in tags:
            mapping.setdefault("SNI-S101", []).append(obs)
        if "auth-token" in tags:
            mapping.setdefault("SNI-S102", []).append(obs)
        if "encoded" in tags:
            mapping.setdefault("SNI-S103", []).append(obs)
        if "cloud-bucket" in tags and any(key.startswith("aws_s3") or key.startswith("gcs") for key in tags):
            mapping.setdefault("SNI-C201", []).append(obs)
        if "cloud-bucket" in tags and any("firebase" in key for key in tags):
            mapping.setdefault("SNI-C202", []).append(obs)
        if "feature-flag" in tags:
            mapping.setdefault("SNI-C203", []).append(obs)
        if "entropy-spike" in tags:
            mapping.setdefault("SNI-E301", []).append(obs)
    return mapping


def _compute_category_scores(results: Sequence[TestResult], catalog: TestCatalog) -> tuple[CategoryRollup, ...]:
    output: list[CategoryRollup] = []
    for key, category in catalog.categories.items():
        relevant = [result for result in results if result.category == key]
        if not relevant:
            score = 0.0
        elif category.aggregation == "mean":
            score = sum(result.score for result in relevant) / len(relevant)
        else:
            score = max(result.score for result in relevant)
        grade = _grade(score)
        output.append(
            CategoryRollup(
                category=key,
                label=category.label,
                score=score,
                grade=grade,
                tests=tuple(result.test_id for result in relevant),
            )
        )
    return tuple(output)


def _compute_final_assessment(
    categories: Sequence[CategoryRollup],
    profile: str,
    weights: Mapping[str, float],
    *,
    uncertainty: float,
) -> FinalAssessment:
    score = 0.0
    for category in categories:
        weight = weights.get(category.category, 0.0)
        score += category.score * weight
    grade = _grade(score)
    weights_hash = hash_weights(weights)
    return FinalAssessment(
        profile=profile,
        score=score,
        grade=grade,
        weights=weights,
        weights_hash=weights_hash,
        uncertainty=uncertainty,
    )


def evaluate_tests(
    observations: Sequence[Observation],
    catalog: TestCatalog,
    profile_catalog: ProfileCatalog,
    profile: str,
) -> Scorecard:
    assignments = _assign_observations(observations)
    results: list[TestResult] = []
    for test_id, definition in catalog.tests.items():
        obs = assignments.get(test_id, [])
        if test_id == "SNI-N001":
            results.append(_evaluate_cleartext(obs, definition))
        elif test_id == "SNI-N002":
            results.append(_evaluate_ip_literal(obs, definition))
        elif test_id == "SNI-N003":
            results.append(_evaluate_graph_protocol(obs, definition))
        elif test_id == "SNI-N004":
            results.append(_evaluate_redirector(obs, definition))
        elif test_id == "SNI-S101":
            results.append(_evaluate_aws_pair(obs, definition))
        elif test_id == "SNI-S102":
            results.append(_evaluate_auth_token(obs, definition))
        elif test_id == "SNI-S103":
            results.append(_evaluate_encoded(obs, definition))
        elif test_id == "SNI-C201":
            results.append(_evaluate_cloud(obs, definition, presign_keywords=("X-Amz-Algorithm", "X-Goog-Algorithm")))
        elif test_id == "SNI-C202":
            results.append(_evaluate_cloud(obs, definition))
        elif test_id == "SNI-C203":
            results.append(_evaluate_feature_flags(obs, definition))
        elif test_id == "SNI-E301":
            results.append(_evaluate_entropy(obs, definition))
        else:
            # Unknown test definition; treat as informational with zero score.
            results.append(
                TestResult(
                    test_id=definition.test_id,
                    name=definition.name,
                    category=definition.category,
                    score=0.0,
                    grade="A",
                    rationale="Test not implemented",
                    observations=tuple(),
                    evidence=tuple(),
                    uncertainty=0.0,
                )
            )

    categories = _compute_category_scores(results, catalog)
    weights = profile_catalog.get_weights(profile)
    aggregate_uncertainty = max((result.uncertainty for result in results), default=0.0)
    final = _compute_final_assessment(categories, profile, weights, uncertainty=aggregate_uncertainty)
    return Scorecard(tests=tuple(results), categories=categories, final=final)


def load_test_catalog(path: str | Path) -> TestCatalog:
    payload = json.loads(Path(path).read_text("utf-8"))
    tests = {
        test_id: TestDefinition(
            test_id=test_id,
            name=data.get("name", test_id),
            category=data.get("category", "network"),
            base=float(data.get("base", 0.0)),
            description=data.get("description", ""),
        )
        for test_id, data in payload.get("tests", {}).items()
    }
    categories = {
        key: CategoryDefinition(
            key=key,
            label=data.get("label", key.title()),
            aggregation=data.get("aggregation", "max"),
        )
        for key, data in payload.get("categories", {}).items()
    }
    return TestCatalog(tests=tests, categories=categories)


def load_profiles(path: str | Path) -> ProfileCatalog:
    if str(path).endswith(".json"):
        payload = json.loads(Path(path).read_text("utf-8"))
    else:
        payload = tomllib.loads(Path(path).read_text("utf-8"))
    profiles = payload.get("profiles", {})
    return ProfileCatalog(profiles={key: dict(value) for key, value in profiles.items()})


__all__ = [
    "CategoryDefinition",
    "ProfileCatalog",
    "TestCatalog",
    "TestDefinition",
    "evaluate_tests",
    "load_profiles",
    "load_test_catalog",
]
