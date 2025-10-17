"""Signal post-processing helpers for string analysis."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .allowlist import NoisePolicy, load_noise_policy
from .detectors import (
    Fragment,
    collect_fragments,
    iterate_fragment_observations,
    iterate_pair_observations,
)
from .extractor import StringIndex
from .schema import Observation, SniSummary
from .scoring import ProfileCatalog, TestCatalog, evaluate_tests, load_profiles, load_test_catalog

_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_TESTS = _REPO_ROOT / "config" / "sni_tests.json"
_DEFAULT_PROFILES = _REPO_ROOT / "config" / "risk_profiles.json"


def _resolve_test_catalog(test_catalog: TestCatalog | str | Path | None) -> TestCatalog | None:
    if test_catalog is None:
        path = _DEFAULT_TESTS
        if not path.exists():
            return None
        return load_test_catalog(path)
    if isinstance(test_catalog, TestCatalog):
        return test_catalog
    path = Path(test_catalog)
    if not path.exists():
        return None
    return load_test_catalog(path)


def _resolve_profile_catalog(profile_catalog: ProfileCatalog | str | Path | None) -> ProfileCatalog | None:
    if profile_catalog is None:
        path = _DEFAULT_PROFILES
        if not path.exists():
            return None
        return load_profiles(path)
    if isinstance(profile_catalog, ProfileCatalog):
        return profile_catalog
    path = Path(profile_catalog)
    if not path.exists():
        return None
    return load_profiles(path)


def _sort_key(obs: Observation) -> tuple[str, int | None, str]:
    return (obs.src, obs.evidence.offset if obs.evidence.offset is not None else -1, obs.value)


def _route_observation(policy: NoisePolicy, obs: Observation) -> bool:
    host = getattr(obs, "host", None)
    if policy.is_documentary_source(obs.src):
        return False
    if host and policy.is_documentary_host(host):
        return False
    return True


def _extend_with_fragments(
    policy: NoisePolicy,
    fragments: Iterable[Fragment],
    risk: list[Observation],
    documentary: list[Observation],
) -> None:
    for fragment in fragments:
        for obs in iterate_fragment_observations(fragment):
            (risk if _route_observation(policy, obs) else documentary).append(obs)


def summarise(
    index: StringIndex,
    *,
    noise_policy: NoisePolicy | None = None,
    test_catalog: TestCatalog | str | Path | None = None,
    profile_catalog: ProfileCatalog | str | Path | None = None,
    profile: str = "enterprise",
) -> SniSummary:
    """Return structured SNI summary for *index*."""

    policy = noise_policy or NoisePolicy(frozenset(), frozenset())
    fragments_by_origin = collect_fragments(index)
    risk: list[Observation] = []
    documentary: list[Observation] = []

    for _, fragments in fragments_by_origin.items():
        _extend_with_fragments(policy, fragments, risk, documentary)
        risk.extend(iterate_pair_observations(fragments))

    risk_sorted = tuple(sorted(risk, key=_sort_key))
    doc_sorted = tuple(sorted(documentary, key=_sort_key))

    scorecard = None
    catalog = _resolve_test_catalog(test_catalog)
    profiles = _resolve_profile_catalog(profile_catalog)
    if catalog and profiles:
        try:
            scorecard = evaluate_tests(risk_sorted, catalog, profiles, profile)
        except KeyError:
            scorecard = None

    return SniSummary(risk_relevant=risk_sorted, documentary=doc_sorted, scorecard=scorecard)


__all__ = ["NoisePolicy", "load_noise_policy", "summarise"]
