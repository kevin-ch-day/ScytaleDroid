from __future__ import annotations

import math
from collections.abc import Mapping

__all__ = [
    "parse_vector",
    "score_vector",
    "severity_band",
    "apply_profiles",
    "resolve_threat_code",
    "resolve_env_metrics",
    "format_vector",
]


_ATTACK_WEIGHTS: Mapping[str, Mapping[str, float]] = {
    "AV": {"N": 1.0, "A": 0.85, "L": 0.6, "P": 0.2},
    "AC": {"L": 1.0, "H": 0.6},
    "AT": {"N": 1.0, "P": 0.7},
    "PR": {"N": 1.0, "L": 0.62, "H": 0.27},
    "UI": {"N": 1.0, "R": 0.6, "A": 0.4},
}

_IMPACT_WEIGHTS: Mapping[str, Mapping[str, float]] = {
    "VC": {"H": 2.5, "L": 1.75, "N": 0.0},
    "VI": {"H": 1.65, "L": 1.15, "N": 0.0},
    "VA": {"H": 0.9, "L": 0.52, "N": 0.0},
    "SC": {"H": 1.2, "L": 0.6, "N": 0.0},
    "SI": {"H": 1.2, "L": 0.6, "N": 0.0},
    "SA": {"H": 1.2, "L": 0.6, "N": 0.0},
}

_EXPLOITABILITY_CONSTANT = 4.58


def parse_vector(vector: str | None) -> dict[str, str]:
    if not vector or "CVSS:4.0/" not in vector:
        return {}
    metrics: dict[str, str] = {}
    for segment in vector.split("/"):
        if ":" not in segment or segment.startswith("CVSS"):
            continue
        key, value = segment.split(":", 1)
        metrics[key.upper()] = value.upper()
    return metrics


def format_vector(metrics: Mapping[str, str]) -> str:
    parts = ["CVSS:4.0"]
    for key in sorted(metrics.keys()):
        parts.append(f"{key}:{metrics[key]}")
    return "/".join(parts)


def _round_up(score: float) -> float:
    return math.ceil(score * 10.0) / 10.0


def score_vector(vector: str | None) -> float | None:
    metrics = parse_vector(vector)
    if not metrics:
        return None
    exploitability = 1.0
    for key, weights in _ATTACK_WEIGHTS.items():
        value = metrics.get(key)
        weight = weights.get(value or "")
        if weight is None:
            return None
        exploitability *= weight
    exploitability *= _EXPLOITABILITY_CONSTANT

    impact = 0.0
    for key, weights in _IMPACT_WEIGHTS.items():
        value = metrics.get(key)
        if value is None:
            continue
        weight = weights.get(value)
        if weight is None:
            return None
        impact += weight

    total = min(impact + exploitability, 10.0)
    return _round_up(total)


def severity_band(score: float | None) -> str | None:
    """Return the CVSS 4.0 qualitative band for ``score``.

    The band mapping follows the CVSS v4.0 guidance:

    - Critical: 9.0 – 10.0
    - High:     7.0 – 8.9
    - Medium:   4.0 – 6.9
    - Low:      0.1 – 3.9
    - None:     0.0
    """

    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def resolve_threat_code(threat_profile: str | None) -> str:
    profile = (threat_profile or "Unknown").strip()
    return {
        "Unknown": "U",
        "Unreported": "U",
        "ProofOfConcept": "P",
        "PoC": "P",
        "Active": "A",
        "Attacked": "A",
        "Weaponized": "W",
    }.get(profile, "U")


def resolve_env_metrics(env_profile: str | None) -> Mapping[str, str]:
    profile = (env_profile or "consumer").strip().lower()
    mapping = {
        "consumer": {"CR": "M", "IR": "M", "AR": "M"},
        "enterprise": {"CR": "H", "IR": "H", "AR": "H"},
    }
    return mapping.get(profile, mapping["consumer"])


def apply_profiles(
    base_vector: str | None,
    threat_profile: str | None,
    env_profile: str | None,
) -> tuple[str | None, float | None, str | None, float | None, str | None, float | None, dict[str, object]]:
    if not base_vector:
        return None, None, None, None, None, None, {}

    base_metrics = parse_vector(base_vector)
    threat_code = resolve_threat_code(threat_profile)
    env_metrics = resolve_env_metrics(env_profile)

    bt_metrics = dict(base_metrics)
    bt_metrics["E"] = threat_code

    be_metrics = dict(base_metrics)
    be_metrics.update(env_metrics)

    bte_metrics = dict(be_metrics)
    bte_metrics["E"] = threat_code

    bt_vector = format_vector(bt_metrics)
    be_vector = format_vector(be_metrics)
    bte_vector = format_vector(bte_metrics)

    meta = {
        "threat": {"profile": threat_profile or "Unknown", "E": threat_code},
        "env": {"profile": env_profile or "consumer", **env_metrics},
    }

    return (
        bt_vector,
        score_vector(bt_vector),
        be_vector,
        score_vector(be_vector),
        bte_vector,
        score_vector(bte_vector),
        meta,
    )