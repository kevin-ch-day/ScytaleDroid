"""Contrastive testing utilities for behavioral metrics."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable

import numpy as np


def js_divergence(p: Iterable[float], q: Iterable[float]) -> float:
    p_arr = np.asarray(list(p), dtype=float)
    q_arr = np.asarray(list(q), dtype=float)
    p_arr = p_arr / (p_arr.sum() or 1.0)
    q_arr = q_arr / (q_arr.sum() or 1.0)
    m = 0.5 * (p_arr + q_arr)
    return float(0.5 * (_kl_div(p_arr, m) + _kl_div(q_arr, m)))


def wasserstein_distance(x: Iterable[float], y: Iterable[float]) -> float:
    x_arr = np.sort(np.asarray(list(x), dtype=float))
    y_arr = np.sort(np.asarray(list(y), dtype=float))
    if x_arr.size == 0 or y_arr.size == 0:
        return 0.0
    x_cdf = np.cumsum(x_arr) / (x_arr.sum() or 1.0)
    y_cdf = np.cumsum(y_arr) / (y_arr.sum() or 1.0)
    min_len = min(len(x_cdf), len(y_cdf))
    return float(np.mean(np.abs(x_cdf[:min_len] - y_cdf[:min_len])))


def burstiness_cv(values: Iterable[float]) -> float:
    arr = np.asarray(list(values), dtype=float)
    if arr.size == 0:
        return 0.0
    mean = float(arr.mean())
    return float(arr.std() / mean) if mean else 0.0


def duty_cycle(active_flags: Iterable[bool]) -> float:
    flags = list(active_flags)
    if not flags:
        return 0.0
    return float(sum(1 for flag in flags if flag) / len(flags))


def transition_entropy(states: Iterable[str]) -> float:
    states_list = list(states)
    if len(states_list) < 2:
        return 0.0
    transitions: dict[tuple[str, str], int] = {}
    for prev, curr in zip(states_list, states_list[1:], strict=False):
        transitions[(prev, curr)] = transitions.get((prev, curr), 0) + 1
    total = sum(transitions.values())
    entropy = 0.0
    for count in transitions.values():
        prob = count / total
        entropy -= prob * math.log(prob + 1e-12, 2)
    return entropy


@dataclass(frozen=True)
class ContrastiveResult:
    conclusion: str
    js_divergence: float
    wasserstein: float
    effect_size_pass: bool
    replication_pass: bool


def evaluate_contrastive(
    *,
    js_value: float,
    wasserstein_value: float,
    effect_threshold: float,
    replication_ok: bool,
    label: str,
) -> ContrastiveResult:
    effect_pass = js_value >= effect_threshold
    conclusion = (
        f"{label}: meaningful difference"
        if effect_pass and replication_ok
        else f"{label}: difference not stable"
    )
    return ContrastiveResult(
        conclusion=conclusion,
        js_divergence=js_value,
        wasserstein=wasserstein_value,
        effect_size_pass=effect_pass,
        replication_pass=replication_ok,
    )


def _kl_div(p: np.ndarray, q: np.ndarray) -> float:
    eps = 1e-12
    p = np.clip(p, eps, 1.0)
    q = np.clip(q, eps, 1.0)
    return float(np.sum(p * np.log(p / q)))


__all__ = [
    "js_divergence",
    "wasserstein_distance",
    "burstiness_cv",
    "duty_cycle",
    "transition_entropy",
    "evaluate_contrastive",
    "ContrastiveResult",
]
