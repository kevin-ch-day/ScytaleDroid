"""Scoring curves shared by per-permission severity and app-level risk.

Two identities are used, both standard in security scoring:

* Independent-risk / noisy-OR / CVSS Impact Sub-Score:
  ``scale * (1 - Π (1 - w_i / scale))``. Same-dimension impacts (C/I/A in
  CVSS v3.1, protection tokens here) are unions, not sums.
* CARA saturating exponential ``C (1 - e^{-n w / C})``: concave in the
  count, initial slope ``w``, asymptote ``C``. This is the smooth form of
  diminishing returns; a linear-then-hard-cap has a kink in the derivative.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


def saturating_response(count: float, weight: float, cap: float) -> float:
    """Diminishing-return response ``C (1 - e^{-n w / C})``.

    Initial slope is ``weight``. The second derivative is negative for ``C>0``.
    ``cap <= 0`` keeps the historical linear term ``n * weight``.
    """

    n = max(0.0, float(count))
    w = max(0.0, float(weight))
    ceiling = float(cap)
    if n == 0.0 or w == 0.0:
        return 0.0
    if ceiling <= 0.0:
        return n * w
    return ceiling * (1.0 - math.exp(-n * w / ceiling))


def saturating_marginal(count: float, weight: float, cap: float) -> float:
    """First derivative ``d/dn`` of :func:`saturating_response`.

    Equals ``weight`` at ``n=0`` and decays as ``w e^{-n w / C}``.
    """

    n = max(0.0, float(count))
    w = max(0.0, float(weight))
    ceiling = float(cap)
    if w == 0.0:
        return 0.0
    if ceiling <= 0.0:
        return w
    return w * math.exp(-n * w / ceiling)


def independent_risk_combine(weights: Sequence[float], *, scale: float) -> float:
    """CVSS-style ISS / noisy-OR combine on a shared impact scale.

    Numerically uses ``sum log1p(-p_i)`` so many small components stay stable.
    A component with ``p >= 1`` saturates the scale immediately.
    """

    if not weights or scale <= 0.0:
        return 0.0
    log_survival = 0.0
    for raw in weights:
        weight = max(0.0, float(raw))
        if weight <= 0.0:
            continue
        if weight >= scale:
            return float(scale)
        log_survival += math.log1p(-weight / scale)
    return float(scale) * (1.0 - math.exp(log_survival))


__all__ = [
    "independent_risk_combine",
    "saturating_marginal",
    "saturating_response",
]
