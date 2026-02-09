"""Compatibility wrapper for deterministic NumPy percentiles.

Paper toolchain policy:
- Percentile algorithm must be explicit (no reliance on NumPy defaults).
- If the requested algorithm cannot be applied, fail closed with a clear error.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def percentile(
    a: Any,
    q: float,
    *,
    axis: int | None = None,
    method: str = "linear",
) -> Any:
    """Return np.percentile(a, q) using an explicit algorithm.

    Notes:
    - Newer NumPy uses the `method=` keyword.
    - Older NumPy uses `interpolation=` for equivalent behavior.
    """

    try:
        return np.percentile(a, q, axis=axis, method=method)
    except TypeError as exc:
        # Back-compat for older NumPy.
        try:
            return np.percentile(a, q, axis=axis, interpolation=method)  # type: ignore[call-arg]
        except Exception as exc2:  # noqa: BLE001
            raise RuntimeError(
                f"NumPy percentile method unsupported (method={method!r}). "
                f"Pin the paper toolchain or adjust configuration. "
                f"Original errors: {exc!r} / {exc2!r}"
            ) from exc2


__all__ = ["percentile"]

