"""Analytics utilities for post-processing static analysis results."""

from __future__ import annotations

from typing import Any, Mapping, Tuple

__all__ = ["build_finding_matrices", "build_workload_profile"]


def build_finding_matrices(*args: Any, **kwargs: Any) -> Tuple[Mapping[str, Mapping[str, Mapping[str, int]]], Mapping[str, float]]:
    from .matrices import build_finding_matrices as _impl

    return _impl(*args, **kwargs)


def build_workload_profile(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
    from .workload import build_workload_profile as _impl

    return _impl(*args, **kwargs)
