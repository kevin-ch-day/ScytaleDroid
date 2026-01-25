"""Deprecated schema for AOSP permission baselines (legacy)."""

from __future__ import annotations

import warnings

warnings.warn(
    "aosp_permission_baseline is deprecated; use android_permission_dict_aosp.",
    DeprecationWarning,
    stacklevel=2,
)

_NOOP = ""

CREATE_BASELINE = _NOOP

__all__ = [
    "CREATE_BASELINE",
]
