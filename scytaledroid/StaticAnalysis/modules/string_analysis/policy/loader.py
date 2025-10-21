"""Policy loading helpers for string analysis."""

from __future__ import annotations

from pathlib import Path

from ..allowlist import DEFAULT_POLICY_ROOT, NoisePolicy, load_noise_policy


def load_policy(path: str | Path | None = None) -> NoisePolicy:
    """Load the configured :class:`NoisePolicy`.

    If *path* is ``None`` the default root from ``config/strings`` is used.  The
    helper mirrors :func:`~scytaledroid.StaticAnalysis.modules.string_analysis.allowlist.load_noise_policy`
    but provides a stable import location for the refactored extractor.
    """

    if path is None:
        path = DEFAULT_POLICY_ROOT
    return load_noise_policy(path)


__all__ = ["load_policy", "NoisePolicy"]
