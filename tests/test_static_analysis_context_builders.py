"""Tests for static-analysis context building helpers."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.core.context import AnalysisConfig
from scytaledroid.StaticAnalysis.core.context_builders import derive_run_id


def test_derive_run_id_accepts_non_string_config_values() -> None:
    """run ID generation should coerce config values to strings."""

    config = AnalysisConfig(
        profile="full",
        verbosity=2,  # int
        persistence_mode=False,  # bool
        analysis_version=None,  # None
        enabled_detectors=("detector.alpha", 7, None),
    )

    run_id = derive_run_id("deadbeef", config)
    assert isinstance(run_id, str)
    assert len(run_id) == 12
    # Deterministic for identical inputs
    assert run_id == derive_run_id("deadbeef", config)
