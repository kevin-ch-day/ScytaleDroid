"""Tests for CLI analysis configuration helpers."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution.scan_flow import build_analysis_config
from scytaledroid.StaticAnalysis.cli.models import RunParameters


def _params(**overrides) -> RunParameters:
    base = dict(profile="full", scope="app", scope_label="Single")
    base.update(overrides)
    return RunParameters(**base)


def test_build_analysis_config_applies_sampler_overrides() -> None:
    params = _params(
        secrets_entropy=6.4,
        secrets_hits_per_bucket=12,
        secrets_scope="dex",
    )

    config = build_analysis_config(params)

    assert config.secrets_sampler is not None
    assert config.secrets_sampler.entropy_threshold == 6.4
    assert config.secrets_sampler.hits_per_bucket == 12
    assert config.secrets_sampler.scope == "dex-only"


def test_build_analysis_config_guards_sampler_lower_bounds() -> None:
    params = _params(secrets_entropy=-1.0, secrets_hits_per_bucket=0)

    config = build_analysis_config(params)

    assert config.secrets_sampler is not None
    assert config.secrets_sampler.entropy_threshold == 0.0
    assert config.secrets_sampler.hits_per_bucket == 1


def test_build_analysis_config_enables_string_index_for_custom_strings() -> None:
    params = _params(profile="custom", selected_tests=("secrets", "manifest"))

    config = build_analysis_config(params)

    assert config.enable_string_index is True


def test_build_analysis_config_disables_string_index_for_metadata_profile() -> None:
    params = _params(profile="metadata")

    config = build_analysis_config(params)

    assert config.profile == "quick"
    assert config.enable_string_index is False


def test_run_parameters_canonicalise_secrets_scope() -> None:
    params = _params(secrets_scope="resources")
    assert params.secrets_scope_canonical == "resources-only"

    params = _params(secrets_scope="dex-only")
    assert params.secrets_scope_canonical == "dex-only"

    params = _params(secrets_scope="UNKNOWN")
    assert params.secrets_scope_canonical == "both"
