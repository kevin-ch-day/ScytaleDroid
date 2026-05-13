from __future__ import annotations

from dataclasses import replace

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.execution.scan_report import build_analysis_config


def _base_params(**overrides: object) -> RunParameters:
    p = RunParameters(profile="full", scope="all", scope_label="All")
    return replace(p, **overrides)


def test_string_index_resources_full_preset() -> None:
    cfg = build_analysis_config(_base_params(profile="full"))
    assert cfg.string_index_include_resources is True


def test_string_index_resources_strings_preset() -> None:
    cfg = build_analysis_config(_base_params(profile="strings"))
    assert cfg.profile == "quick"
    assert cfg.string_index_include_resources is True


def test_string_index_resources_lightweight_omits_res() -> None:
    cfg = build_analysis_config(_base_params(profile="lightweight"))
    assert cfg.profile == "quick"
    assert cfg.string_index_include_resources is False


def test_string_index_resources_split_preset_omits_res() -> None:
    cfg = build_analysis_config(_base_params(profile="split"))
    assert cfg.string_index_include_resources is False


def test_string_index_resources_unknown_profile_defaults_full_pipeline() -> None:
    cfg = build_analysis_config(_base_params(profile="custom_operator_preset"))
    assert cfg.profile == "full"
    assert cfg.string_index_include_resources is True
