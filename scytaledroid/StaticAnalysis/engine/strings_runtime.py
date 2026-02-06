"""Runtime configuration for string-analysis behavior (frozen per run)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StringsRuntimeConfig:
    include_https_risk: bool = False
    debug: bool = False
    skip_resources_on_arsc_warn: bool = False
    long_string_length: int = 256
    low_entropy_threshold: float = 3.2


_CONFIG = StringsRuntimeConfig()


def get_config() -> StringsRuntimeConfig:
    return _CONFIG


def set_config(config: StringsRuntimeConfig) -> None:
    global _CONFIG
    _CONFIG = config


__all__ = ["StringsRuntimeConfig", "get_config", "set_config"]
