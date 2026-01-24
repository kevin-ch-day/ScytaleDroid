"""Dynamic analysis entrypoints."""

from __future__ import annotations

from .core import DynamicSessionConfig, DynamicSessionResult, run_dynamic_session


def run_dynamic_analysis(package_name: str, *, duration_seconds: int = 120) -> DynamicSessionResult:
    config = DynamicSessionConfig(
        package_name=package_name,
        duration_seconds=duration_seconds,
    )
    return run_dynamic_session(config)


__all__ = ["run_dynamic_analysis"]
