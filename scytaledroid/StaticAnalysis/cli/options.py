"""Display configuration for static-analysis CLI runs."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        candidate = int(value)
        return candidate if candidate > 0 else default
    except ValueError:
        return default


@dataclass(frozen=True)
class ScanDisplayOptions:
    """Controls how static-analysis progress is rendered."""

    quiet: bool = False
    show_findings: bool = False
    show_timings: bool = True
    finding_limit: int = 3

    def describe(self) -> str:
        parts: list[str] = []
        parts.append(f"quiet={'on' if self.quiet else 'off'}")
        parts.append(f"timings={'on' if self.show_timings else 'off'}")
        parts.append(
            f"findings={'top ' + str(self.finding_limit) if self.show_findings else 'off'}"
        )
        return ", ".join(parts)


def resolve_display_options() -> ScanDisplayOptions:
    quiet = _env_flag("SCYTALEDROID_STATIC_QUIET", False)
    show_findings_default = _env_flag("SCYTALEDROID_STATIC_SHOW_FINDINGS", False)
    show_timings = _env_flag("SCYTALEDROID_STATIC_SHOW_TIMINGS", True)
    limit = _env_int("SCYTALEDROID_STATIC_FINDING_LIMIT", 3)

    show_findings = False if quiet else show_findings_default

    return ScanDisplayOptions(
        quiet=quiet,
        show_findings=show_findings,
        show_timings=show_timings,
        finding_limit=limit,
    )


__all__ = ["ScanDisplayOptions", "resolve_display_options"]
