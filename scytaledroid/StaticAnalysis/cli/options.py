"""Static analysis CLI option helpers."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Sequence

_DEFAULT_PROFILE = "full"
_DEFAULT_VERBOSITY = "normal"
_DEFAULT_EVIDENCE_LIMIT = 2
_VALID_PROFILES = ("quick", "full")
_VALID_VERBOSITIES = ("normal", "detail", "debug")


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
    """Controls static-analysis output for both interactive and CLI flows."""

    profile: str = _DEFAULT_PROFILE
    verbosity: str = _DEFAULT_VERBOSITY
    max_evidence: int = _DEFAULT_EVIDENCE_LIMIT
    quiet: bool = False
    show_findings: bool = False
    show_timings: bool = True
    finding_limit: int = 3

    def describe(self) -> str:
        parts: list[str] = []
        parts.append(f"profile={self.profile}")
        parts.append(f"verbosity={self.verbosity}")
        parts.append(f"max_evidence={self.max_evidence}")
        parts.append(f"quiet={'on' if self.quiet else 'off'}")
        parts.append(f"timings={'on' if self.show_timings else 'off'}")
        findings = (
            f"top {self.finding_limit}" if self.show_findings else "off"
        )
        parts.append(f"findings={findings}")
        return ", ".join(parts)

    @property
    def evidence_limit(self) -> int:
        """Return the evidence display limit adjusted for verbosity."""

        if self.verbosity in {"detail", "debug"}:
            return max(self.max_evidence, 5)
        return max(1, self.max_evidence)


def resolve_display_options() -> ScanDisplayOptions:
    """Resolve menu display options from environment defaults."""

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


def parse_cli_args(argv: Sequence[str] | None = None) -> ScanDisplayOptions:
    """Parse CLI arguments controlling static analysis rendering."""

    parser = argparse.ArgumentParser(
        prog="scd-static",
        description="Render static analysis results with deterministic formatting.",
    )
    parser.add_argument(
        "--profile",
        choices=_VALID_PROFILES,
        default=_DEFAULT_PROFILE,
        help="Analysis profile to run (quick skips slower detectors).",
    )
    parser.add_argument(
        "--verbosity",
        choices=_VALID_VERBOSITIES,
        default=_DEFAULT_VERBOSITY,
        help="Verbosity for section output.",
    )
    parser.add_argument(
        "--max-evidence",
        type=int,
        default=_DEFAULT_EVIDENCE_LIMIT,
        help="Maximum evidence pointers to display per section (before verbosity adjustments).",
    )

    namespace = parser.parse_args(argv)
    max_evidence = max(1, namespace.max_evidence)

    return ScanDisplayOptions(
        profile=namespace.profile,
        verbosity=namespace.verbosity,
        max_evidence=max_evidence,
    )


def describe_cli_flags(options: ScanDisplayOptions) -> str:
    """Return a concise textual summary of CLI-facing options."""

    return ", ".join(
        (
            f"profile={options.profile}",
            f"verbosity={options.verbosity}",
            f"evidence_limit={options.evidence_limit}",
        )
    )


__all__ = [
    "ScanDisplayOptions",
    "resolve_display_options",
    "parse_cli_args",
    "describe_cli_flags",
]
