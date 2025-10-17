"""Static analysis CLI option helpers."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Sequence

_DEFAULT_PROFILE = "full"
_DEFAULT_VERBOSITY = "summary"
_DEFAULT_EVIDENCE_LIMIT = 2
_VALID_PROFILES = ("quick", "full")
_VALID_VERBOSITIES = ("summary", "detail", "debug")


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
    show_pipeline: bool = True
    explore: bool = False

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
        parts.append(f"pipeline={'on' if self.show_pipeline else 'off'}")
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
    show_pipeline_default = _env_flag("SCYTALEDROID_STATIC_SHOW_PIPELINE", True)
    limit = _env_int("SCYTALEDROID_STATIC_FINDING_LIMIT", 3)

    show_findings = False if quiet else show_findings_default
    show_pipeline = False if quiet else show_pipeline_default

    return ScanDisplayOptions(
        quiet=quiet,
        show_findings=show_findings,
        show_timings=show_timings,
        finding_limit=limit,
        show_pipeline=show_pipeline,
    )


def parse_cli_args(argv: Sequence[str] | None = None) -> ScanDisplayOptions:
    """Parse CLI arguments controlling static analysis rendering."""

    parser = argparse.ArgumentParser(
        prog="scd-static",
        description="Render static analysis results with deterministic formatting.",
    )
    parser.set_defaults(show_pipeline=True)
    parser.add_argument(
        "--profile",
        choices=_VALID_PROFILES,
        default=_DEFAULT_PROFILE,
        help="Analysis profile to run (quick skips slower detectors).",
    )

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "--summary-only",
        dest="verbosity",
        action="store_const",
        const="summary",
        default=_DEFAULT_VERBOSITY,
        help="Render only the Base APK Summary block (default).",
    )
    verbosity_group.add_argument(
        "--detail",
        dest="verbosity",
        action="store_const",
        const="detail",
        help="Include topology, integrity, and findings tables for the base APK.",
    )
    verbosity_group.add_argument(
        "--debug",
        dest="verbosity",
        action="store_const",
        const="debug",
        help="Detail output plus debug appendix and raw logs.",
    )

    parser.add_argument(
        "--max-evidence",
        type=int,
        default=_DEFAULT_EVIDENCE_LIMIT,
        help="Maximum evidence pointers to display per section (before verbosity adjustments).",
    )

    parser.add_argument(
        "--hide-pipeline",
        dest="show_pipeline",
        action="store_false",
        help="Disable per-detector pipeline breakdown output.",
    )

    parser.add_argument(
        "--explore",
        action="store_true",
        help="Print exploratory string-intelligence summary metrics.",
    )

    namespace = parser.parse_args(argv)
    max_evidence = max(1, namespace.max_evidence)

    return ScanDisplayOptions(
        profile=namespace.profile,
        verbosity=namespace.verbosity,
        max_evidence=max_evidence,
        show_pipeline=namespace.show_pipeline,
        explore=namespace.explore,
    )


def describe_cli_flags(options: ScanDisplayOptions) -> str:
    """Return a concise textual summary of CLI-facing options."""

    return ", ".join(
        (
            f"profile={options.profile}",
            f"verbosity={options.verbosity}",
            f"evidence_limit={options.evidence_limit}",
            f"pipeline={'on' if options.show_pipeline else 'off'}",
            f"explore={'on' if options.explore else 'off'}",
        )
    )


__all__ = [
    "ScanDisplayOptions",
    "resolve_display_options",
    "parse_cli_args",
    "describe_cli_flags",
]
