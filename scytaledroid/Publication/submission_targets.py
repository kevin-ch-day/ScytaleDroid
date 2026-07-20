"""Stable identifiers and labels for active research submission targets."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SubmissionTarget:
    """Human and machine labels for one reproducible submission package."""

    identifier: str
    paper_label: str
    venue: str
    venue_short_label: str
    target_format: str

    @property
    def generation_label(self) -> str:
        return f"{self.paper_label} | {self.venue_short_label}"


IEEE_CARS_2026 = SubmissionTarget(
    identifier="IEEE-CARS-2026",
    paper_label="ScytaleDroid Paper #3",
    venue="IEEE Cyber Awareness and Research Symposium (IEEE CARS 2026)",
    venue_short_label="IEEE CARS 2026",
    target_format="IEEE conference format",
)


__all__ = ["IEEE_CARS_2026", "SubmissionTarget"]
