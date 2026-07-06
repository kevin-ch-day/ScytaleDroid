"""Shared models and constants for dynamic plan handling."""

from __future__ import annotations

from dataclasses import dataclass, field

SUPPORTED_SIGNATURE_VERSIONS = {"v1"}
SUPPORTED_PLAN_SCHEMA_VERSIONS = {"v1"}


@dataclass(frozen=True)
class PlanValidationOutcome:
    status: str
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    mismatches: list[dict[str, str]] = field(default_factory=list)
    plan: dict[str, object] = field(default_factory=dict)
    db: dict[str, object] = field(default_factory=dict)
    source: str = "static_analysis_runs"

    @property
    def is_pass(self) -> bool:
        return self.status == "PASS"


class PlanValidationError(RuntimeError):
    def __init__(self, outcome: PlanValidationOutcome) -> None:
        super().__init__("dynamic plan validation failed")
        self.outcome = outcome

