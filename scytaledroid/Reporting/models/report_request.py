"""Typed report request model for study-oriented reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

STUDY_PROFILE_KEYS = {
    "static_exposure_privacy",
    "runtime_network_behavior",
    "integrated_static_runtime",
}
SCOPE_TYPES = {
    "research_cohort",
    "application_category",
    "all_eligible_apps",
    "single_app",
    "saved_custom_scope",
}
EVIDENCE_BASIS_TYPES = {
    "exact_historical_freeze",
    "named_static_session",
    "selected_publication_manifest",
    "latest_valid_as_of",
    "fixed_recent_window",
}
OUTPUT_CONTRACTS = {
    "exploratory",
    "publication_candidate",
    "frozen",
}
REQUESTED_FORMATS = {"csv", "json", "txt", "tex", "figures"}


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class ReportRequest:
    """Resolved report request.

    The request intentionally preserves each independent operator choice rather
    than inferring scope, evidence basis, or report output mode from the study.
    """

    study_profile_key: str
    study_profile_version: str
    scope_type: str
    scope_key: str
    scope_label: str
    package_names: list[str]
    evidence_basis_type: str
    evidence_basis_key: str
    output_contract: str
    requested_formats: list[str] = field(default_factory=lambda: ["csv", "json", "txt", "figures"])
    generated_at_utc: str = field(default_factory=_utc_now)
    as_of_utc: str | None = None
    window_start_utc: str | None = None
    window_end_utc: str | None = None
    operator_notes: str = ""
    scope_exclusions: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.study_profile_key not in STUDY_PROFILE_KEYS:
            raise ValueError(f"Unsupported study_profile_key: {self.study_profile_key}")
        if self.scope_type not in SCOPE_TYPES:
            raise ValueError(f"Unsupported scope_type: {self.scope_type}")
        if self.evidence_basis_type not in EVIDENCE_BASIS_TYPES:
            raise ValueError(f"Unsupported evidence_basis_type: {self.evidence_basis_type}")
        if self.output_contract not in OUTPUT_CONTRACTS:
            raise ValueError(f"Unsupported output_contract: {self.output_contract}")
        bad_formats = [fmt for fmt in self.requested_formats if fmt not in REQUESTED_FORMATS]
        if bad_formats:
            raise ValueError(f"Unsupported requested_formats: {', '.join(bad_formats)}")
        self.package_names[:] = sorted({str(pkg).strip().lower() for pkg in self.package_names if str(pkg).strip()})
        if self.scope_type == "single_app" and len(self.package_names) != 1:
            raise ValueError("single_app reports must resolve exactly one package")
        if not self.package_names and self.scope_type != "all_eligible_apps":
            raise ValueError("report request must preserve at least one resolved package for this scope")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ReportRequest:
        return cls(**payload)
