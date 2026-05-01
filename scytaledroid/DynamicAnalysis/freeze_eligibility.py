"""Canonical freeze/cohort eligibility helpers.

This module is the preferred import path for active code. It preserves the
existing evidence-first eligibility logic while the repo transitions away from
paper-era module naming.
"""

from __future__ import annotations

from .paper_eligibility import (
    EXCLUSION_REASON_CODES,
    EXCLUSION_REASON_PRECEDENCE,
    PaperEligibility,
    derive_paper_eligibility,
)

# Canonical aliases for active code.
FreezeEligibility = PaperEligibility
derive_freeze_eligibility = derive_paper_eligibility

__all__ = [
    "EXCLUSION_REASON_CODES",
    "EXCLUSION_REASON_PRECEDENCE",
    "FreezeEligibility",
    "PaperEligibility",
    "derive_freeze_eligibility",
    "derive_paper_eligibility",
]
