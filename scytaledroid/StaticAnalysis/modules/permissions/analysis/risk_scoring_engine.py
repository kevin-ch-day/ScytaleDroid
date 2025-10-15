"""Risk scoring engine (permission-first).

This thin module re-exports the public scoring API. Prefer importing from
here in new code. The underlying implementation remains in ``scoring.py``.
"""

from __future__ import annotations

from .scoring import permission_risk_score, permission_risk_grade

__all__ = ["permission_risk_score", "permission_risk_grade"]

