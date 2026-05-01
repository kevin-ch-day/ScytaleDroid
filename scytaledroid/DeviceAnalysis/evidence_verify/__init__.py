"""Filesystem-first harvest evidence verification (V1).

See docs/design/v1_evidence_catalog_verification.md — ``verify --filesystem-only``.
"""

from __future__ import annotations

from .filesystem import VerifyIssue, verify_harvest_filesystem

__all__ = ["VerifyIssue", "verify_harvest_filesystem"]


def __getattr__(name: str):
    if name == "verify_harvest_db_alignment":
        from .database import verify_harvest_db_alignment as fn

        return fn
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
