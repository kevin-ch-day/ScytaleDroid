"""Compatibility shim for the former `paper_readiness_audit.py` module."""

from __future__ import annotations

from .freeze_readiness_audit import AuditSummary, run_freeze_readiness_audit

# Back-compat alias
run_paper_readiness_audit = run_freeze_readiness_audit

__all__ = ["AuditSummary", "run_paper_readiness_audit", "run_freeze_readiness_audit"]
