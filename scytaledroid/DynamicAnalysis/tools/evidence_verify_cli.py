"""Backward-compatible import wrapper.

The evidence-pack verifier CLI lives under:
`scytaledroid.DynamicAnalysis.tools.evidence.verify_cli`.
"""

from __future__ import annotations

from .evidence.verify_cli import run_dynamic_evidence_verify

__all__ = ["run_dynamic_evidence_verify"]

