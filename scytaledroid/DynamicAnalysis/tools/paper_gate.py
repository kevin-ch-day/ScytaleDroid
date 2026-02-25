"""Compatibility shim for the former `paper_gate.py` module."""

from __future__ import annotations

from .freeze_gate import GateResult, main, run_freeze_gate

# Back-compat alias
run_paper_gate = run_freeze_gate

__all__ = ["GateResult", "run_paper_gate", "run_freeze_gate", "main"]

