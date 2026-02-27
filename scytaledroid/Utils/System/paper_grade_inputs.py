"""Compatibility shim for the former `paper_grade_inputs.py` module.

Use `scytaledroid.Utils.System.governance_inputs` going forward.
"""

from __future__ import annotations

from .governance_inputs import render_dataset_readiness_line, render_governance_inputs

# Back-compat name
render_paper_grade_inputs = render_governance_inputs

__all__ = ["render_dataset_readiness_line", "render_governance_inputs", "render_paper_grade_inputs"]

