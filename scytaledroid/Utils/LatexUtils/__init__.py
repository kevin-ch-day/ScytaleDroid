"""Centralized helpers for consistent LaTeX output.

Goals:
- Single escaping implementation (avoid drift across modules).
- Consistent booktabs-style tabular rendering.
- Optional IEEE-friendly float wrappers for tables.

This package intentionally stays dependency-free.
"""

from .escape import RawLatex, latex_escape_text
from .labels import latex_labelify
from .tables import (
    LatexTableSpec,
    render_table_float,
    render_tabular_only,
)

__all__ = [
    "RawLatex",
    "latex_escape_text",
    "latex_labelify",
    "LatexTableSpec",
    "render_tabular_only",
    "render_table_float",
]

