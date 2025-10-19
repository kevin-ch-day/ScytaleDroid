"""Read-only command definitions."""

from __future__ import annotations

from .models import Command
from ..masvs_menu import (
    render_masvs_summary_menu,
    render_scoring_explainer_menu,
    render_masvs_matrix_menu,
)
from ..diagnostics import render_static_diagnostics_menu

READ_ONLY_COMMANDS: tuple[Command, ...] = (
    Command(
        id="4",
        title="MASVS summary (read-only)",
        description="Summarise MASVS pass/fail by area from last baseline",
        kind="readonly",
        handler=render_masvs_summary_menu,
        section="insight",
    ),
    Command(
        id="5",
        title="Risk scoring explainer (read-only)",
        description="Explain weights, breadth bonus and grade thresholds",
        kind="readonly",
        handler=render_scoring_explainer_menu,
        section="insight",
    ),
    Command(
        id="6",
        title="Diagnostics & verification",
        description="Run post-scan verification and database health checks",
        kind="readonly",
        handler=render_static_diagnostics_menu,
        section="insight",
    ),
    Command(
        id="7",
        title="MASVS matrix",
        description="Matrix of MASVS pass/fail across latest package runs",
        kind="readonly",
        handler=render_masvs_matrix_menu,
        section="insight",
    ),
)

__all__ = ["READ_ONLY_COMMANDS"]
