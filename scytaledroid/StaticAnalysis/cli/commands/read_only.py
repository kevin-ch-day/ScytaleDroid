"""Read-only command definitions."""

from __future__ import annotations

from .models import Command
from ..masvs_menu import render_masvs_summary_menu, render_scoring_explainer_menu

READ_ONLY_COMMANDS: tuple[Command, ...] = (
    Command(
        id="12",
        title="MASVS summary (read-only)",
        description="Summarise MASVS pass/fail by area from last baseline",
        kind="readonly",
        handler=render_masvs_summary_menu,
    ),
    Command(
        id="13",
        title="Risk scoring explainer (read-only)",
        description="Explain weights, breadth bonus and grade thresholds",
        kind="readonly",
        handler=render_scoring_explainer_menu,
    ),
)

__all__ = ["READ_ONLY_COMMANDS"]

