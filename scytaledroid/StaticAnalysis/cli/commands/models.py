"""Command registry models for static analysis CLI."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

CommandHandler = Callable[[], None]


class SelectionMode(StrEnum):
    SCOPE = "scope"
    LAST = "last"
    DIFF_LAST = "diff_last"


@dataclass(frozen=True)
class Command:
    """Definition for a CLI command entry."""

    id: str
    title: str
    description: str
    kind: str  # "scan" or "readonly"
    profile: str | None = None
    handler: CommandHandler | None = None
    section: str = "workflow"
    persist: bool = True
    dry_run: bool = False
    auto_verify: bool = False
    prompt_reset: bool = False
    force_app_scope: bool = False
    selection_mode: SelectionMode = SelectionMode.SCOPE
    force_verbose: bool = False


__all__ = ["Command", "CommandHandler", "SelectionMode"]
