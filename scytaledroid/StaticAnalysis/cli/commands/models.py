"""Command registry models for static analysis CLI."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

CommandHandler = Callable[[], None]


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
    selection_mode: str = "scope"  # "scope", "last", "diff_last", "batch_dataset"
    force_verbose: bool = False


__all__ = ["Command", "CommandHandler"]
