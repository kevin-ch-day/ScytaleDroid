"""Command registry models for static analysis CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

CommandHandler = Callable[[], None]


@dataclass(frozen=True)
class Command:
    """Definition for a CLI command entry."""

    id: str
    title: str
    description: str
    kind: str  # "scan" or "readonly"
    profile: Optional[str] = None
    handler: Optional[CommandHandler] = None


__all__ = ["Command", "CommandHandler"]

