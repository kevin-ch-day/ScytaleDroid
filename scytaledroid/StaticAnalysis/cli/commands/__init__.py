"""Command registry for static analysis CLI menu."""

from __future__ import annotations

from typing import Iterable, List, Optional

from .models import Command
from .read_only import READ_ONLY_COMMANDS
from .scans import SCAN_COMMANDS

COMMANDS: List[Command] = sorted(
    [*SCAN_COMMANDS, *READ_ONLY_COMMANDS], key=lambda cmd: int(cmd.id)
)


def get_command(command_id: str) -> Optional[Command]:
    for cmd in COMMANDS:
        if cmd.id == command_id:
            return cmd
    return None


def iter_commands(kind: str | None = None) -> Iterable[Command]:
    if kind is None:
        return tuple(COMMANDS)
    return tuple(cmd for cmd in COMMANDS if cmd.kind == kind)


__all__ = ["COMMANDS", "get_command", "iter_commands"]

