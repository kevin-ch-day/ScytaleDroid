"""Command registry for static analysis CLI menu."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Command
from .read_only import READ_ONLY_COMMANDS
from .scans import SCAN_COMMANDS

# Preserve declaration order from scans.py/read_only.py; some ids are non-numeric
COMMANDS: list[Command] = [*SCAN_COMMANDS, *READ_ONLY_COMMANDS]


def get_command(command_id: str) -> Command | None:
    for cmd in COMMANDS:
        if cmd.id == command_id:
            return cmd
    return None


def iter_commands(kind: str | None = None) -> Iterable[Command]:
    if kind is None:
        return tuple(COMMANDS)
    return tuple(cmd for cmd in COMMANDS if cmd.kind == kind)


__all__ = ["COMMANDS", "get_command", "iter_commands"]