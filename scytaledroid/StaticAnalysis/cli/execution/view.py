"""Formatting helpers for static analysis result output."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetailBuffer:
    lines: list[str] = field(default_factory=list)

    def add(self, line: str = "") -> None:
        self.lines.append(line)


__all__ = ["DetailBuffer"]
