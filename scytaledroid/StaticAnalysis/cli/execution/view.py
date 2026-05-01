"""Formatting helpers for static analysis result output."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetailBuffer:
    lines: list[str] = field(default_factory=list)

    def add(self, line: str = "") -> None:
        self.lines.append(line)

    def compact_lines(self) -> list[str]:
        compacted: list[str] = []
        pending_blank = False
        started = False
        for line in self.lines:
            text = str(line)
            if not text.strip():
                if started:
                    pending_blank = True
                continue
            if pending_blank and compacted:
                compacted.append("")
            compacted.append(text)
            started = True
            pending_blank = False
        return compacted


__all__ = ["DetailBuffer"]
