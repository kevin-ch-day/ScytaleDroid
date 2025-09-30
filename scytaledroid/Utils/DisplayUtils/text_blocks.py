"""text_blocks.py - Reusable helpers for consistent CLI text output."""

from __future__ import annotations

from typing import Iterable


DEFAULT_WIDTH = 60


def divider(char: str = "-", width: int = DEFAULT_WIDTH) -> str:
    """Return a horizontal divider line."""
    return char * width


def boxed(lines: Iterable[str], *, width: int = DEFAULT_WIDTH) -> str:
    """Return lines surrounded by a simple ASCII box."""
    processed = [line.rstrip() for line in lines]
    max_len = max((len(line) for line in processed), default=0)
    inner_width = min(max_len, width - 4)
    cap = "+" + "-" * (inner_width + 2) + "+"
    output = [cap]
    for line in processed:
        truncated = line[:inner_width]
        padding = " " * (inner_width - len(truncated))
        output.append(f"| {truncated}{padding} |")
    output.append(cap)
    return "\n".join(output)


def headline(title: str, *, width: int = DEFAULT_WIDTH) -> str:
    """Return a headline with an underline."""
    title = title.strip()
    bar = divider("=", width=min(len(title), width))
    return f"{title}\n{bar}"


def bullet_list(items: Iterable[str], *, bullet: str = "- ") -> str:
    """Return formatted bullet list."""
    return "\n".join(f"{bullet}{item}" for item in items)
