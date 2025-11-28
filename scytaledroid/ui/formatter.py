"""Plain-text formatting helpers for forensic-style CLI output."""

from __future__ import annotations

from typing import Dict


def print_header(title: str, subtitle: str | None = None) -> None:
    print(title)
    print("=" * len(title))
    if subtitle:
        print(subtitle)
    print()


def format_kv_block(prefix: str, pairs: Dict[str, str]) -> str:
    """
    Return a block of key/value lines with a common prefix.

    Example:
        [RUN] Target      : App "Foo" (com.foo)
        [RUN] Profile     : full
    """
    lines: list[str] = []
    for key, value in pairs.items():
        lines.append(f"{prefix} {key:<12}: {value}")
    return "\n".join(lines)
