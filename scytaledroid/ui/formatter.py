"""Plain-text formatting helpers for forensic-style CLI output."""

from __future__ import annotations

from typing import Dict

from scytaledroid.Utils.DisplayUtils import colors, text_blocks


def print_header(title: str, subtitle: str | None = None) -> None:
    headline = text_blocks.headline(title)
    print(headline)
    if subtitle:
        palette = colors.get_palette()
        sub = colors.apply(subtitle, palette.muted) if colors.colors_enabled() else subtitle
        print(sub)
    print()


def format_kv_block(prefix: str, pairs: Dict[str, str]) -> str:
    """
    Return a block of key/value lines with a common prefix.

    Example:
        [RUN] Target      : App "Foo" (com.foo)
        [RUN] Profile     : full
    """
    lines: list[str] = []
    max_key = max((len(str(key)) for key in pairs), default=0)
    palette = colors.get_palette()
    use_color = colors.colors_enabled()
    prefix_text = prefix
    if use_color:
        prefix_text = colors.apply(prefix, palette.muted)
    for key, value in pairs.items():
        key_text = f"{key:<{max_key}}"
        if use_color:
            key_text = colors.apply(key_text, palette.muted)
            value = colors.apply(str(value), palette.text)
        lines.append(f"{prefix_text} {key_text}: {value}")
    return "\n".join(lines)
