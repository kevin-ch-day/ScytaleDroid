"""Glyph utilities for terminal-friendly static analysis output."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GlyphSet:
    """Collection of glyphs with ASCII fallbacks for deterministic output."""

    check: str
    cross: str
    partial: str
    xref: str
    pointer: str
    bullet: str
    rule: str
    branch: str
    branch_last: str
    branch_pipe: str
    bar_levels: str
    ascii_bar: str
    arrow_right: str
    line_width: int
    use_color: bool
    supports_unicode: bool
    is_tty: bool

    @classmethod
    def for_tty(
        cls,
        is_tty: bool,
        *,
        supports_unicode: bool = True,
        use_color: bool = False,
        line_width: int = 64,
    ) -> "GlyphSet":
        """Return a glyph configuration tuned to the active terminal."""

        clamped_width = max(40, min(line_width, 120))

        if not is_tty or not supports_unicode:
            return cls(
                check="+",
                cross="-",
                partial="~",
                xref="<->",
                pointer="v",
                bullet="-",
                rule="-",
                branch="|-",
                branch_last="\\-",
                branch_pipe="| ",
                bar_levels="",
                ascii_bar="#",
                arrow_right="->",
                line_width=clamped_width,
                use_color=False,
                supports_unicode=False,
                is_tty=is_tty,
            )

        return cls(
            check="✓",
            cross="✗",
            partial="≈",
            xref="⇄",
            pointer="↧",
            bullet="•",
            rule="─",
            branch="├─",
            branch_last="└─",
            branch_pipe="│ ",
            bar_levels="▏▎▍▌▋▊▉█",
            ascii_bar="#",
            arrow_right="→",
            line_width=clamped_width,
            use_color=use_color,
            supports_unicode=True,
            is_tty=is_tty,
        )

    def bar(self, value: float, max_value: float, *, width: int = 10) -> str:
        """Return a proportional bar using unicode blocks or ASCII."""

        if width <= 0 or max_value <= 0 or value <= 0:
            return ""

        ratio = min(max(value / max_value, 0.0), 1.0)

        if not self.is_tty or not self.bar_levels:
            filled = max(1, int(round(ratio * width)))
            return self.ascii_bar * filled

        levels = self.bar_levels
        level_count = len(levels)
        total_units = width * level_count
        filled_units = int(round(ratio * total_units))

        full_blocks, remainder = divmod(filled_units, level_count)
        bar_chars: list[str] = []
        if full_blocks:
            bar_chars.append(levels[-1] * full_blocks)
        if remainder:
            bar_chars.append(levels[remainder - 1])
        return "".join(bar_chars)


__all__ = ["GlyphSet"]
