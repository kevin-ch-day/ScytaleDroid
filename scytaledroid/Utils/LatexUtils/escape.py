"""LaTeX escaping helpers.

We keep this intentionally small and conservative:
- escape text-mode special chars
- allow explicitly-marked raw LaTeX snippets to pass through
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RawLatex:
    """Wrapper to mark content as already-valid LaTeX (no escaping)."""

    s: str

    def __str__(self) -> str:  # pragma: no cover
        return self.s


_LATEX_TEXT_ESCAPES: dict[str, str] = {
    "\\": "\\textbackslash{}",
    "&": "\\&",
    "%": "\\%",
    "$": "\\$",
    "#": "\\#",
    "_": "\\_",
    "{": "\\{",
    "}": "\\}",
    "~": "\\textasciitilde{}",
    "^": "\\textasciicircum{}",
}


def latex_escape_text(value: object) -> str:
    """Escape a value for LaTeX text mode.

    If value is RawLatex, it is returned verbatim.
    """

    if isinstance(value, RawLatex):
        return value.s
    s = str(value if value is not None else "")
    # Fast path: no special chars.
    if not any(ch in s for ch in _LATEX_TEXT_ESCAPES):
        return s
    return "".join(_LATEX_TEXT_ESCAPES.get(ch, ch) for ch in s)


__all__ = ["RawLatex", "latex_escape_text"]

