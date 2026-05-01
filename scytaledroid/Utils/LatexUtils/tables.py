"""LaTeX table rendering helpers (booktabs-first, IEEE-friendly defaults)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .escape import RawLatex, latex_escape_text


@dataclass(frozen=True)
class LatexTableSpec:
    """Specification for a LaTeX table float.

    This wraps a pre-rendered tabular. It does not attempt to implement a full
    LaTeX templating system.
    """

    caption: object
    label: str | None = None
    placement: str = "t"
    centering: bool = True
    size_cmd: str | None = "\\scriptsize"
    pre_tabular_tex: str | None = None


def _align_spec(align: str | None, ncols: int) -> str:
    if align and align.strip():
        return align.strip()
    # Default: left for first col, right for numeric-ish remaining columns.
    if ncols <= 0:
        return "l"
    return "l" + ("r" * max(0, ncols - 1))


def render_tabular_only(
    *,
    headers: Sequence[object],
    rows: Sequence[Sequence[object]],
    align: str | None = None,
    booktabs: bool = True,
    comment_lines: Iterable[str] | None = None,
) -> str:
    """Render a tabular-only block.

    - Escapes text cells by default.
    - Use RawLatex(...) for cells that should not be escaped (e.g., math).
    """

    ncols = len(headers)
    spec = _align_spec(align, ncols)
    out: list[str] = []
    for ln in (comment_lines or []):
        s = str(ln).strip("\n")
        out.append(f"% {s}" if not s.lstrip().startswith("%") else s)

    out.append(f"\\begin{{tabular}}{{{spec}}}")
    if booktabs:
        out.append("\\toprule")
    out.append(" & ".join(latex_escape_text(h) for h in headers) + " \\\\")
    if booktabs:
        out.append("\\midrule")

    for r in rows:
        if len(r) != ncols:
            raise ValueError(f"Row has {len(r)} cols, expected {ncols}")
        out.append(" & ".join(latex_escape_text(v) for v in r) + " \\\\")

    if booktabs:
        out.append("\\bottomrule")
    out.append("\\end{tabular}")
    return "\n".join(out) + "\n"


def render_table_float(*, spec: LatexTableSpec, tabular_tex: str) -> str:
    """Wrap a tabular-only block in an IEEE-friendly table float."""

    out: list[str] = []
    out.append(f"\\begin{{table}}[{spec.placement}]")
    if spec.centering:
        out.append("\\centering")
    if spec.size_cmd:
        out.append(spec.size_cmd)
    if spec.pre_tabular_tex:
        out.append(str(spec.pre_tabular_tex).rstrip("\n"))
    # IEEE style: caption before label, label after caption.
    out.append(f"\\caption{{{latex_escape_text(spec.caption)}}}")
    if spec.label:
        # Labels are identifiers, not prose; do not escape.
        out.append(f"\\label{{{str(spec.label).strip()}}}")
    out.append(tabular_tex.rstrip("\n"))
    out.append("\\end{table}")
    out.append("")
    return "\n".join(out)


__all__ = [
    "LatexTableSpec",
    "render_tabular_only",
    "render_table_float",
    "RawLatex",
]
