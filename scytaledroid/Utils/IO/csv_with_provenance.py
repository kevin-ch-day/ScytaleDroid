"""CSV with provenance comment headers.

Many ScytaleDroid exports are "CSV + provenance" where metadata is emitted as comment
lines before the real header row:

  # key: value
  # other_key: other_value
  #
  col1,col2,...

This module is the single canonical reader/writer for that format. Do not reimplement
"skip # lines" logic in ad-hoc scripts.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class ProvenanceCsv:
    provenance: dict[str, str]
    rows: list[dict[str, str]]


def _split_comment_header(lines: list[str]) -> tuple[list[str], list[str]]:
    """Split lines into (comment_header_lines, data_lines)."""
    comment: list[str] = []
    data: list[str] = []
    in_comment = True
    for ln in lines:
        if in_comment and ln.lstrip().startswith("#"):
            comment.append(ln)
            continue
        in_comment = False
        data.append(ln)
    return comment, data


def parse_provenance_comment_lines(comment_lines: Iterable[str]) -> dict[str, str]:
    prov: dict[str, str] = {}
    for ln in comment_lines:
        s = ln.strip()
        if not s.startswith("#"):
            continue
        s = s[1:].strip()
        if not s:
            continue
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            prov[k] = v
    return prov


def read_csv_with_provenance(path: Path) -> ProvenanceCsv:
    """Read a provenance CSV and return (provenance, rows)."""
    text = path.read_text(encoding="utf-8", errors="strict").splitlines()
    comment, data = _split_comment_header(text)
    prov = parse_provenance_comment_lines(comment)
    # Drop blank/comment-only lines from data.
    data_lines: list[str] = []
    for ln in data:
        if not ln.strip():
            continue
        if ln.lstrip().startswith("#"):
            continue
        data_lines.append(ln)
    if not data_lines:
        return ProvenanceCsv(provenance=prov, rows=[])
    r = csv.DictReader(data_lines)
    return ProvenanceCsv(provenance=prov, rows=[dict(row) for row in r])


def write_csv_with_provenance(
    path: Path,
    *,
    provenance: dict[str, Any],
    fieldnames: list[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    """Write provenance header + CSV body deterministically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        for k in sorted(provenance.keys()):
            v = provenance.get(k)
            f.write(f"# {k}: {v}\n")
        f.write("#\n")
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})


__all__ = [
    "ProvenanceCsv",
    "parse_provenance_comment_lines",
    "read_csv_with_provenance",
    "write_csv_with_provenance",
]

