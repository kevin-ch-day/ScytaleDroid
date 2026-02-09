#!/usr/bin/env python3
"""Rewrite output/paper/tables/table_4_signature_deltas.tex into a compact variant.

This is presentation-only:
- Reads the already-generated CSV at output/paper/tables/table_4_signature_deltas.csv
- Writes a narrower LaTeX table to output/paper/tables/table_4_signature_deltas.tex

No analysis is rerun and no values are recomputed.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scytaledroid.Paper.table4_compactor import write_table_4_compact_tex


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--paper-root",
        default="output/paper",
        help="Paper directory root (default: output/paper).",
    )
    ap.add_argument(
        "--top-n",
        type=int,
        default=2,
        help="Top-N metrics per app to show (default: 2).",
    )
    args = ap.parse_args()

    paper_root = Path(args.paper_root)
    src_csv = paper_root / "tables" / "table_4_signature_deltas.csv"
    dst_tex = paper_root / "tables" / "table_4_signature_deltas.tex"

    if not src_csv.exists():
        raise SystemExit(f"Missing: {src_csv}")

    write_table_4_compact_tex(src_csv=src_csv, dst_tex=dst_tex, top_n_metrics_per_app=int(args.top_n))
    print(f"[OK] Wrote compact Table 4: {dst_tex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

