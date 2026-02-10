from __future__ import annotations

from pathlib import Path

from scytaledroid.Publication.table_compactor import write_table_4_compact_tex


def test_write_table_4_compact_tex(tmp_path: Path) -> None:
    src = tmp_path / "table_4_signature_deltas.csv"
    src.write_text(
        "\n".join(
            [
                "app,bytes_p50_delta,bytes_p95_delta,pps_p50_delta,pps_p95_delta,pkt_size_p50_delta,pkt_size_p95_delta",
                "AppA,1.0,100.0,0.1,0.2,5.0,6.0",
                "AppB,2.0,3.0,9.0,10.0,0.0,0.0",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    dst = tmp_path / "table_4_signature_deltas.tex"

    write_table_4_compact_tex(src_csv=src, dst_tex=dst, top_n_metrics_per_app=2)
    tex = dst.read_text(encoding="utf-8")
    assert "Table 4 (compact)" in tex
    assert "\\begin{tabular}" in tex
    assert "AppA" in tex
    assert "Bytes/s" in tex
    assert "PPS" in tex or "PktSz" in tex
