"""TLS fingerprint summaries for saved PCAPs.

This module stays within the existing metadata-only contract:
- tshark field extraction only
- no payload/body inspection
- deterministic top-N summaries suitable for report/features/DB indexing
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def summarize_tls_fingerprints(
    pcap_path: Path,
    *,
    tshark_path: str | None = None,
    top_n: int = 5,
) -> dict[str, Any]:
    tp = tshark_path or shutil.which("tshark")
    if not tp:
        raise RuntimeError("tshark_missing")
    if not pcap_path.exists():
        raise RuntimeError("pcap_missing")

    client = _run_handshake_rows(
        tp,
        pcap_path,
        display_filter="tls.handshake.type == 1",
        fields=(
            "tls.handshake.ja3",
            "tls.handshake.ja4",
            "tls.handshake.extensions_alpn_str",
            "tls.handshake.extensions_server_name",
        ),
    )
    server = _run_handshake_rows(
        tp,
        pcap_path,
        display_filter="tls.handshake.type == 2",
        fields=("tls.handshake.ja3s", "tls.handshake.extensions_alpn_str"),
    )

    ja3_counts: dict[str, int] = {}
    ja4_counts: dict[str, int] = {}
    ja3s_counts: dict[str, int] = {}
    alpn_counts: dict[str, int] = {}
    sni_counts: dict[str, int] = {}

    client_hello_count = 0
    server_hello_count = 0

    for row in client:
        client_hello_count += 1
        ja3 = _clean(row[0] if len(row) > 0 else "")
        ja4 = _clean(row[1] if len(row) > 1 else "")
        alpn = _clean(row[2] if len(row) > 2 else "")
        sni = _clean(row[3] if len(row) > 3 else "")
        _bump(ja3_counts, ja3)
        _bump(ja4_counts, ja4)
        _bump(alpn_counts, alpn)
        _bump(sni_counts, sni)

    for row in server:
        server_hello_count += 1
        ja3s = _clean(row[0] if len(row) > 0 else "")
        alpn = _clean(row[1] if len(row) > 1 else "")
        _bump(ja3s_counts, ja3s)
        _bump(alpn_counts, alpn)

    return {
        "status": "ok",
        "client_hello_count": int(client_hello_count),
        "server_hello_count": int(server_hello_count),
        "unique_ja3_count": int(len(ja3_counts)),
        "unique_ja4_count": int(len(ja4_counts)),
        "unique_ja3s_count": int(len(ja3s_counts)),
        "unique_alpn_count": int(len(alpn_counts)),
        "unique_sni_from_client_hello_count": int(len(sni_counts)),
        "top_ja3": _top_items(ja3_counts, top_n),
        "top_ja4": _top_items(ja4_counts, top_n),
        "top_ja3s": _top_items(ja3s_counts, top_n),
        "top_alpn": _top_items(alpn_counts, top_n),
        "top_sni_from_client_hello": _top_items(sni_counts, top_n),
        "top1_ja3_share": _top1_share(ja3_counts),
        "top1_ja4_share": _top1_share(ja4_counts),
        "top1_ja3s_share": _top1_share(ja3s_counts),
        "top1_alpn_share": _top1_share(alpn_counts),
    }


def _run_handshake_rows(
    tshark_path: str,
    pcap_path: Path,
    *,
    display_filter: str,
    fields: tuple[str, ...],
) -> list[list[str]]:
    cmd = [
        tshark_path,
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
    ]
    for field in fields:
        cmd.extend(["-e", field])
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "tshark_tls_fingerprints_failed")
    rows: list[list[str]] = []
    for line in (completed.stdout or "").splitlines():
        rows.append(line.rstrip("\n").split("\t"))
    return rows


def _clean(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _bump(counts: dict[str, int], value: str | None) -> None:
    if not value:
        return
    counts[value] = counts.get(value, 0) + 1


def _top_items(counts: dict[str, int], top_n: int) -> list[dict[str, object]]:
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)[: max(top_n, 1)]
    return [{"value": value, "count": count} for value, count in ranked]


def _top1_share(counts: dict[str, int]) -> float | None:
    if not counts:
        return None
    total = sum(counts.values())
    if total <= 0:
        return None
    top1 = max(counts.values())
    return float(top1) / float(total)


__all__ = ["summarize_tls_fingerprints"]
