from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.fingerprints import summarize_tls_fingerprints


def test_summarize_tls_fingerprints_counts_client_server_and_top_shares(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")

    outputs = iter(
        [
            "ja3a\tja4a\th2\tapi.example.com\nja3a\tja4a\th2\tapi.example.com\nja3b\tja4b\th3\tcdn.example.com\n",
            "ja3sa\th2\nja3sb\th3\n",
        ]
    )

    class _Result:
        def __init__(self, stdout: str) -> None:
            self.returncode = 0
            self.stderr = ""
            self.stdout = stdout

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.fingerprints.subprocess.run",
        lambda *args, **kwargs: _Result(next(outputs)),
    )

    summary = summarize_tls_fingerprints(pcap_path, tshark_path="tshark", top_n=5)

    assert summary["client_hello_count"] == 3
    assert summary["server_hello_count"] == 2
    assert summary["unique_ja3_count"] == 2
    assert summary["unique_ja4_count"] == 2
    assert summary["unique_ja3s_count"] == 2
    assert summary["unique_alpn_count"] == 2
    assert summary["unique_sni_from_client_hello_count"] == 2
    assert summary["top_ja3"][0]["value"] == "ja3a"
    assert summary["top_ja3"][0]["count"] == 2
    assert summary["top1_ja3_share"] == 2.0 / 3.0
    assert summary["top1_ja4_share"] == 2.0 / 3.0
    assert summary["top1_ja3s_share"] == 0.5
