from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.pcap.transport_health import _EVENT_FIELDS
from scytaledroid.DynamicAnalysis.pcap.transport_health import summarize_transport_health


def test_summarize_transport_health_counts_events_and_top_streams(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    pcap_path.write_bytes(b"pcap")
    row_len = 1 + len(_EVENT_FIELDS) + 1
    rows = [["" for _ in range(row_len)] for _ in range(4)]
    rows[0][0] = "7"
    rows[0][1] = "1"
    rows[0][-1] = "1"
    rows[1][0] = "7"
    rows[1][2] = "1"
    rows[2][0] = "9"
    rows[2][5] = "1"
    rows[3][0] = "9"
    rows[3][7] = "1"

    class _Result:
        returncode = 0
        stderr = ""
        stdout = "\n".join("\t".join(row) for row in rows) + "\n"

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.pcap.transport_health.subprocess.run",
        lambda *args, **kwargs: _Result(),
    )

    summary = summarize_transport_health(pcap_path, tshark_path="tshark")
    assert summary["tcp_packet_count"] == 4
    assert summary["issue_packet_count"] == 4
    assert summary["reset_packet_count"] == 1
    assert summary["event_counts"]["retransmission"] == 1
    assert summary["event_counts"]["fast_retransmission"] == 1
    assert summary["event_counts"]["duplicate_ack"] == 1
    assert summary["event_counts"]["zero_window"] == 1
    assert summary["affected_stream_count"] == 2
    assert summary["top_streams"][0]["tcp_stream"] == "7"
