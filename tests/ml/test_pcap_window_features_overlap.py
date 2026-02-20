from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml.pcap_window_features import PacketRecord, build_window_features
from scytaledroid.DynamicAnalysis.ml.telemetry_windowing import WindowSpec


def test_build_window_features_assigns_packets_to_overlapping_windows() -> None:
    spec = WindowSpec(window_size_s=10.0, stride_s=5.0)
    packets = [
        PacketRecord(t=3.0, length=100),
        PacketRecord(t=7.0, length=200),
        PacketRecord(t=12.0, length=300),
    ]
    rows, dropped = build_window_features(packets, duration_s=20.0, spec=spec)

    assert dropped == 1
    assert len(rows) == 3
    # windows: [0,10), [5,15), [10,20)
    assert [r["packet_count"] for r in rows] == [2, 2, 1]
    assert [r["byte_count"] for r in rows] == [300, 500, 300]


def test_build_window_features_boundary_and_non_monotonic_packets() -> None:
    spec = WindowSpec(window_size_s=10.0, stride_s=5.0)
    packets = [
        PacketRecord(t=12.0, length=300),
        PacketRecord(t=10.0, length=100),  # boundary point
        PacketRecord(t=7.0, length=200),
    ]
    rows, _ = build_window_features(packets, duration_s=20.0, spec=spec)

    # t=10 contributes to [5,15) and [10,20), not [0,10)
    # t=7 contributes to [0,10) and [5,15)
    # t=12 contributes to [5,15) and [10,20)
    assert [r["packet_count"] for r in rows] == [1, 3, 2]
    assert [r["byte_count"] for r in rows] == [200, 600, 400]
