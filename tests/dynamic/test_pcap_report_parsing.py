from scytaledroid.DynamicAnalysis.pcap.report import _parse_protocol_hierarchy_output


def test_parse_protocol_hierarchy_output_extracts_rows() -> None:
    sample = """
===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:21037 bytes:61280633
  raw                                    frames:21037 bytes:61280633
    ip                                   frames:21037 bytes:61280633
      udp                                frames:8091 bytes:8112162
        dns                              frames:240 bytes:39665
        quic                             frames:7808 bytes:8038976
      tcp                                frames:12946 bytes:53168471
        tls                              frames:5416 bytes:41447181
===================================================================
""".strip()
    rows = _parse_protocol_hierarchy_output(sample)
    assert rows
    assert any(r.get("protocol") == "udp" for r in rows)
    assert any(r.get("protocol") == "tcp" for r in rows)
    assert any(r.get("protocol") == "tls" for r in rows)

