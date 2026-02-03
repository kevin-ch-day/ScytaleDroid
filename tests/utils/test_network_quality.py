from scytaledroid.Utils.network_quality import evaluate_network_signal_quality


def test_network_quality_netstats_ok():
    result = evaluate_network_signal_quality(
        netstats_rows=5,
        netstats_missing_rows=0,
        sum_bytes_in=10,
        sum_bytes_out=20,
    )
    assert result == "netstats_ok"


def test_network_quality_zero_bytes():
    result = evaluate_network_signal_quality(
        netstats_rows=3,
        netstats_missing_rows=0,
        sum_bytes_in=0,
        sum_bytes_out=0,
    )
    assert result == "netstats_zero_bytes"


def test_network_quality_missing():
    result = evaluate_network_signal_quality(
        netstats_rows=0,
        netstats_missing_rows=3,
        sum_bytes_in=None,
        sum_bytes_out=None,
    )
    assert result == "netstats_missing"


def test_network_quality_pcap_only():
    result = evaluate_network_signal_quality(
        netstats_rows=0,
        netstats_missing_rows=0,
        sum_bytes_in=None,
        sum_bytes_out=None,
        pcap_present=True,
    )
    assert result == "pcap_only"
