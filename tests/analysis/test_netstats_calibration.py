from scytaledroid.DynamicAnalysis.analysis.netstats_calibration import calibrate_netstats


def test_netstats_calibration_invalid():
    result = calibrate_netstats(pcap_bins=[100, 100], netstats_bins=[0, 0])
    assert result.status == "invalid"
