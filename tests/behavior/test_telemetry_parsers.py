import time

from scytaledroid.BehaviorAnalysis import telemetry as t


TOP_FIXTURE = """\
PID CPU RES NAME
12345 5% 10M com.android.chrome
23456 1% 8M com.other.app
"""

MEMINFO_FIXTURE = """\
Applications Memory Usage (in Kilobytes):
TOTAL 12345
"""

NETSTATS_FIXTURE = """\
iface=wlan0 uid=1234 set=DEFAULT tag=0x0 rxBytes=111 txBytes=222
iface=wlan0 uid=5555 set=DEFAULT tag=0x0 rxBytes=10 txBytes=20
"""

PROC_NET_DEV_FIXTURE = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0
"""


def test_parse_top_output_parses_cpu_and_mem():
    parsed = t.parse_top_output(TOP_FIXTURE, "12345")
    assert parsed["cpu_pct"] == 5.0
    assert parsed["rss_kb"] == 10240
    assert parsed["proc_name"] == "com.android.chrome"


def test_parse_meminfo_total_extracts_total():
    assert t.parse_meminfo_total(MEMINFO_FIXTURE) == 12345


def test_parse_netstats_and_proc_net_dev():
    bytes_in, bytes_out = t.parse_netstats_detail(NETSTATS_FIXTURE, "1234")
    assert bytes_in == 111
    assert bytes_out == 222
    fb_in, fb_out = t.parse_proc_net_dev(PROC_NET_DEV_FIXTURE)
    assert fb_in == 100
    assert fb_out == 200


def test_should_mark_missed_sample_respects_jitter_multiplier():
    start = time.time()
    assert t.should_mark_missed_sample(start, 2.0) is False
    early = start - (2.0 * t.JITTER_MULTIPLIER + 0.1)
    assert t.should_mark_missed_sample(early, 2.0) is True
