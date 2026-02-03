from pathlib import Path

from scytaledroid.Utils.netstats_parser import NetstatsParser


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def test_netstats_parser_detail_android15_fixture():
    payload = (FIXTURES_DIR / "netstats_android15_detail.txt").read_text()
    parser = NetstatsParser()
    sample = parser.parse_detail(payload, "10234")
    assert sample.rx_bytes == 1500
    assert sample.tx_bytes == 3000
    assert sample.parse_method == "detail_uid"


def test_netstats_parser_detail_section_android15_fixture():
    payload = (FIXTURES_DIR / "netstats_android15_detail_sections.txt").read_text()
    parser = NetstatsParser()
    sample = parser.parse_detail(payload, "10234")
    assert sample.rx_bytes == 1500
    assert sample.tx_bytes == 3000
    assert sample.parse_method == "detail_uid"


def test_netstats_parser_uid_android15_fixture():
    payload = (FIXTURES_DIR / "netstats_android15_uid.txt").read_text()
    parser = NetstatsParser()
    sample = parser.parse_uid(payload, "10234")
    assert sample.rx_bytes == 1000
    assert sample.tx_bytes == 1300
    assert sample.parse_method == "uid_uid"


def test_netstats_parser_uid_table_android15_fixture():
    payload = (FIXTURES_DIR / "netstats_android15_uid_table.txt").read_text()
    parser = NetstatsParser()
    sample = parser.parse_uid(payload, "10454")
    assert sample.rx_bytes == 863299312
    assert sample.tx_bytes == 21213135
    assert sample.parse_method == "uid_table"
