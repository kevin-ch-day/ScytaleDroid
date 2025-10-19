from __future__ import annotations

import pytest

from scytaledroid.StaticAnalysis.cli.renderer import _normalise_string_data


def test_http_cleartext_zero_counts_reset():
    raw = {
        "counts": {"http_cleartext": 0},
        "structured": {
            "buckets": {
                "http_cleartext": {"total": 0, "unique_values": 2}
            }
        },
    }
    result = _normalise_string_data(raw)
    assert result["counts"]["http_cleartext"] == 0
    http_struct = result["structured"]["buckets"]["http_cleartext"]
    assert http_struct["unique_values"] == 0


def test_http_cleartext_counts_match_unique():
    raw = {
        "counts": {"http_cleartext": 3},
        "structured": {
            "buckets": {
                "http_cleartext": {"total": 3, "unique_values": 2}
            }
        },
    }
    result = _normalise_string_data(raw)
    http_struct = result["structured"]["buckets"]["http_cleartext"]
    assert http_struct["total"] == 3
    assert http_struct["unique_values"] == 2


def test_http_cleartext_invalid_combo_raises():
    raw = {
        "counts": {"http_cleartext": 1},
        "structured": {
            "buckets": {
                "http_cleartext": {"total": 1, "unique_values": 5}
            }
        },
    }
    with pytest.raises(AssertionError):
        _normalise_string_data(raw)
