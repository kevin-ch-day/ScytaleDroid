from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution import results


def test_hash_prefix_short_value():
    assert results._hash_prefix("abcd") == "abcd"


def test_hash_prefix_long_value():
    assert results._hash_prefix("0123456789abcdef") == "0123…cdef"


def test_group_diagnostic_warnings_dedupes():
    warnings = [
        ("Linkage", "pkg.alpha", "UNAVAILABLE: no run_map; no db link"),
        ("Linkage", "pkg.beta", "UNAVAILABLE: no run_map; no db link"),
        ("Identity", "pkg.alpha", "missing split"),
        ("Identity", "pkg.alpha", "missing split"),
    ]
    lines = results._group_diagnostic_warnings(warnings, max_packages=3)
    assert any("Linkage UNAVAILABLE: no run_map; no db link" in line for line in lines)
    assert any("Identity missing split" in line for line in lines)
