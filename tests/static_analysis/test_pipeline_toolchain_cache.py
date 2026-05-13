from __future__ import annotations

from scytaledroid.StaticAnalysis.core.pipeline import _resolve_toolchain_versions


def test_resolve_toolchain_versions_returns_independent_dicts() -> None:
    a = _resolve_toolchain_versions()
    b = _resolve_toolchain_versions()
    assert isinstance(a, dict)
    assert a == b
    assert a is not b
    a["androguard"] = "mutated"
    assert b["androguard"] != "mutated"
