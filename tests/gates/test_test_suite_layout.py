from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = [pytest.mark.contract, pytest.mark.gate]


def test_tests_root_has_no_stray_test_modules() -> None:
    root = Path("tests")
    stray = sorted(
        path.name
        for path in root.glob("test_*.py")
        if path.name != "conftest.py"
    )
    assert stray == [], (
        "top-level tests/ should stay reserved for conftest/fixtures only; "
        f"move stray modules into a domain folder: {', '.join(stray)}"
    )


def test_in_package_tests_are_limited_to_approved_roots() -> None:
    approved = {
        Path("scytaledroid/StaticAnalysis/modules/string_analysis/tests"),
    }
    discovered = {
        path.parent
        for path in Path("scytaledroid").rglob("test_*.py")
        if "tests" in path.parts
    }
    assert discovered == approved, (
        "in-package tests should stay deliberate and rare; "
        f"approved={sorted(str(path) for path in approved)} "
        f"discovered={sorted(str(path) for path in discovered)}"
    )


def test_retired_test_buckets_have_no_active_modules() -> None:
    retired = [
        Path("tests/static"),
        Path("tests/db_utils"),
        Path("tests/db"),
        Path("tests/profile_tools"),
        Path("tests/logging"),
        Path("tests/diagnostics"),
    ]
    active = {
        str(path): sorted(child.name for child in path.glob("test_*.py"))
        for path in retired
        if path.exists() and any(path.glob("test_*.py"))
    }
    assert active == {}, f"retired test buckets should stay empty: {active}"
