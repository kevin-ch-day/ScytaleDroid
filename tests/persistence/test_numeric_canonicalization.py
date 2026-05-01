from __future__ import annotations

import pytest

from scytaledroid.StaticAnalysis.cli.persistence.utils import canonical_decimal_text


def test_canonical_decimal_text_rounds_half_up():
    assert canonical_decimal_text("2.34567", field="x", scale=3) == "2.346"
    assert canonical_decimal_text("2.3454", field="x", scale=3) == "2.345"


def test_canonical_decimal_text_rejects_non_finite():
    with pytest.raises(ValueError, match="finite"):
        canonical_decimal_text(float("nan"), field="x", scale=3)


def test_canonical_decimal_text_enforces_bounds():
    with pytest.raises(ValueError, match="above maximum"):
        canonical_decimal_text("10.001", field="x", scale=3, min_value=0.0, max_value=10.0)
