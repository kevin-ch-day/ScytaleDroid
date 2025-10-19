"""Tests for the string matcher sampler and filters."""

from __future__ import annotations

import re

from scytaledroid.StaticAnalysis.modules.string_analysis.indexing import (
    IndexedString,
    StringIndex,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.matcher import (
    DEFAULT_SECRET_FILTERS,
    MatchStatus,
    StringMatcher,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.patterns.base import StringPattern


def _index(*values: IndexedString) -> StringIndex:
    return StringIndex(strings=values)


def test_matcher_enforces_origin_scope_and_hit_limits() -> None:
    pattern = StringPattern(
        name="stripe_secret",
        description="Stripe keys",
        pattern=re.compile(r"(sk_(?:live|test)_[0-9A-Za-z]{16,})"),
    )
    dex_primary = IndexedString(
        value="sk_live_1234567890ABCDEF",
        origin="classes.dex",
        origin_type="dex",
    )
    dex_secondary = IndexedString(
        value="sk_live_ABCDEFGHIJ1234567890",
        origin="classes2.dex",
        origin_type="dex",
    )
    res_entry = IndexedString(
        value="sk_live_ZYXW9876543210AB",
        origin="res/values/strings.xml",
        origin_type="res",
    )

    matcher = StringMatcher(
        _index(dex_primary, dex_secondary, res_entry),
        patterns=(pattern,),
    )

    batch = matcher.match(
        allowed_origin_types={"dex"},
        max_hits_per_pattern=1,
    )

    group = batch.groups["stripe_secret"]
    assert group.accepted_count == 1
    assert group.filtered_count == 2

    filtered_reasons = {reason for match in group.filtered for reason in match.reasons}
    assert "origin_scope" in filtered_reasons
    assert "hits_limit" in filtered_reasons


def test_matcher_filters_low_entropy_samples() -> None:
    pattern = StringPattern(
        name="token",
        description="Low entropy token",
        pattern=re.compile(r"([A-Za-z0-9]+)"),
    )
    entry = IndexedString(
        value="AAAAAA111111",
        origin="classes.dex",
        origin_type="dex",
    )

    matcher = StringMatcher(_index(entry), patterns=(pattern,))
    batch = matcher.match(min_entropy=3.5)

    assert batch.accepted_total == 0
    assert batch.filtered_total == 1
    filtered = batch.groups["token"].filtered[0]
    assert filtered.status is MatchStatus.FILTERED
    assert "entropy_below_threshold" in filtered.reasons


def test_matcher_secret_filters_flag_placeholders() -> None:
    pattern = StringPattern(
        name="stripe_secret",
        description="Stripe keys",
        pattern=re.compile(r"(sk_(?:live|test)_[0-9A-Za-z_]{8,})"),
    )
    entry = IndexedString(
        value="sk_test_your_placeholder_value",
        origin="assets/creds.json",
        origin_type="asset",
    )

    matcher = StringMatcher(
        _index(entry),
        patterns=(pattern,),
        filters=DEFAULT_SECRET_FILTERS,
    )

    batch = matcher.match()
    assert batch.accepted_total == 0
    assert batch.filtered_total == 1
    filtered = batch.groups["stripe_secret"].filtered[0]
    assert filtered.status is MatchStatus.FILTERED
    assert any(
        reason in filtered.reasons for reason in {"test_hint", "stripe_test_key"}
    )
