from __future__ import annotations

import re

from scytaledroid.StaticAnalysis.modules.string_analysis.matcher import StringMatcher
from scytaledroid.StaticAnalysis.modules.string_analysis.patterns.base import StringPattern
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.models import IndexedString


class _IndexWithoutSearch:
    def __init__(self, strings):
        self.strings = tuple(strings)


def test_string_matcher_uses_string_entries_without_index_search() -> None:
    index = _IndexWithoutSearch(
        [
            IndexedString(
                value="AIza0123456789abcdefghijklmnopqrstuvwxy",
                origin="classes.dex",
                origin_type="code",
            )
        ]
    )
    pattern = StringPattern(
        name="google_api_key",
        description="Potential Google API key",
        pattern=re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
        preferred_origins=("code",),
        required_substrings=("aiza",),
    )

    batch = StringMatcher(index, patterns=(pattern,)).match()

    assert batch.accepted_total == 1
    assert batch.groups["google_api_key"].accepted_count == 1
    assert batch.groups["google_api_key"].candidate_count == 1
    assert batch.groups["google_api_key"].raw_match_count == 1


def test_string_matcher_respects_preferred_origins_without_regexing_other_entries() -> None:
    index = _IndexWithoutSearch(
        [
            IndexedString(
                value="AIza0123456789abcdefghijklmnopqrstuvwxy",
                origin="assets/config.json",
                origin_type="asset",
            ),
            IndexedString(
                value="AIza0123456789abcdefghijklmnopqrstuvwxy",
                origin="classes.dex",
                origin_type="code",
            ),
        ]
    )
    pattern = StringPattern(
        name="code_only_google_api_key",
        description="Potential Google API key in code",
        pattern=re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
        preferred_origins=("code",),
        required_substrings=("aiza",),
    )

    batch = StringMatcher(index, patterns=(pattern,)).match()

    accepted = batch.groups["code_only_google_api_key"].accepted
    assert len(accepted) == 1
    assert accepted[0].record.string_entry.origin == "classes.dex"
    assert batch.groups["code_only_google_api_key"].candidate_count == 1
    assert batch.groups["code_only_google_api_key"].raw_match_count == 1


def test_string_matcher_context_keywords_consider_entry_context() -> None:
    index = _IndexWithoutSearch(
        [
            IndexedString(
                value="A12345678901234567890-ABCDEFGHIJKLMNO12345",
                origin="classes.dex",
                origin_type="code",
                context="paypal checkout client id",
            ),
            IndexedString(
                value="A12345678901234567890-ABCDEFGHIJKLMNO12345",
                origin="classes.dex",
                origin_type="code",
                context="generic analytics token",
            ),
        ]
    )
    pattern = StringPattern(
        name="paypal_client_id",
        description="Potential PayPal client ID",
        pattern=re.compile(r"A[A-Za-z0-9]{20,64}-[A-Za-z0-9_-]{10,64}"),
        preferred_origins=("code",),
        context_keywords=("paypal",),
    )

    batch = StringMatcher(index, patterns=(pattern,)).match()

    accepted = batch.groups["paypal_client_id"].accepted
    assert len(accepted) == 1
    assert accepted[0].record.string_entry.context == "paypal checkout client id"
    assert batch.groups["paypal_client_id"].candidate_count == 1
    assert batch.groups["paypal_client_id"].raw_match_count == 1


def test_string_matcher_context_keywords_prune_broad_provider_candidates() -> None:
    index = _IndexWithoutSearch(
        [
            IndexedString(
                value="DD1234567890ABCDEF1234567890ABCDEF",
                origin="classes.dex",
                origin_type="code",
                context="generic buffer",
            ),
            IndexedString(
                value="DD1234567890ABCDEF1234567890ABCDEF",
                origin="classes.dex",
                origin_type="code",
                context="datadog upload api key",
            ),
        ]
    )
    pattern = StringPattern(
        name="datadog_api_key",
        description="Potential Datadog API key",
        pattern=re.compile(r"DD[a-zA-Z0-9]{32}"),
        preferred_origins=("code",),
        context_keywords=("datadog", "dd-sdk", "dd_sdk"),
    )

    batch = StringMatcher(index, patterns=(pattern,)).match()

    accepted = batch.groups["datadog_api_key"].accepted
    assert len(accepted) == 1
    assert accepted[0].record.string_entry.context == "datadog upload api key"
    assert batch.groups["datadog_api_key"].candidate_count == 1
    assert batch.groups["datadog_api_key"].raw_match_count == 1


def test_string_matcher_keeps_pattern_scan_stats_even_when_regex_does_not_match() -> None:
    index = _IndexWithoutSearch(
        [
            IndexedString(
                value="datadog instrumentation marker without full key",
                origin="classes.dex",
                origin_type="code",
                context="datadog upload api key",
            ),
        ]
    )
    pattern = StringPattern(
        name="datadog_api_key",
        description="Potential Datadog API key",
        pattern=re.compile(r"DD[a-zA-Z0-9]{32}"),
        preferred_origins=("code",),
        context_keywords=("datadog", "dd-sdk", "dd_sdk"),
    )

    batch = StringMatcher(index, patterns=(pattern,)).match()

    assert "datadog_api_key" not in batch.groups
    assert batch.pattern_scan_stats["datadog_api_key"].candidate_count == 1
    assert batch.pattern_scan_stats["datadog_api_key"].raw_match_count == 0


def test_required_substrings_short_circuit_non_matching_values() -> None:
    pattern = StringPattern(
        name="google_api_key",
        description="Potential Google API key",
        pattern=re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
        required_substrings=("aiza",),
    )

    assert pattern.iter_matches("no credential here at all") == ()
    assert pattern.iter_matches("AIza0123456789abcdefghijklmnopqrstuvwxy")
