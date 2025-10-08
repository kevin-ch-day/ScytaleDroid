"""Pattern matching helpers for indexed APK strings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Mapping, MutableMapping, Sequence, Tuple
from typing import Literal

from .extractor import IndexedString, StringIndex
from .patterns import DEFAULT_PATTERNS, StringPattern


class MatchStatus(str, Enum):
    """Enumeration describing how a match should be treated."""

    ACCEPTED = "accepted"
    FILTERED = "filtered"


FilterOutcome = Literal["accept", "filter", "reject"]
FilterResult = Tuple[FilterOutcome, Tuple[str, ...]]
FilterFunc = Callable[["MatchRecord"], FilterResult]


@dataclass(frozen=True)
class MatchRecord:
    """Represents a raw pattern hit against an indexed string."""

    pattern: StringPattern
    string_entry: IndexedString
    fragment: str


@dataclass(frozen=True)
class EvaluatedMatch:
    """A match after filters have been applied."""

    record: MatchRecord
    status: MatchStatus
    reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class MatchGroup:
    """Bundle of matches for the same pattern."""

    pattern: StringPattern
    accepted: Tuple[EvaluatedMatch, ...]
    filtered: Tuple[EvaluatedMatch, ...]
    accepted_count: int = field(init=False)
    filtered_count: int = field(init=False)

    def __post_init__(self) -> None:  # pragma: no cover - simple counters
        object.__setattr__(self, "accepted_count", len(self.accepted))
        object.__setattr__(self, "filtered_count", len(self.filtered))

    @property
    def total(self) -> int:
        return self.accepted_count + self.filtered_count


@dataclass(frozen=True)
class MatchBatch:
    """Aggregate result produced by :class:`StringMatcher`."""

    evaluated: Tuple[EvaluatedMatch, ...]
    groups: Mapping[str, MatchGroup]
    accepted_total: int = field(init=False)
    filtered_total: int = field(init=False)

    def __post_init__(self) -> None:  # pragma: no cover - simple counters
        accepted = 0
        filtered = 0
        for match in self.evaluated:
            if match.status is MatchStatus.ACCEPTED:
                accepted += 1
            else:
                filtered += 1
        object.__setattr__(self, "accepted_total", accepted)
        object.__setattr__(self, "filtered_total", filtered)

    @property
    def matched_total(self) -> int:
        return len(self.evaluated)


class StringMatcher:
    """Coordinator that applies patterns and filters to a string index."""

    def __init__(
        self,
        index: StringIndex,
        *,
        patterns: Sequence[StringPattern] | None = None,
        filters: Sequence[FilterFunc] | None = None,
    ) -> None:
        self._index = index
        self._patterns = tuple(patterns or DEFAULT_PATTERNS)
        self._filters = tuple(filters or ())

    def match(self) -> MatchBatch:
        evaluated = self._evaluate_matches()
        groups = _group_by_pattern(evaluated)
        return MatchBatch(evaluated=evaluated, groups=groups)

    def _evaluate_matches(self) -> Tuple[EvaluatedMatch, ...]:
        seen: set[tuple[str, str, str]] = set()
        evaluated: list[EvaluatedMatch] = []

        for record in self._iter_records():
            key = (record.pattern.name, record.string_entry.sha256, record.fragment)
            if key in seen:
                continue
            seen.add(key)

            status = MatchStatus.ACCEPTED
            reasons: list[str] = []
            rejected = False

            for filter_fn in self._filters:
                outcome, details = filter_fn(record)
                if details:
                    reasons.extend(details)
                if outcome == "reject":
                    rejected = True
                    break
                if outcome == "filter":
                    status = MatchStatus.FILTERED

            if rejected:
                continue

            evaluated.append(
                EvaluatedMatch(record=record, status=status, reasons=tuple(reasons))
            )

        return tuple(evaluated)

    def _iter_records(self) -> Iterable[MatchRecord]:
        for pattern in self._patterns:
            candidates = self._index.search(
                pattern.pattern,
                origin_types=pattern.preferred_origins,
                min_length=pattern.min_length,
            )
            for entry in candidates:
                if pattern.context_keywords:
                    haystack = f"{entry.origin}:{entry.value}".lower()
                    if not any(keyword in haystack for keyword in pattern.context_keywords):
                        continue
                for fragment in pattern.iter_matches(entry.value):
                    if not _is_fragment_valid(pattern.name, fragment):
                        continue
                    yield MatchRecord(
                        pattern=pattern,
                        string_entry=entry,
                        fragment=fragment,
                    )


def _group_by_pattern(matches: Sequence[EvaluatedMatch]) -> Mapping[str, MatchGroup]:
    grouped: MutableMapping[str, dict[str, object]] = {}
    for match in matches:
        pattern = match.record.pattern
        bucket = grouped.setdefault(
            pattern.name,
            {"pattern": pattern, "accepted": [], "filtered": []},
        )
        key = "accepted" if match.status is MatchStatus.ACCEPTED else "filtered"
        bucket[key].append(match)

    return {
        name: MatchGroup(
            pattern=data["pattern"],
            accepted=tuple(data["accepted"]),
            filtered=tuple(data["filtered"]),
        )
        for name, data in grouped.items()
    }


def _is_fragment_valid(pattern_name: str, fragment: str) -> bool:
    if pattern_name == "aws_secret_access_key":
        upper = sum(1 for char in fragment if char.isupper())
        lower = sum(1 for char in fragment if char.islower())
        digits = sum(1 for char in fragment if char.isdigit())
        if upper < 4 or lower < 4 or digits < 4:
            return False
    if pattern_name == "generic_bearer":
        if len(fragment.split()) <= 1:
            return False
    if pattern_name == "google_oauth_client":
        if "{" in fragment or "}" in fragment:
            return False
    if pattern_name == "slack_token" and "your" in fragment.lower():
        return False
    if pattern_name == "private_key_block":
        if "PRIVATE KEY" not in fragment:
            return False
    return True


_TEST_HINTS: tuple[str, ...] = (
    "test",
    "dummy",
    "sample",
    "example",
    "fake",
    "demo",
    "staging",
    "sandbox",
    "placeholder",
    "replace",
    "your",
    "localhost",
    "127.0.0.1",
    "10.0.2.2",
)


def _test_like_filter(record: MatchRecord) -> FilterResult:
    fragment = record.fragment
    entry = record.string_entry
    lowered = fragment.lower()

    if any(token in lowered for token in _TEST_HINTS):
        return "filter", ("test_hint",)
    if fragment.startswith("sk_test_"):
        return "filter", ("stripe_test_key",)
    if lowered.startswith("sq0dev-") or lowered.startswith("sq0csp-"):
        return "filter", ("square_test_key",)
    if lowered.startswith(("xox",)) and "your" in lowered:
        return "filter", ("slack_placeholder",)
    if lowered.startswith(("ghp_", "gho_", "ghs_", "ghu_")) and "your" in lowered:
        return "filter", ("github_placeholder",)

    composite = f"{entry.origin}:{entry.value}".lower()
    if any(host in composite for host in ("example.com", "localhost", "127.0.0.1", "10.0.2.2")):
        return "filter", ("loopback_reference",)

    return "accept", ()


def _pattern_guard_filter(record: MatchRecord) -> FilterResult:
    if _is_fragment_valid(record.pattern.name, record.fragment):
        return "accept", ()
    return "reject", ("invalid_format",)


DEFAULT_SECRET_FILTERS: tuple[FilterFunc, ...] = (
    _pattern_guard_filter,
    _test_like_filter,
)


__all__ = [
    "DEFAULT_SECRET_FILTERS",
    "EvaluatedMatch",
    "MatchBatch",
    "MatchGroup",
    "MatchRecord",
    "MatchStatus",
    "StringMatcher",
]

