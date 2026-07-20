"""Unit tests for canonical finding evidence hashing."""

from __future__ import annotations

import hashlib
import json

import pytest
from scytaledroid.StaticAnalysis.cli.persistence.finding_evidence_payload import (
    canonical_evidence_body,
    evidence_hash_mismatch_hint,
    findings_evidence_inline_enabled,
)


def test_canonical_evidence_body_stable_for_dict_key_order() -> None:
    a, _ = canonical_evidence_body({"b": 2, "a": 1})
    b, _ = canonical_evidence_body({"a": 1, "b": 2})
    assert a == b
    assert a is not None


def test_canonical_evidence_body_empty() -> None:
    assert canonical_evidence_body({}) == (None, None)
    assert canonical_evidence_body("  ") == (None, None)


def test_evidence_hash_mismatch_hint_whitespace() -> None:
    py = canonical_evidence_body("  hello  ")[0]
    raw_sql = hashlib.sha256(b"  hello  ").hexdigest()
    assert py != raw_sql
    h = evidence_hash_mismatch_hint("  hello  ", sql_hash=raw_sql, python_hash=py)
    assert h == "likely_whitespace_or_padding"


def test_evidence_hash_mismatch_hint_unsorted_dict_matches_sql_style() -> None:
    obj = {"b": 1, "a": 2}
    py = canonical_evidence_body(obj)[0]
    unsorted = json.dumps(obj, sort_keys=False, separators=(",", ":"))
    sql_like = hashlib.sha256(unsorted.encode()).hexdigest()
    assert py != sql_like
    h = evidence_hash_mismatch_hint(obj, sql_hash=sql_like, python_hash=py)
    assert h == "likely_json_key_order_or_unsorted_serialization"


def test_evidence_hash_mismatch_hint_match() -> None:
    obj = {"a": 1}
    py = canonical_evidence_body(obj)[0]
    assert evidence_hash_mismatch_hint(obj, sql_hash=py, python_hash=py) == "match"


def test_findings_evidence_inline_enabled_default_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_FINDINGS_EVIDENCE_INLINE", raising=False)
    assert findings_evidence_inline_enabled() is True
