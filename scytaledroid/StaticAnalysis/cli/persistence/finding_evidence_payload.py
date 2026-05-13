"""Dedupe helpers for canonical ``static_analysis_findings`` evidence storage."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any


def findings_evidence_inline_enabled() -> bool:
    """When true, persist full ``evidence`` JSON alongside ``evidence_hash`` (transition / rollback).

    Set ``SCYTALEDROID_FINDINGS_EVIDENCE_INLINE=0`` to omit inline ``evidence`` when a payload row exists.
    """

    raw = str(os.environ.get("SCYTALEDROID_FINDINGS_EVIDENCE_INLINE", "1") or "").strip().lower()
    return raw in {"", "1", "true", "yes", "on"}


def canonical_evidence_body(evidence: Any) -> tuple[str | None, str | None]:
    """Return ``(sha256_hex, canonical_json_text)`` for dedupe payloads, or ``(None, None)`` if empty."""

    if evidence is None:
        return None, None
    if isinstance(evidence, (dict, list)):
        body = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    elif isinstance(evidence, str):
        stripped = evidence.strip()
        if not stripped:
            return None, None
        body = stripped
    else:
        body = json.dumps(evidence, sort_keys=True, default=str)
    if body in ("{}", "[]", "null", ""):
        return None, None
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return digest, body


def evidence_hash_mismatch_hint(
    evidence: Any,
    *,
    sql_hash: str | None,
    python_hash: str | None,
) -> str:
    """Best-effort label for why DB ``evidence_hash`` (e.g. MariaDB ``SHA2``) may differ from ``canonical_evidence_body``.

    Used by parity probes; not a cryptographic proof.
    """

    s_sql = str(sql_hash or "").strip().lower()
    s_py = str(python_hash or "").strip().lower()
    if not s_sql and not s_py:
        return "both_empty"
    if s_sql and s_py and s_sql == s_py:
        return "match"
    if s_sql and not s_py:
        return "sql_set_python_empty"
    if not s_sql and s_py:
        return "python_set_sql_empty"

    if isinstance(evidence, str):
        if (
            evidence != evidence.strip()
            and hashlib.sha256(evidence.encode("utf-8")).hexdigest() == s_sql
            and s_py
            and s_sql != s_py
        ):
            return "likely_whitespace_or_padding"
        if canonical_evidence_body(evidence.strip())[0] == s_sql:
            return "likely_whitespace_or_padding"
        s = evidence.strip()
        if s.startswith("{") or s.startswith("["):
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                return "likely_invalid_json_text"
            unsorted = json.dumps(parsed, sort_keys=False, separators=(",", ":"), default=str)
            if hashlib.sha256(unsorted.encode("utf-8")).hexdigest() == s_sql:
                return "likely_json_key_order_or_unsorted_serialization"
        else:
            return "likely_non_json_text"

    if isinstance(evidence, (dict, list)):
        unsorted = json.dumps(evidence, sort_keys=False, separators=(",", ":"), default=str)
        if hashlib.sha256(unsorted.encode("utf-8")).hexdigest() == s_sql:
            return "likely_json_key_order_or_unsorted_serialization"

    return "other_or_mixed"


__all__ = ["canonical_evidence_body", "evidence_hash_mismatch_hint", "findings_evidence_inline_enabled"]
