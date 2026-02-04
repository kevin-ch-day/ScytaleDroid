from __future__ import annotations

import re
from collections.abc import Iterable

__all__ = ["derive_rule_id"]


_RULE_REGEXES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"usesCleartextTraffic\s*=\s*true", re.IGNORECASE), "BASE-CLR-001"),
    (re.compile(r"\bcleartext\b", re.IGNORECASE), "BASE-CLR-001"),
    (re.compile(r"requestLegacyExternalStorage\s*=\s*true", re.IGNORECASE), "BASE-STO-LEGACY"),
    (
        re.compile(r"\b(Activity|Service|Receiver|Activity Alias|Provider)\b.*exported.*relies on.*\bpermission", re.IGNORECASE),
        "BASE-IPC-EXPORTED-WITH-PERM",
    ),
    (re.compile(r"\bexported\b.*\brelies on\b.*\bpermission", re.IGNORECASE), "BASE-IPC-EXPORTED-WITH-PERM"),
    (re.compile(r"ContentProvider.*(without|no)\s+permission", re.IGNORECASE), "BASE-IPC-PROVIDER-NO-ACL"),
    (
        re.compile(
            r"\b(Activity|Service|Receiver|Activity Alias|Provider)\b.*exported.*(does not d|does not decla|without)\s+permission",
            re.IGNORECASE,
        ),
        "BASE-IPC-COMP-NO-ACL",
    ),
)

_RULE_FORCE_PHRASES: tuple[tuple[str, str], ...] = (
    ("exported receiver relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("exported service relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("exported activity relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("exported provider relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("is exported but does not", "BASE-IPC-COMP-NO-ACL"),
)


def _iter_tokens(*values: str | None) -> Iterable[str]:
    for value in values:
        if not value:
            continue
        stripped = value.strip()
        if stripped:
            yield stripped


def derive_rule_id(
    kind: str | None,
    module_id: str | None,
    evidence_path: str | None,
    detail: str | None,
    *,
    rule_id_hint: str | None = None,
) -> str | None:
    """Best-effort rule identifier inference."""

    if rule_id_hint:
        hint = rule_id_hint.strip()
        if hint:
            return hint

    tokens = " ".join(_iter_tokens(kind, module_id, evidence_path, detail))
    if not tokens:
        return None

    for pattern, rid in _RULE_REGEXES:
        if pattern.search(tokens):
            return rid

    lower_tokens = tokens.lower()
    for phrase, rid in _RULE_FORCE_PHRASES:
        if phrase in lower_tokens:
            return rid

    return None