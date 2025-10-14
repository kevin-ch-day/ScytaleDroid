from __future__ import annotations

from typing import Iterable


ALLOWED_TOKENS = {
    "dangerous",
    "normal",
    "signature",
    "signatureorsystem",
    "privileged",
    "development",
    "installer",
    "instant",
    "appop",
    "system",
    "internal",
    "oem",
    "preinstalled",
    "role",
}


def sanitise_tokens(tokens: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for tok in tokens:
        t = str(tok).strip().lower()
        if t in ALLOWED_TOKENS and t not in seen:
            seen.add(t)
            out.append(t)
    return out


__all__ = ["ALLOWED_TOKENS", "sanitise_tokens"]

