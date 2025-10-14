from __future__ import annotations

import re


_STRIP_MARKERS_RE = re.compile(
    r"\b(Protection level:|Constant\s+Value:|Added in API level|Added in version)\b",
    re.I,
)


def dedupe_sentences(paragraph: str) -> str:
    paragraph = re.sub(r'\bConstant\s+Value:\s*"[^"]+"', "", paragraph)
    parts = re.split(r"(?<=[.!?])\s+", paragraph)
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        norm = " ".join(part.split()).strip()
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return " ".join(out)


def strip_markers(text: str) -> str:
    text = re.sub(r'\bConstant\s+Value:\s*"[^"]+"', "", text, flags=re.I)
    m = _STRIP_MARKERS_RE.search(text)
    if m:
        text = text[: m.start()].rstrip()
    return " ".join(text.split()).strip()


def purge_markers(text: str) -> str:
    text = re.sub(r"\bProtection\s+level:\s*[^.]*\.?", "", text, flags=re.I)
    text = re.sub(r'\bConstant\s+Value:\s*"[^"]+"\.?', "", text, flags=re.I)
    text = re.sub(r"\bAdded\s+in\s+API\s+level\s*\d+\.?", "", text, flags=re.I)
    text = re.sub(r"\bAdded\s+in\s+version\s*[0-9]+(?:\.[0-9]+)?\.?", "", text, flags=re.I)
    return " ".join(text.split()).strip()


__all__ = ["dedupe_sentences", "strip_markers", "purge_markers"]

