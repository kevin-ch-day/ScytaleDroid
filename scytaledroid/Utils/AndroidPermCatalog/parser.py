from __future__ import annotations

import re
from typing import Dict, Any, Iterable, List, Tuple

from .normalize import PermissionMeta, normalise_protection, split_protection_tokens
from .protection import ALLOWED_TOKENS
from .summary_clean import dedupe_sentences as _dedupe_sentences, strip_markers as _strip_markers, purge_markers as _purge_markers


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _short(name: str) -> str:
    return name.split("android.permission.", 1)[1] if name.startswith("android.permission.") else name




def parse_manifest_permissions(html: str, *, base_url: str) -> List[PermissionMeta]:
    """Parse Manifest.permission documentation HTML into PermissionMeta rows.

    Requires BeautifulSoup at runtime. If BeautifulSoup is not available,
    raises a RuntimeError with an actionable message, so callers can surface a
    friendly hint to install the dependency.
    """

    try:
        from bs4 import BeautifulSoup as Soup  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "beautifulsoup4 is required to parse permission docs. Install with: pip install beautifulsoup4"
        ) from exc

    soup = Soup(html, "html.parser")
    entries: Dict[str, Dict[str, Any]] = {}

    # Try to find sections/cards per permission; fall back heuristics when needed
    cards: List[Any] = soup.find_all(["div", "section"], attrs={"data-version-added": re.compile(r"^\d+$")})  # type: ignore[name-defined]
    if not cards:
        for h in soup.select("div.devsite-article-body h2, div.devsite-article-body h3"):
            txt = _clean(h.get_text())
            if txt.startswith("android.permission.") or re.match(r"^[A-Z_0-9]+$", txt):
                parent = h.parent if h.parent else h
                cards.append(parent)
    if not cards:
        cards = soup.find_all(string=re.compile(r"^android\.permission\.", re.I))  # type: ignore[assignment]

    for card in cards:
        heading = card.find(["h3", "h2"]) if hasattr(card, "find") else None
        anchor_id = heading.get("id") if (heading and heading.has_attr("id")) else None
        if anchor_id and anchor_id.startswith("android.permission."):
            name = anchor_id
        else:
            heading_text = _clean((heading.get_text() if heading else getattr(card, "get_text", lambda **k: str(card))()))
            if heading_text.startswith("android.permission."):
                name = heading_text
            elif re.match(r"^[A-Z_0-9]+$", heading_text):
                name = f"android.permission.{heading_text}"
            else:
                code = card.find("code") if hasattr(card, "find") else None
                code_text = _clean(code.get_text()) if code else ""
                name = code_text if code_text.startswith("android.permission.") else ""
        if not name or name in ("Constants", "Manifest.permission"):
            continue

        text = card.get_text(" ", strip=True) if hasattr(card, "get_text") else str(card)

        # Added API / version
        added_api = None
        added_version = None
        ver = card.get("data-version-added") if hasattr(card, "get") else None
        if ver and str(ver).isdigit():
            added_api = int(ver)
        else:
            m = re.search(r"\bAdded in API level\s+(\d+)\b", text)
            if m:
                added_api = int(m.group(1))
            else:
                # Some entries use semantic version strings like "Added in version 36.1"
                mv = re.search(r"\bAdded in version\s+([0-9]+(?:\.[0-9]+)?)\b", text)
                if mv:
                    added_version = mv.group(1)

        # Protection level — robust capture of tokens (e.g., signature|privileged|development)
        prot_raw = None
        m = re.search(r"\bProtection level:\s*", text)
        prot_tokens: list[str] = []
        prot_raw = None
        if m:
            # Look ahead a small window for token extraction
            window = text[m.end() : m.end() + 120]
            # Collect only allowed tokens
            for tok in re.findall(r"[A-Za-z]+", window):
                t = tok.lower()
                if t in ALLOWED_TOKENS and t not in prot_tokens:
                    prot_tokens.append(t)
            if prot_tokens:
                prot_raw = "|".join(prot_tokens)
        prot = normalise_protection(prot_raw)
        if not prot_tokens and prot:
            prot_tokens = [prot]

        # Flags and deprecation
        hard_restricted = bool(re.search(r"\bhard restricted\b", text, re.I))
        soft_restricted = bool(re.search(r"\bsoft restricted\b", text, re.I))
        system_only = bool(re.search(r"\bNot for use by third[- ]party applications\b", text, re.I))

        dep_api = None
        dep_note = None
        mdep = re.search(r"\bdeprecated in API level\s+(\d+)\b", text, re.I)
        if mdep:
            dep_api = int(mdep.group(1))
        sn = re.search(r"([^.]*\bdeprecated\b[^.]*\.)", text, re.I)
        if sn:
            dep_note = _purge_markers(_clean(sn.group(1)))

        # Constant Value
        const_value = None
        mconst = re.search(r'Constant Value:\s*"([^"]+)"', text)
        if mconst:
            const_value = mconst.group(1)

        # Summary paragraphs before protection level (trim noisy tail, de-duplicate)
        summary_parts: List[str] = []
        if hasattr(card, "find_all"):
            for p in card.find_all("p", recursive=True):
                t = _clean(p.get_text(" ", strip=True))
                if not t:
                    continue
                if t.startswith("Added in API level"):
                    continue
                # Trim paragraph at protection marker or constant value marker if inline
                # Hard-strip markers and payloads, then de-duplicate repeated sentences
                t = _strip_markers(t)
                t = _dedupe_sentences(t)
                if not t:
                    continue
                summary_parts.append(t)
        # De-duplicate while preserving order
        seen = set()
        ordered: List[str] = []
        for seg in summary_parts:
            if seg not in seen:
                seen.add(seg)
                ordered.append(seg)
        summary = _clean(" ".join(ordered))
        # Final safety pass to strip markers and dedupe once more
        summary = _purge_markers(_dedupe_sentences(summary))

        # Capture restricted and system-only notes (first matching sentence)
        restricted_note = None
        m_rn = re.search(r"([^.]*\b(hard|soft) restricted\b[^.]*\.)", text, re.I)
        if m_rn:
            restricted_note = _purge_markers(_clean(m_rn.group(1)))
        if hard_restricted and not restricted_note:
            restricted_note = "Hard restricted; installer allowlist required"
        system_only_note = None
        m_sn = re.search(r"([^.]*Not for use by third[- ]party applications[^.]*\.)", text, re.I)
        if m_sn:
            system_only_note = _purge_markers(_clean(m_sn.group(1)))

        # Extract API references like Foo.bar(…) or Class#method
        api_refs: set[str] = set()
        # Replace ERROR(...) wrappers that appear in some online docs
        cleaned_text = re.sub(r"ERROR\(/([^)]*)\)", r"\1", text)
        for match in re.findall(r"\b([A-Z][A-Za-z0-9_]*(?:\.[A-Z]?[A-Za-z0-9_]+)+)\s*\(", cleaned_text):
            api_refs.add(match)
        for match in re.findall(r"\b([A-Z][A-Za-z0-9_]*(?:#[A-Za-z0-9_]+))\b", cleaned_text):
            api_refs.add(match)

        # Prefer short-name anchors like #ACCESS_FINE_LOCATION
        short_name = _short(name)
        anchor = anchor_id or short_name or name
        doc_url = f"{base_url}#{anchor}"

        entries[name] = {
            "name": name,
            "short": _short(name),
            "protection_raw": prot_raw,
            "protection": prot,
            "protection_tokens": prot_tokens,
            "added_api": added_api,
            "added_version": added_version,
            "deprecated_api": dep_api,
            "deprecated_note": dep_note,
            "hard_restricted": hard_restricted,
            "soft_restricted": soft_restricted,
            "system_only": system_only,
            "restricted_note": restricted_note,
            "system_only_note": system_only_note,
            "constant_value": const_value,
            "summary": summary,
            "doc_url": doc_url,
            "api_references": sorted(api_refs),
        }

    result: List[PermissionMeta] = []
    for name, meta in sorted(entries.items(), key=lambda kv: kv[0].casefold()):
        result.append(
            PermissionMeta(
                name=name,
                short=str(meta.get("short") or ""),
                protection=meta.get("protection"),
                protection_raw=meta.get("protection_raw"),
                protection_tokens=tuple(meta.get("protection_tokens") or ()),
                added_api=meta.get("added_api"),
                added_version=meta.get("added_version"),
                deprecated_api=meta.get("deprecated_api"),
                deprecated_note=meta.get("deprecated_note"),
                hard_restricted=bool(meta.get("hard_restricted")),
                soft_restricted=bool(meta.get("soft_restricted")),
                system_only=bool(meta.get("system_only")),
                restricted_note=meta.get("restricted_note"),
                system_only_note=meta.get("system_only_note"),
                constant_value=meta.get("constant_value"),
                summary=str(meta.get("summary") or ""),
                doc_url=str(meta.get("doc_url") or ""),
                api_references=tuple(meta.get("api_references") or ()),
            )
        )
    return result
