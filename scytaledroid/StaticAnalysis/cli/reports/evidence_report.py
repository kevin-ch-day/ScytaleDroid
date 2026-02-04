from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any

__all__ = ["NormalisedEvidence", "normalize_evidence"]


@dataclass(slots=True)
class NormalisedEvidence:
    """Canonicalised evidence payload emitted by detectors/persistence."""

    detail: str | None
    path: str | None
    offset: str | None
    dex_sid: str | None
    entries: list[Mapping[str, Any]]

    def as_payload(self) -> Mapping[str, Any]:
        payload: MutableMapping[str, Any] = {}
        if self.path:
            payload["path"] = self.path
        if self.offset:
            payload["offset"] = self.offset
        if self.detail:
            payload["detail"] = self.detail
        if self.dex_sid:
            payload["dex_sid"] = self.dex_sid
        if self.entries:
            payload["entries"] = self.entries
        return payload


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _normalise_entry(item: Mapping[str, Any]) -> Mapping[str, Any]:
    normalised: MutableMapping[str, Any] = {}
    for key, value in item.items():
        if isinstance(value, (str, int, float, bool)):
            normalised[str(key)] = value
    return normalised


def _iter_evidence(evidence: Any) -> Iterable[Any]:
    if evidence is None:
        return []
    if isinstance(evidence, (list, tuple, set)):
        return evidence
    return [evidence]


_PATH_KEYS = ("path", "file", "resource", "location")
_OFFSET_KEYS = ("offset", "line", "index", "column")
_DETAIL_KEYS = ("detail", "message", "preview", "summary", "headline", "note", "because")
_DEX_KEYS = ("dex_sid", "dexSid", "dex", "dex_id")


def normalize_evidence(
    evidence: Any,
    *,
    detail_hint: str | None = None,
    path_hint: str | None = None,
    offset_hint: str | None = None,
    dex_hint: str | None = None,
) -> NormalisedEvidence:
    """Normalise detector evidence for DB persistence."""

    chosen_path: str | None = None
    chosen_offset: str | None = None
    chosen_detail: str | None = None
    chosen_dex: str | None = None
    entries: list[Mapping[str, Any]] = []

    for raw in _iter_evidence(evidence):
        if isinstance(raw, Mapping):
            mapping: Mapping[str, Any] = raw
        else:
            mapping = {
                key: getattr(raw, key)
                for key in dir(raw)
                if not key.startswith("_")
            }
        candidate_path = next(
            (
                _truncate(str(mapping.get(key)), 512)
                for key in _PATH_KEYS
                if mapping.get(key)
            ),
            None,
        )
        candidate_offset = next(
            (
                _truncate(str(mapping.get(key)), 64)
                for key in _OFFSET_KEYS
                if mapping.get(key) not in (None, "")
            ),
            None,
        )
        candidate_detail = next(
            (
                _truncate(str(mapping.get(key)), 256)
                for key in _DETAIL_KEYS
                if mapping.get(key)
            ),
            None,
        )
        candidate_dex = next(
            (
                _truncate(str(mapping.get(key)), 128)
                for key in _DEX_KEYS
                if mapping.get(key)
            ),
            None,
        )
        if candidate_path and not chosen_path:
            chosen_path = candidate_path
        if candidate_offset and not chosen_offset:
            chosen_offset = candidate_offset
        if candidate_detail and not chosen_detail:
            chosen_detail = candidate_detail
        if candidate_dex and not chosen_dex:
            chosen_dex = candidate_dex

        normalised_entry = _normalise_entry(mapping)
        if normalised_entry:
            entries.append(normalised_entry)

    if not chosen_path:
        chosen_path = _truncate(path_hint, 512)
    if not chosen_offset:
        chosen_offset = _truncate(offset_hint, 64)
    if not chosen_detail:
        chosen_detail = _truncate(detail_hint, 256)
    if not chosen_dex:
        chosen_dex = _truncate(dex_hint, 128)

    return NormalisedEvidence(
        detail=chosen_detail,
        path=chosen_path,
        offset=chosen_offset,
        dex_sid=chosen_dex,
        entries=entries,
    )