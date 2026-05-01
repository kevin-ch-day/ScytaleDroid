"""Deterministic selection of string samples for paper-grade reports."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .allowlist import DEFAULT_POLICY_ROOT
from .bucket_meta import BUCKET_METADATA, BUCKET_ORDER

_SELECTION_VERSION = "v1"
_CONFIDENCE_RANK = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
    "": 0,
}


def _stable_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()


def _policy_version(root: Path) -> str | None:
    try:
        if not root.exists():
            return None
        if root.is_file():
            return hashlib.sha256(root.read_bytes()).hexdigest()
        entries: list[tuple[str, str]] = []
        for path in sorted(root.rglob("*.toml")):
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            entries.append((path.as_posix(), digest))
        if not entries:
            return None
        combined = "\n".join(f"{path}:{digest}" for path, digest in entries)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()
    except Exception:
        return None


def _selection_key(entry: Mapping[str, Any]) -> tuple[int, int, int, str, str]:
    confidence = str(entry.get("confidence") or "").strip().lower()
    confidence_rank = _CONFIDENCE_RANK.get(confidence, 0)
    value = str(entry.get("value_masked") or entry.get("value") or "")
    length = len(value)
    sample_hash = str(entry.get("sample_hash") or "").strip()
    if not sample_hash:
        sample_hash = _stable_hash(value)[:40]
    src = str(entry.get("src") or "")
    # Higher confidence/length first, stable hash and source for deterministic tie-breaks.
    return (-confidence_rank, -length, 0, sample_hash, src)


def select_samples(
    samples: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    max_samples: int,
    min_entropy: float | None = None,
    policy_root: Path | None = None,
) -> tuple[dict[str, list[Mapping[str, Any]]], dict[str, Any]]:
    """Select a deterministic subset of string samples per bucket."""

    if max_samples < 1:
        max_samples = 1

    selected: dict[str, list[Mapping[str, Any]]] = {}
    for bucket in BUCKET_ORDER:
        entries = samples.get(bucket) if isinstance(samples, Mapping) else None
        if not entries:
            continue
        ordered = sorted(
            (entry for entry in entries if isinstance(entry, Mapping)),
            key=_selection_key,
        )
        selected[bucket] = ordered[:max_samples]

    policy_root = policy_root or DEFAULT_POLICY_ROOT
    policy_version = _policy_version(Path(policy_root))
    bucket_priorities = {
        key: metadata.priority for key, metadata in BUCKET_METADATA.items()
    }
    selection_params = {
        "selection_version": _SELECTION_VERSION,
        "max_samples": max_samples,
        "min_entropy": min_entropy,
        "policy_root": str(policy_root),
        "policy_version": policy_version,
        "bucket_priorities": bucket_priorities,
        "sort_key": "confidence_desc,length_desc,hash_asc,src_asc",
    }
    return selected, selection_params


__all__ = ["select_samples"]
