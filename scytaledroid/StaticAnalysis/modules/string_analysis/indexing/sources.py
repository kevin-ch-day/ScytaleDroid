"""String source collectors for APK contents."""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from collections.abc import Iterable, Mapping

from scytaledroid.StaticAnalysis._androguard import APK, FileNotPresent

from .models import IndexedString
from ..origins import canonical_origin_type
from .utils import (
    StringFragment,
    looks_textual,
    strings_from_binary,
    strings_from_text,
    strings_from_utf16,
    strings_from_utf32,
)

_DEX_ID_PATTERN = re.compile(r"classes(?P<index>\d+)?\.dex", re.IGNORECASE)
_LOCALE_PATTERN = re.compile(r"res/(?:values|xml|raw|layout)(?:-([\w-]+))?/")
_TEXT_FORWARD_SUFFIXES: tuple[str, ...] = (
    ".json",
    ".js",
    ".txt",
    ".xml",
    ".html",
    ".htm",
    ".properties",
    ".conf",
    ".cfg",
    ".ini",
    ".csv",
    ".md",
    ".bundle",
    ".map",
)
_TEXT_FORWARD_TOKENS: tuple[str, ...] = (
    "config",
    "manifest",
    "endpoint",
    "url",
    "domain",
    "host",
    "policy",
    "settings",
)


def iterate_resource_strings(resources: object) -> Iterable[str]:
    """Best-effort generator for resource string values."""

    try:
        public = resources.get_resolved_strings()
    except Exception:
        public = None

    if isinstance(public, Mapping):
        yield from _iter_nested_string_values(public)

    if hasattr(resources, "get_string_resources"):  # pragma: no cover - optional API
        try:
            entries = resources.get_string_resources()
        except Exception:
            entries = None
        if isinstance(entries, Mapping):
            yield from _iter_nested_string_values(entries)


def _iter_nested_string_values(node: object) -> Iterable[str]:
    if isinstance(node, Mapping):
        for value in node.values():
            yield from _iter_nested_string_values(value)
        return
    if isinstance(node, (list, tuple, set)):
        for value in node:
            yield from _iter_nested_string_values(value)
        return
    if isinstance(node, str):
        if node.strip():
            yield node


def _apk_sha256(apk: APK) -> str | None:
    """Best-effort APK hash helper."""

    for attr in ("get_sha256", "sha256", "file_sha256"):
        getter = getattr(apk, attr, None)
        if callable(getter):
            try:
                value = getter()
            except Exception:  # pragma: no cover - defensive against wrappers
                continue
        else:
            value = getter
        if isinstance(value, str) and value:
            return value
    try:
        data = apk.get_buff()
    except Exception:  # pragma: no cover - fallback path
        return None
    if not isinstance(data, (bytes, bytearray)):
        return None
    return hashlib.sha256(data).hexdigest()


def _infer_split_id(apk: APK) -> str:
    candidate = getattr(apk, "split_name", None) or getattr(apk, "split_id", None)
    if isinstance(candidate, str) and candidate:
        return candidate
    filename = getattr(apk, "filename", None)
    if isinstance(filename, str) and "split_config" in filename:
        stem = os.path.basename(filename)
        return stem.split(".apk", 1)[0]
    return "base"


def _dex_id_from_name(path: str) -> int | None:
    match = _DEX_ID_PATTERN.search(path)
    if not match:
        return None
    index = match.group("index")
    if not index:
        return 1
    try:
        return int(index)
    except ValueError:
        return None


def _locale_from_path(path: str) -> str | None:
    match = _LOCALE_PATTERN.search(path)
    if not match:
        return None
    qualifier = match.group(1)
    return qualifier or None


def _is_probable_protobuf(blob: bytes) -> bool:
    if len(blob) < 32:
        return False
    sample = blob[:512]
    markers = sum(1 for byte in sample if byte in {0x0A, 0x12, 0x1A, 0x22, 0x2A})
    return markers / len(sample) > 0.08


def _should_scan_binary(origin_type: str, blob: bytes) -> bool:
    if origin_type == "native":
        return True
    if origin_type == "rn_bundle":
        return True
    if looks_textual(blob):
        return False
    return _is_probable_protobuf(blob)


def _should_skip_split_member_entry(name: str, origin_type: str, blob: bytes) -> bool:
    lowered = name.lower()
    if origin_type == "native":
        return True
    if origin_type == "resource":
        return True
    if origin_type == "rn_bundle":
        return not looks_textual(blob)
    if origin_type in {"asset", "raw"}:
        if lowered.endswith(_TEXT_FORWARD_SUFFIXES):
            return False
        if any(token in lowered for token in _TEXT_FORWARD_TOKENS) and looks_textual(blob):
            return False
        return True
    return False


def _allow_utf_expansion(mode: str, origin_type: str, name: str) -> bool:
    if mode != "split_lightweight":
        return True
    lowered = name.lower()
    if origin_type == "code":
        return True
    if origin_type == "rn_bundle":
        return lowered.endswith(".json")
    return False


def collect_file_strings(apk: APK, *, mode: str = "full") -> tuple[IndexedString, ...]:
    """Extract UTF-8 string fragments from APK file entries."""

    try:
        file_names = sorted(apk.get_files() or [])
    except (RuntimeError, zipfile.BadZipFile):  # pragma: no cover - corrupted APKs
        return tuple()

    collected: list[IndexedString] = []

    apk_hash = _apk_sha256(apk)
    split_id = _infer_split_id(apk)

    for name in file_names:
        origin_type = classify_origin_type(name)
        if origin_type is None:
            continue
        try:
            blob = apk.get_file(name)
        except FileNotPresent:  # pragma: no cover - race condition/odd APKs
            continue
        except Exception:  # pragma: no cover - keep extraction resilient
            continue

        if not blob:
            continue
        if mode == "split_lightweight" and _should_skip_split_member_entry(name, origin_type, blob):
            continue

        blob_hash = hashlib.sha256(blob).hexdigest()
        sha_short = blob_hash[:8]

        fragments: tuple[StringFragment, ...]
        confidence = "normal"
        if origin_type == "native":
            fragments = strings_from_binary(blob)
            confidence = "low"
        else:
            if looks_textual(blob):
                fragments = strings_from_text(blob)
            elif _should_scan_binary(origin_type, blob):
                if mode == "split_lightweight" and origin_type in {"asset", "raw", "rn_bundle"}:
                    continue
                fragments = strings_from_binary(blob)
                confidence = "low"
            else:
                continue

        if _allow_utf_expansion(mode, origin_type, name):
            utf16_fragments = strings_from_utf16(blob)
            utf32_fragments = strings_from_utf32(blob)
            if utf16_fragments or utf32_fragments:
                fragments = tuple(
                    {
                        (frag.start, frag.end): frag
                        for frag in fragments + utf16_fragments + utf32_fragments
                    }.values()
                )
                confidence = "low"

        for fragment in fragments:
            locale_qualifier = _locale_from_path(name)
            dex_id = _dex_id_from_name(name) if origin_type == "code" else None
            collected.append(
                IndexedString(
                    value=fragment.value,
                    origin=name,
                    origin_type=origin_type,
                    confidence=confidence,
                    byte_offset=fragment.start,
                    source_sha256=blob_hash,
                    source_sha_short=sha_short,
                    context=fragment.context(blob),
                    apk_sha256=apk_hash,
                    split_id=split_id,
                    apk_offset_kind="byte_offset" if fragment.start is not None else "unknown",
                    dex_id=dex_id,
                    locale_qualifier=locale_qualifier,
                    synthetic=False,
                    derived_from=None,
                )
            )

    return tuple(collected)


def classify_origin_type(path: str) -> str | None:
    """Map APK file paths to semantic origin types."""

    lowered = path.lower()
    if lowered.startswith("assets/") and (
        lowered.endswith(".hbc")
        or lowered.endswith(".bundle")
        or lowered.endswith(".bundle.js")
        or "index.android.bundle" in lowered
    ):
        return "rn_bundle"
    if lowered.startswith("assets/"):
        return "asset"
    if lowered.startswith("res/raw"):
        return "raw"
    if lowered.startswith("lib/") and lowered.endswith(".so"):
        return "native"
    if lowered.endswith(".so"):
        return "native"
    if lowered.endswith(".dex"):
        return "code"
    if lowered == "resources.arsc":
        return "resource"
    return None


def collect_resource_table_strings(apk: APK) -> tuple[IndexedString, ...]:
    """Extract resolved resource-table strings from *apk* when available."""

    getter = getattr(apk, "get_android_resources", None)
    if not callable(getter):
        return tuple()

    try:
        resources = getter()
    except Exception:
        return tuple()
    if resources is None:
        return tuple()

    apk_hash = _apk_sha256(apk)
    split_id = _infer_split_id(apk)
    seen: set[str] = set()
    collected: list[IndexedString] = []

    for value in iterate_resource_strings(resources):
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        collected.append(
            IndexedString(
                value=normalized,
                origin="resources.arsc",
                origin_type=canonical_origin_type("resource"),
                confidence="normal",
                byte_offset=None,
                source_sha256=None,
                source_sha_short=None,
                context="resolved resource string",
                apk_sha256=apk_hash,
                split_id=split_id,
                apk_offset_kind="resource_table",
                dex_id=None,
                locale_qualifier=None,
                synthetic=False,
                derived_from=None,
            )
        )

    return tuple(collected)


__all__ = [
    "iterate_resource_strings",
    "collect_file_strings",
    "collect_resource_table_strings",
    "classify_origin_type",
]
