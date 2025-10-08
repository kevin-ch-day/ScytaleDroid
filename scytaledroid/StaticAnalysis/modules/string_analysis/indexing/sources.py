"""String source collectors for APK contents."""

from __future__ import annotations

import zipfile
from typing import Iterable, Mapping

try:  # pragma: no cover - compatibility for androguard <4
    from androguard.core.bytecodes.apk import FileNotPresent
except ImportError:  # pragma: no cover - androguard >=4
    from androguard.core.apk import FileNotPresent
from androguard.core.apk import APK

from .models import IndexedString
from .utils import looks_textual, strings_from_binary, strings_from_text


def iterate_resource_strings(resources: object) -> Iterable[str]:
    """Best-effort generator for resource string values."""

    try:
        public = resources.get_resolved_strings()
    except Exception:
        public = None

    if isinstance(public, Mapping):
        for value in public.values():
            if not value:
                continue
            string_value = str(value)
            if string_value.strip():
                yield string_value

    if hasattr(resources, "get_string_resources"):  # pragma: no cover - optional API
        try:
            entries = resources.get_string_resources()
        except Exception:
            entries = None
        if isinstance(entries, Mapping):
            for value in entries.values():
                if not value:
                    continue
                string_value = str(value)
                if string_value.strip():
                    yield string_value


def collect_file_strings(apk: APK) -> tuple[IndexedString, ...]:
    """Extract UTF-8 string fragments from APK file entries."""

    try:
        file_names = sorted(apk.get_files() or [])
    except (RuntimeError, zipfile.BadZipFile):  # pragma: no cover - corrupted APKs
        return tuple()

    collected: list[IndexedString] = []

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

        if origin_type == "native":
            fragments = strings_from_binary(blob)
            confidence = "low"
        else:
            if not looks_textual(blob):
                continue
            fragments = strings_from_text(blob)
            confidence = "normal"

        for fragment in fragments:
            collected.append(
                IndexedString(
                    value=fragment,
                    origin=name,
                    origin_type=origin_type,
                    confidence=confidence,
                )
            )

    return tuple(collected)


def classify_origin_type(path: str) -> str | None:
    """Map APK file paths to semantic origin types."""

    lowered = path.lower()
    if lowered.startswith("assets/"):
        return "asset"
    if lowered.startswith("res/raw"):
        return "raw"
    if lowered.startswith("lib/") and lowered.endswith(".so"):
        return "native"
    if lowered.endswith(".so"):
        return "native"
    if lowered == "resources.arsc":
        return "resource"
    return None


__all__ = ["iterate_resource_strings", "collect_file_strings", "classify_origin_type"]
