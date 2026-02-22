"""Authoritative app-category mapping for scripted template selection (Paper #2)."""

from __future__ import annotations

import json
import hashlib
from functools import lru_cache
from pathlib import Path

_MAP_PATH = Path(__file__).with_name("category_map_v1.json")
_DEFAULT_VERSION = "v1"


@lru_cache(maxsize=1)
def _load_mapping() -> dict:
    try:
        payload = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {"version": _DEFAULT_VERSION, "categories": {}, "packages": {}}


def mapping_version() -> str:
    payload = _load_mapping()
    return str(payload.get("version") or _DEFAULT_VERSION)


def mapping_snapshot() -> dict:
    payload = _load_mapping()
    out = dict(payload)
    out.setdefault("version", _DEFAULT_VERSION)
    out.setdefault("categories", {})
    out.setdefault("packages", {})
    return out


def mapping_sha256() -> str:
    snap = mapping_snapshot()
    material = json.dumps(snap, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def category_for_package(package_name: str) -> str | None:
    payload = _load_mapping()
    packages = payload.get("packages") if isinstance(payload.get("packages"), dict) else {}
    return str(packages.get(str(package_name or "").strip().lower()) or "").strip().lower() or None


def template_for_package(package_name: str) -> str | None:
    payload = _load_mapping()
    categories = payload.get("categories") if isinstance(payload.get("categories"), dict) else {}
    cat = category_for_package(package_name)
    if not cat:
        return None
    return str(categories.get(cat) or "").strip() or None


__all__ = [
    "mapping_version",
    "mapping_snapshot",
    "mapping_sha256",
    "category_for_package",
    "template_for_package",
]
