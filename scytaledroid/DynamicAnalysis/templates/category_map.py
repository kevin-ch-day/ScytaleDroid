"""Authoritative app-category mapping for scripted template selection.

Default behavior targets the v2/Paper #2 scripted templates and uses static JSON maps.

For Profile v3 (Paper #3) scripted capture, we need a catalog-driven mapping so the
"category is the primary scripted interaction protocol" rule stays consistent across:
- profiles/profile_v3_app_catalog.json
- manuscript/export tables
- operator scripted templates

Enable v3 mapping via: SCYTALEDROID_TEMPLATE_MAP_PROFILE=v3
"""

from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

_MAP_PATH = Path(__file__).with_name("category_map_v1.json")
_OVERRIDE_PATH = Path(__file__).with_name("app_template_overrides_v1.json")
_OVERRIDE_V3_PATH = Path(__file__).with_name("app_template_overrides_v3.json")
_DEFAULT_VERSION = "v1"
_PROFILE_ENV = "SCYTALEDROID_TEMPLATE_MAP_PROFILE"


@lru_cache(maxsize=1)
def _load_mapping() -> dict:
    try:
        payload = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {"version": _DEFAULT_VERSION, "categories": {}, "packages": {}}


def _load_overrides() -> dict:
    try:
        payload = json.loads(_OVERRIDE_PATH.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {"version": _DEFAULT_VERSION, "packages": {}}


def _load_overrides_v3() -> dict:
    try:
        payload = json.loads(_OVERRIDE_V3_PATH.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return {"version": _DEFAULT_VERSION, "packages": {}}


@lru_cache(maxsize=1)
def _load_v3_catalog() -> dict[str, dict[str, str]]:
    """Load v3 catalog as {package: {app, app_category}} (lowercased package keys)."""
    try:
        repo_root = Path(__file__).resolve().parents[3]
        cat_path = repo_root / "profiles" / "profile_v3_app_catalog.json"
        payload = json.loads(cat_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            out: dict[str, dict[str, str]] = {}
            for pkg, meta in payload.items():
                if not isinstance(meta, dict):
                    continue
                out[str(pkg).strip().lower()] = {
                    "app": str(meta.get("app") or "").strip(),
                    "app_category": str(meta.get("app_category") or "").strip().lower(),
                }
            return out
    except Exception:
        pass
    return {}


def _profile() -> str:
    return str(os.environ.get(_PROFILE_ENV) or "").strip().lower() or "v2"


def _v3_category_templates() -> dict[str, str]:
    return {
        "social_messaging": "social_messaging_basic_v1",
        "cloud_productivity": "cloud_productivity_basic_v1",
        "rtc_collaboration": "rtc_collaboration_basic_v1",
    }


def mapping_version() -> str:
    if _profile() == "v3":
        overrides = _load_overrides_v3()
        ovr_ver = str(overrides.get("version") or _DEFAULT_VERSION).strip() or _DEFAULT_VERSION
        return f"profile_v3_catalog_v1+overrides:{ovr_ver}"
    payload = _load_mapping()
    overrides = _load_overrides()
    base_ver = str(payload.get("version") or _DEFAULT_VERSION).strip() or _DEFAULT_VERSION
    ovr_ver = str(overrides.get("version") or _DEFAULT_VERSION).strip() or _DEFAULT_VERSION
    return f"{base_ver}+overrides:{ovr_ver}"


def mapping_snapshot() -> dict:
    if _profile() == "v3":
        overrides = _load_overrides_v3()
        return {
            "version": "profile_v3_catalog_v1",
            "profile": "v3",
            "category_templates": _v3_category_templates(),
            "catalog": _load_v3_catalog(),
            "app_template_overrides_version": str(overrides.get("version") or _DEFAULT_VERSION),
            "app_template_overrides": (
                dict(overrides.get("packages"))
                if isinstance(overrides.get("packages"), dict)
                else {}
            ),
        }
    payload = _load_mapping()
    overrides = _load_overrides()
    out = dict(payload)
    out.setdefault("version", _DEFAULT_VERSION)
    out.setdefault("categories", {})
    out.setdefault("packages", {})
    out["app_template_overrides_version"] = str(overrides.get("version") or _DEFAULT_VERSION)
    out["app_template_overrides"] = (
        dict(overrides.get("packages"))
        if isinstance(overrides.get("packages"), dict)
        else {}
    )
    return out


def mapping_sha256() -> str:
    snap = mapping_snapshot()
    material = json.dumps(snap, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def category_for_package(package_name: str) -> str | None:
    if _profile() == "v3":
        v3 = _load_v3_catalog()
        meta = v3.get(str(package_name or "").strip().lower()) or {}
        return str(meta.get("app_category") or "").strip().lower() or None
    payload = _load_mapping()
    packages = payload.get("packages") if isinstance(payload.get("packages"), dict) else {}
    return str(packages.get(str(package_name or "").strip().lower()) or "").strip().lower() or None


def template_for_package(package_name: str) -> str | None:
    if _profile() == "v3":
        cat = category_for_package(package_name)
        if not cat:
            return None
        return str(_v3_category_templates().get(cat) or "").strip() or None
    payload = _load_mapping()
    categories = payload.get("categories") if isinstance(payload.get("categories"), dict) else {}
    cat = category_for_package(package_name)
    if not cat:
        return None
    return str(categories.get(cat) or "").strip() or None


def template_override_for_package(package_name: str) -> str | None:
    if _profile() == "v3":
        payload = _load_overrides_v3()
        packages = payload.get("packages") if isinstance(payload.get("packages"), dict) else {}
        return str(packages.get(str(package_name or "").strip().lower()) or "").strip() or None
    payload = _load_overrides()
    packages = payload.get("packages") if isinstance(payload.get("packages"), dict) else {}
    return str(packages.get(str(package_name or "").strip().lower()) or "").strip() or None


def resolved_template_for_package(package_name: str) -> str | None:
    """Return per-app override template when present; otherwise category template."""
    return template_override_for_package(package_name) or template_for_package(package_name)


__all__ = [
    "mapping_version",
    "mapping_snapshot",
    "mapping_sha256",
    "category_for_package",
    "template_for_package",
    "template_override_for_package",
    "resolved_template_for_package",
]
