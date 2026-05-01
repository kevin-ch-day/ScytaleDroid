"""Permission analysis helpers."""

from __future__ import annotations

from importlib import import_module

_LAZY_EXPORTS = {
    "PermissionCatalog": (".catalog", "PermissionCatalog"),
    "PermissionDescriptor": (".catalog", "PermissionDescriptor"),
    "build_catalog_from_permissions_xml": (".catalog", "build_catalog_from_permissions_xml"),
    "classify_permission": (".catalog", "classify_permission"),
    "load_permission_catalog": (".catalog", "load_permission_catalog"),
    "print_permissions_block": (".permission_console_rendering", "print_permissions_block"),
    "collect_permissions_and_sdk": (".permission_manifest_extract", "collect_permissions_and_sdk"),
    "PermissionAnalysis": (".profile", "PermissionAnalysis"),
    "build_permission_analysis": (".profile", "build_permission_analysis"),
}


def __getattr__(name: str) -> object:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


__all__ = [
    "PermissionCatalog",
    "PermissionDescriptor",
    "build_catalog_from_permissions_xml",
    "PermissionAnalysis",
    "build_permission_analysis",
    "classify_permission",
    "collect_permissions_and_sdk",
    "load_permission_catalog",
    "print_permissions_block",
]
