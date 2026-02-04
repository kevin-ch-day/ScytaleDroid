"""Permission analysis helpers."""

from .catalog import (
    PermissionCatalog,
    PermissionDescriptor,
    build_catalog_from_permissions_xml,
    classify_permission,
    load_permission_catalog,
)
from .permission_console_rendering import print_permissions_block
from .permission_manifest_extract import collect_permissions_and_sdk
from .profile import PermissionAnalysis, build_permission_analysis

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