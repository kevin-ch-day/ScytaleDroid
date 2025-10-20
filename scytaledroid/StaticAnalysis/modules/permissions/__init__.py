"""Permission analysis helpers."""

from .catalog import (
    PermissionCatalog,
    PermissionDescriptor,
    build_catalog_from_permissions_xml,
    classify_permission,
    load_permission_catalog,
)
from .profile import PermissionAnalysis, build_permission_analysis
from .simple import collect_permissions_and_sdk, print_permissions_block

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
