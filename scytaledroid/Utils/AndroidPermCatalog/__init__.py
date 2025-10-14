"""Android framework permissions catalog utilities.

This package provides helpers to fetch, parse, normalise and query the
Android Manifest permission documentation. It is intentionally DB-agnostic
and designed to be used by CLI utilities and StaticAnalysis as a read-only
catalog.
"""

from .normalize import PermissionMeta
from .api import (
    load_catalog,
    save_catalog_json,
    load_catalog_json,
    index_by_constant,
    index_by_short,
)

__all__ = [
    "PermissionMeta",
    "load_catalog",
    "save_catalog_json",
    "load_catalog_json",
    "index_by_constant",
    "index_by_short",
]

