"""Metadata helpers for inventory guard.

This package re-exports the public helpers that the device menu relies on
while keeping loader/normalizer/delta logic split into smaller modules.
"""

from .loader import get_latest_inventory_metadata
from .status_formatters import format_inventory_status, format_pull_hint

__all__ = [
    "get_latest_inventory_metadata",
    "format_inventory_status",
    "format_pull_hint",
]
