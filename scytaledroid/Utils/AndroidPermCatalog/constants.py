from __future__ import annotations

from pathlib import Path

# Shared constants for the AndroidPermCatalog utilities
DEFAULT_CACHE = Path(__file__).resolve().parent / "cache" / "framework_permissions.json"

__all__ = ["DEFAULT_CACHE"]

