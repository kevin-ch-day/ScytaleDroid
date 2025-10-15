from __future__ import annotations

"""Thin wrapper to expose the Harvest menu and CLI commands.

This module intentionally delegates to smaller modules to keep responsibilities
separated:
  - menu.py: interactive menu and rendering
  - commands.py: non-interactive CLI subcommands (refresh, counts, write-db, find)
  - ops.py: reusable helpers (load/export/validate/etc.)
"""

from .permissions_catalog_menu import perm_catalog_menu

__all__ = ["perm_catalog_menu"]


if __name__ == "__main__":  # pragma: no cover - manual invocation
    from .commands import main as _main

    _main()
