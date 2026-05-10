"""S1.5: Guard that PI-governed table names do not appear outside the PI DB module.

``android_permission_dict_*``, ``android_permission_meta_*``, enrichment/observation tables
must be queried only through ``scytaledroid.Database.db_core.permission_intel`` (dedicated DSN),
never via the primary ``run_sql`` session used for Scytale core catalog tables.
"""

from __future__ import annotations

import re
from pathlib import Path

# Contract A-style physical tables (exclude logical DB name ``android_permission_intel``).
_PI_TABLE_FRAGMENT_RE = re.compile(
    r"android_permission_(?:dict_|meta_|enrich_|obs_|run_|triage_|token_|prefix_)"
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCYTALE_PKG = _REPO_ROOT / "scytaledroid"
_PI_MODULE = _SCYTALE_PKG / "Database" / "db_core" / "permission_intel.py"


def _py_files_under_scytaledroid() -> list[Path]:
    return sorted(_SCYTALE_PKG.rglob("*.py"))


def test_android_permission_physical_tables_only_in_permission_intel_module() -> None:
    """Every ``android_permission_*`` table reference in SQL strings lives in permission_intel.py."""
    offenders: list[str] = []
    for path in _py_files_under_scytaledroid():
        if path.resolve() == _PI_MODULE.resolve():
            continue
        text = path.read_text(encoding="utf-8")
        if _PI_TABLE_FRAGMENT_RE.search(text):
            offenders.append(str(path.relative_to(_REPO_ROOT)))
    assert offenders == [], (
        "PI-governed android_permission_* table fragments found outside permission_intel.py — "
        f"use intel_db/permission_intel.run_sql instead: {offenders}"
    )


def test_permission_intel_module_exists() -> None:
    assert _PI_MODULE.is_file()
