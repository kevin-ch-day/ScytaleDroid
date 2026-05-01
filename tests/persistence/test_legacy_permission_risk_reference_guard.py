from __future__ import annotations

from pathlib import Path
import re

import pytest


# Guard that the retired legacy static_permission_risk table does not regrow
# new product or maintenance dependencies.
pytestmark = [pytest.mark.legacy_contract, pytest.mark.tier3]


def test_legacy_permission_risk_references_are_constrained():
    root = Path(__file__).resolve().parents[2]
    allowed = {
        "scytaledroid/Database/db_func/static_analysis/static_permission_risk.py",
        "scytaledroid/Database/db_queries/schema_manifest.py",
        "scytaledroid/Database/db_queries/static_analysis/static_permission_risk.py",
        "scytaledroid/Database/db_utils/database_menu.py",
        "scytaledroid/Database/db_utils/action_groups/risk_actions.py",
        "scytaledroid/StaticAnalysis/cli/persistence/permission_risk.py",
    }

    found: set[str] = set()
    for path in (root / "scytaledroid").rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"\bstatic_permission_risk\b", text):
            found.add(rel)

    unexpected = sorted(found - allowed)
    assert not unexpected, f"Unexpected legacy static_permission_risk references: {unexpected}"
