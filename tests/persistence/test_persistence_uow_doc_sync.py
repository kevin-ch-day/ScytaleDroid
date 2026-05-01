from __future__ import annotations

import re
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.persistence.contracts import SCIENTIFIC_UOW_TABLES


def test_persistence_uow_doc_matches_contract_constant():
    doc_path = Path("docs/contracts/persistence_uow_tables.md")
    text = doc_path.read_text(encoding="utf-8")
    listed = set(re.findall(r"`([a-z0-9_]+)`", text))
    # keep only scientific names (exclude ledger mention section)
    listed_scientific = {name for name in listed if name in SCIENTIFIC_UOW_TABLES}

    # Every scientific contract table must be documented.
    assert SCIENTIFIC_UOW_TABLES.issubset(listed_scientific)

