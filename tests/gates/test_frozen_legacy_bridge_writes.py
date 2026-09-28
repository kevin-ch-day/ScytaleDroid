from __future__ import annotations

import re
from pathlib import Path

import pytest
from scytaledroid.Database.db_utils.bridge_posture import frozen_legacy_write_tables

pytestmark = [pytest.mark.gate]

_SOURCE_ROOTS = (Path("scytaledroid"), Path("scripts"))


def _write_pattern(table: str) -> re.Pattern[str]:
    escaped = re.escape(table)
    return re.compile(
        rf"\b(?:INSERT\s+(?:IGNORE\s+)?INTO|REPLACE\s+INTO|UPDATE)\s+[`\"']?{escaped}[`\"']?\b",
        re.IGNORECASE | re.MULTILINE,
    )


def _owned_sql_sources() -> list[Path]:
    sources: list[Path] = []
    for root in _SOURCE_ROOTS:
        for suffix in ("*.py", "*.sql"):
            sources.extend(root.rglob(suffix))
    return sorted(path for path in sources if "archive" not in path.parts)


@pytest.mark.parametrize(
    "statement",
    (
        "INSERT INTO correlations (run_id) VALUES (1)",
        "insert ignore into `correlations` (run_id) values (1)",
        'REPLACE INTO "correlations" (run_id) VALUES (1)',
        "UPDATE correlations SET score=1",
    ),
)
def test_frozen_write_pattern_recognizes_prohibited_sql(statement: str) -> None:
    assert _write_pattern("correlations").search(statement)


def test_frozen_legacy_tables_have_no_owned_runtime_writers() -> None:
    violations: list[str] = []
    for path in _owned_sql_sources():
        source = path.read_text(encoding="utf-8", errors="replace")
        for table in sorted(frozen_legacy_write_tables()):
            pattern = _write_pattern(table)
            for match in pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                violations.append(f"{path}:{line}:{table}:{match.group(0)}")

    assert not violations, "frozen legacy bridge writer detected:\n" + "\n".join(violations)
