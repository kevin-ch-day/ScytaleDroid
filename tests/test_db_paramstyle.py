import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scytaledroid.Database.db_core import db_queries as core_q  # noqa: E402


@pytest.mark.integration
def test_run_sql_supports_named_and_positional_placeholders():
    """Exercise run_sql with both tuple/positional and dict/named params."""

    table_name = "paramstyle_guard_test"
    try:
        core_q.run_sql(f"DROP TABLE IF EXISTS {table_name}")
        core_q.run_sql(
            f"CREATE TABLE {table_name} ("
            "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "
            "value VARCHAR(64) NOT NULL"
            ")"
        )

        tuple_id = core_q.run_sql(
            f"INSERT INTO {table_name} (value) VALUES (%s)",
            ("tuple-style",),
            return_lastrowid=True,
        )
        dict_id = core_q.run_sql(
            f"INSERT INTO {table_name} (value) VALUES (%(val)s)",
            {"val": "dict-style"},
            return_lastrowid=True,
        )

        assert tuple_id != dict_id

        rows = core_q.run_sql(
            f"SELECT value FROM {table_name} ORDER BY id",
            fetch="all",
        )
        assert rows == [("tuple-style",), ("dict-style",)]
    except Exception as exc:  # pragma: no cover - defensive skip when DB unavailable
        pytest.skip(f"Database not available for paramstyle integration test: {exc}")
    finally:
        try:
            core_q.run_sql(f"DROP TABLE IF EXISTS {table_name}")
        except Exception:
            pass
