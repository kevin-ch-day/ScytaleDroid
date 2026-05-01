from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.storage import persistence


def test_fmt_dt_datetime_to_mysql() -> None:
    dt = datetime(2026, 2, 7, 12, 34, 56, tzinfo=UTC)
    assert persistence._fmt_dt(dt) == "2026-02-07 12:34:56"


def test_fmt_dt_iso_with_tz_offset_to_mysql() -> None:
    assert (
        persistence._fmt_dt("2026-02-07T22:57:29.769069+00:00")
        == "2026-02-07 22:57:29"
    )


def test_fmt_dt_iso_z_suffix_to_mysql() -> None:
    assert persistence._fmt_dt("2026-02-07T17:06:31Z") == "2026-02-07 17:06:31"


def test_fmt_dt_db_string_passthrough_prefix() -> None:
    # Some producers may already emit DB-ish strings. We preserve the DATETIME prefix.
    assert persistence._fmt_dt("2026-02-07 17:06:31.123456") == "2026-02-07 17:06:31"


def test_fmt_dt_none() -> None:
    assert persistence._fmt_dt(None) is None

