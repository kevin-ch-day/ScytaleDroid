from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

import pytest

from scytaledroid.Database.db_func.static_analysis import string_analysis as sa_db


@contextmanager
def _fake_session(**_kwargs):
    yield object()


def test_seed_doc_hosts_normalises_and_deduplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, tuple[str, ...] | None]] = []

    def fake_run_sql(query: str, params: tuple[str, ...] | None = None, **_kwargs: object) -> None:
        captured.append((query, params))

    monkeypatch.setattr(sa_db, "database_session", _fake_session)
    monkeypatch.setattr(sa_db, "run_sql", fake_run_sql)

    count = sa_db.seed_doc_hosts([
        "  W3.org  ",
        "ANDROID.com",
        "android.com",
        "",
        None,
        " schemas.android.com ",
    ])

    assert count == 3
    inserted_hosts = [params[0] for _, params in captured if params]
    assert inserted_hosts == ["android.com", "schemas.android.com", "w3.org"]


def test_seed_doc_hosts_from_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "noise.toml"
    config_file.write_text(
        """
[hosts.allow_doc]
list = ["Example.com", "docs.test.org/path"]

[hosts.allow_cdn_doc]
list = ["static.docs.test.org"]

[placeholders.hosts_exact]
list = ["placeholder.example"]

[sources.doc_like_paths.prefix]
list = []

[[rules]]
name = "dummy"
when.host_in_group = "hosts.allow_doc"
then.action = "suppress"
""".strip()
    )

    captured: list[tuple[str, ...]] = []

    def fake_seed(hosts: Iterable[str]) -> int:
        snapshot = tuple(hosts)
        captured.append(snapshot)
        return len(snapshot)

    monkeypatch.setattr(sa_db, "seed_doc_hosts", fake_seed)

    inserted = sa_db.seed_doc_hosts_from_config(config_file)

    assert inserted == 3
    assert captured == [
        ("docs.test.org", "example.com", "test.org")
    ]


def test_seed_doc_hosts_from_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "a.toml"
    first.write_text(
        """
[hosts.allow_doc]
list = ["example.org"]
""".strip()
    )
    second = tmp_path / "b.toml"
    second.write_text(
        """
[hosts.allow_doc]
list = ["docs.example.org", "alpha.test"]
""".strip()
    )

    captured: list[tuple[str, ...]] = []

    def fake_seed(hosts: Iterable[str]) -> int:
        snapshot = tuple(hosts)
        captured.append(snapshot)
        return len(snapshot)

    monkeypatch.setattr(sa_db, "seed_doc_hosts", fake_seed)

    inserted = sa_db.seed_doc_hosts_from_config(tmp_path)

    assert inserted == 3
    assert captured == [("alpha.test", "docs.example.org", "example.org")]
