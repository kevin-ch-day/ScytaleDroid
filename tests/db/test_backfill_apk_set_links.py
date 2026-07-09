from __future__ import annotations

import json
from typing import Any

from scripts.db import backfill_apk_set_links as links


class FakeCoreQueries:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], str | None]] = []

    def run_sql(
        self,
        query: str,
        params: tuple[Any, ...] = (),
        *,
        fetch: str = "none",
        query_name: str | None = None,
        **_: Any,
    ) -> dict[str, int] | None:
        self.calls.append((query, params, query_name))
        if "information_schema.columns" in query:
            return {"n": 1}
        if fetch == "one_dict":
            return {
                "candidates": 0,
                "unique_matches": 0,
                "ambiguous_matches": 0,
                "no_matches": 0,
                "n": 0,
            }
        return None


def test_preview_dynamic_accepts_package_scope() -> None:
    fake = FakeCoreQueries()

    links._preview_dynamic(fake, package="com.pinterest")

    preview = [
        call for call in fake.calls if call[2] == "backfill_apk_set_links.preview_dynamic"
    ][0]
    assert "AND ds.package_name = %s" in preview[0]
    assert preview[1] == ("com.pinterest",)


def test_preview_static_scopes_through_app_version_package() -> None:
    fake = FakeCoreQueries()

    links._preview_static(fake, package="com.pinterest")

    preview = [
        call for call in fake.calls if call[2] == "backfill_apk_set_links.preview_static"
    ][0]
    assert "JOIN app_versions av_scope ON av_scope.id = sar.app_version_id" in preview[0]
    assert "JOIN apps app_scope ON app_scope.id = av_scope.app_id" in preview[0]
    assert "AND app_scope.package_name = %s" in preview[0]
    assert preview[1] == ("com.pinterest",)


def test_apply_dynamic_uses_package_scope_for_update_and_counts() -> None:
    fake = FakeCoreQueries()

    links._apply_dynamic(fake, package="com.pinterest")

    updates = [
        call for call in fake.calls if call[2] == "backfill_apk_set_links.apply_dynamic"
    ]
    assert len(updates) == 1
    assert "AND ds.package_name = %s" in updates[0][0]
    assert updates[0][1] == ("com.pinterest",)
    count_calls = [
        call for call in fake.calls if call[2] == "backfill_apk_set_links.scalar"
    ]
    assert all("AND package_name = %s" in call[0] for call in count_calls)
    assert all(call[1] == ("com.pinterest",) for call in count_calls)


def test_explicit_receipt_dir_writes_summary_json(tmp_path) -> None:
    receipt_dir = links._receipt_dir(str(tmp_path), apply=False)
    assert receipt_dir == tmp_path

    payload = {"apply": False, "dynamic": {"candidates": 0}}
    links._write_json(tmp_path / "summary.json", payload)

    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == payload
