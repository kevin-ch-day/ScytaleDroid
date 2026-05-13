"""Regression tests for catalog hygiene scripts (no live DB required)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = [pytest.mark.gate, pytest.mark.tier3]

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_apply_module():
    path = _REPO_ROOT / "scripts" / "db" / "apply_app_display_name_overrides.py"
    spec = importlib.util.spec_from_file_location("_apply_app_display_name_overrides_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_report_module():
    path = _REPO_ROOT / "scripts" / "db" / "report_app_label_hygiene.py"
    spec = importlib.util.spec_from_file_location("_report_app_label_hygiene_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_apply_csv_duplicate_package_last_row_wins(tmp_path: Path) -> None:
    mod = _load_apply_module()
    csv_path = tmp_path / "overrides.csv"
    csv_path.write_text(
        "package_name,display_name,source,notes\n"
        "com.example.app,FirstName,x,\n"
        "com.example.app,SecondName,x,\n",
        encoding="utf-8",
    )
    rows = mod._load_rows(csv_path)
    assert len(rows) == 1
    pkg, disp, _src, _notes = rows[0]
    assert pkg == "com.example.app"
    assert disp == "SecondName"


def test_report_override_csv_duplicate_last_row_wins(tmp_path: Path) -> None:
    mod = _load_report_module()
    csv_path = tmp_path / "overrides.csv"
    csv_path.write_text(
        "package_name,display_name,source,notes\n"
        "com.example.app,Alpha,x,\n"
        "com.example.app,Beta,x,\n",
        encoding="utf-8",
    )
    m = mod._load_override_csv(csv_path)
    assert m["com.example.app"][1] == "Beta"


def test_apply_csv_duplicate_case_insensitive_collapses_to_one(tmp_path: Path) -> None:
    mod = _load_apply_module()
    csv_path = tmp_path / "overrides.csv"
    csv_path.write_text(
        "package_name,display_name,source,notes\n"
        "COM.EXAMPLE.APP,Early,x,\n"
        "com.example.app,Late,x,\n",
        encoding="utf-8",
    )
    rows = mod._load_rows(csv_path)
    assert len(rows) == 1
    assert rows[0][0] == "com.example.app"
    assert rows[0][1] == "Late"
