from __future__ import annotations

import sys
from pathlib import Path


def _run_reporting_menu_once(monkeypatch) -> None:
    from scytaledroid.Reporting import menu as reporting_menu

    monkeypatch.setenv("SCYTALEDROID_ENABLE_LEGACY_PUBLICATION", "0")
    monkeypatch.setattr(
        reporting_menu,
        "fetch_tier1_status",
        lambda: {
            "schema_version": "0.0.0",
            "expected_schema": "0.0.0",
            "tier1_ready_runs": 0,
            "evidence_dataset_valid": 0,
            "evidence_dataset_packs": 0,
            "db_dynamic_sessions_dataset": 0,
            "pcap_valid_runs": 0,
            "pcap_total_runs": 0,
        },
    )
    monkeypatch.setattr(reporting_menu.prompt_utils, "get_choice", lambda *_a, **_k: "0")
    monkeypatch.setattr(reporting_menu.prompt_utils, "press_enter_to_continue", lambda: None)
    reporting_menu.reporting_menu()


def test_reporting_menu_does_not_import_publication_when_legacy_disabled(monkeypatch):
    before = {name for name in sys.modules if name.startswith("scytaledroid.Publication")}
    _run_reporting_menu_once(monkeypatch)
    after = {name for name in sys.modules if name.startswith("scytaledroid.Publication")}
    assert after == before


def test_reporting_menu_does_not_probe_publication_scripts_when_legacy_disabled(monkeypatch):
    touched: list[str] = []
    original_exists = Path.exists

    def _tracking_exists(path_obj: Path) -> bool:
        normalized = str(path_obj).replace("\\", "/")
        if "scripts/publication" in normalized:
            touched.append(normalized)
        return original_exists(path_obj)

    monkeypatch.setattr(Path, "exists", _tracking_exists)
    _run_reporting_menu_once(monkeypatch)
    assert touched == []

