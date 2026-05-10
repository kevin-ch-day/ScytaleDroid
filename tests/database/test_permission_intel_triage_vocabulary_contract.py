"""S1.5: Pin Scytale Permission Intel triage/queue vocabulary vs documented PI contract.

Documented PI triage superset (maintain when Erebus contract / operator SQL adds states):
- ``docs/database/permission_intel_scytaledroid_s1_5_classifier_contract.md``
- Erebus ``docs/data/android_permissions_schema_contract.md``
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "scytaledroid"
    / "StaticAnalysis"
    / "persistence"
    / "permissions_db.py"
)
_SPEC = importlib.util.spec_from_file_location("_permissions_db_contract", _MODULE_PATH)
assert _SPEC and _SPEC.loader
permissions_db = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(permissions_db)

# Dict-unknown ledger statuses named in Erebus contract docs + common operator SQL.
PI_DOCUMENTED_DICT_UNKNOWN_TRIAGE_STATUSES: frozenset[str] = frozenset(
    {
        "resolved_aosp",
        "resolved_oem",
        "app_defined",
        "gms_known",
        "launcher_ecosystem",
        "malformed",
        "malicious_dga",
        "brand_spoof",
        "new",
        "in_review",
        "oem_candidate",
        "aosp_missing",
        "suspicious_token",
    }
)

# Queue row lifecycle (android_permission_dict_queue.status); Scytale default only.
PI_DOCUMENTED_QUEUE_ROW_WORKFLOW_STATUSES: frozenset[str] = frozenset({"queued"})

# Illustrative queue_action verbs from Erebus queue-apply / API tests (not exhaustive).
PI_ECOSYSTEM_QUEUE_ACTION_EXAMPLES_FROM_EREBUS: frozenset[str] = frozenset(
    {
        "aosp",
        "apply",
        "approve",
        "accept",
        "defer",
        "skip",
        "reject",
        "rejected",
        "google",
        "app_defined",
        "gms",
    }
)


def _scytale_emitted_dict_unknown_triage_statuses() -> frozenset[str]:
    """Every literal triage_status Scytale static may pass to upsert_unknown."""
    return frozenset(
        {
            "malformed",
            "app_defined",
            "oem_candidate",
            "aosp_missing",
            "new",
        }
    )


def _scytale_queue_action_from_static() -> frozenset[str]:
    """queue_action literals emitted by static ``permissions_db`` (not governance CSV import)."""
    return frozenset({"aosp"})


def _scytale_queue_source_system() -> frozenset[str]:
    return frozenset({"static-analysis"})


def test_scytale_dict_unknown_triage_subset_of_pi_documented_vocabulary() -> None:
    emitted = _scytale_emitted_dict_unknown_triage_statuses()
    missing = emitted - PI_DOCUMENTED_DICT_UNKNOWN_TRIAGE_STATUSES
    assert not missing, (
        "Scytale emits triage_status values not covered by PI_DOCUMENTED_DICT_UNKNOWN_TRIAGE_STATUSES "
        f"in this module — update constants + S1.5 doc: {sorted(missing)}"
    )


def test_scytale_emitted_triage_vocabulary_is_stable() -> None:
    """Guards against silent string drift in permissions_db."""
    assert _scytale_emitted_dict_unknown_triage_statuses() == frozenset(
        {"malformed", "app_defined", "oem_candidate", "aosp_missing", "new"}
    )


def test_permissions_db_malformed_prefixes_stable() -> None:
    assert permissions_db._MALFORMED_PREFIXES == ("android.premission.",)


def test_permissions_db_ghostaosp_broadcast_perms_stable() -> None:
    assert permissions_db._GHOSTAOSP_BROADCAST_PERMS == {
        "android.permission.BROADCAST_PACKAGE_ADDED",
        "android.permission.BROADCAST_PACKAGE_REPLACED",
        "android.permission.BROADCAST_PACKAGE_CHANGED",
    }


def test_queue_action_aosp_is_erbus_compatible() -> None:
    """Static path emits ``aosp`` — matches Erebus ``permission_queue_apply.class_action_map``."""
    scytale_actions = _scytale_queue_action_from_static()
    assert scytale_actions == {"aosp"}
    assert scytale_actions <= PI_ECOSYSTEM_QUEUE_ACTION_EXAMPLES_FROM_EREBUS


def test_insert_queue_default_status_is_documented(monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.Database.db_core import permission_intel as intel_mod
    from scytaledroid.Database.db_func.permissions import permission_dicts

    payload = {
        "permission_string": "android.permission.FAKE_MISSING",
        "queue_action": "aosp_promote",
        "triage_status": "aosp_missing",
        "requested_by": "static-analysis",
        "source_system": "static-analysis",
    }
    captured: dict = {}

    def _fake_insert(params: dict) -> None:
        captured.clear()
        captured.update(params)

    monkeypatch.setattr(intel_mod, "insert_permission_queue", _fake_insert)
    permission_dicts.insert_queue(payload)
    assert captured.get("queue_action") == "aosp"
    assert captured.get("status") == "queued"
    assert captured["status"] in PI_DOCUMENTED_QUEUE_ROW_WORKFLOW_STATUSES


def test_source_system_static_analysis_stable() -> None:
    assert _scytale_queue_source_system() == {"static-analysis"}
