from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Publication.app_category_policy import (
    APP_CATEGORY_POLICY,
    PUBLICATION_APP_ORDER,
    RETIRED_PUBLICATION_CATEGORY_LABELS,
    TAXONOMY_VERSION,
    app_category,
    app_category_policy_rows,
    app_display_name,
)
from scytaledroid.Publication.contract_inputs import load_publication_contracts
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile


def test_publication_taxonomy_uses_current_primary_function_labels() -> None:
    assert app_category("com.snapchat.android") == "Social Media"
    assert app_category("com.linkedin.android") == "Professional Networking"
    assert app_category("com.zhiliaoapp.musically") == "Social Media"
    assert app_category("com.facebook.orca") == "Messaging"
    assert app_display_name("com.facebook.orca") == "Facebook Msg"


def test_publication_taxonomy_rows_do_not_emit_retired_labels() -> None:
    rows = app_category_policy_rows()
    assert len(rows) == 15
    assert TAXONOMY_VERSION == "integrated-primary-function-v1"
    categories = {row["category"] for row in rows}
    assert not categories & RETIRED_PUBLICATION_CATEGORY_LABELS
    assert categories == {"Messaging", "News", "Professional Networking", "Social Media"}
    assert {row["taxonomy_version"] for row in rows} == {TAXONOMY_VERSION}


def test_tracked_publication_contracts_match_current_taxonomy() -> None:
    contracts = load_publication_contracts(fail_closed=True)
    assert contracts.package_order == PUBLICATION_APP_ORDER
    assert contracts.display_name_by_package == {
        pkg: APP_CATEGORY_POLICY[pkg].app_display_name for pkg in PUBLICATION_APP_ORDER
    }

    repo_contracts = Path("scytaledroid/Publication/contracts")
    display_json = json.loads((repo_contracts / "display_name_map.json").read_text(encoding="utf-8"))
    order_json = json.loads((repo_contracts / "app_ordering.json").read_text(encoding="utf-8"))
    assert order_json == PUBLICATION_APP_ORDER
    assert display_json == contracts.display_name_by_package


def test_runtime_ml_display_labels_match_current_taxonomy() -> None:
    assert ml_parameters_profile.DISPLAY_NAME_BY_PACKAGE == {
        pkg: APP_CATEGORY_POLICY[pkg].app_display_name for pkg in PUBLICATION_APP_ORDER
    }
