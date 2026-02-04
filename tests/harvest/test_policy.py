"""Minimal regression checks for harvest policy and scope metadata."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.harvest import planner, rules, scope
from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow


def _row(
    package_name: str,
    app_label: str,
    *,
    primary_path: str,
    installer: str = "com.android.vending",
    profile: str | None = None,
) -> InventoryRow:
    profile_key = profile.upper() if profile else None
    return InventoryRow(
        raw={},
        package_name=package_name,
        app_label=app_label,
        installer=installer,
        category=None,
        primary_path=primary_path,
        profile_key=profile_key,
        profile=profile,
        version_name=None,
        version_code=None,
        apk_paths=[primary_path],
        split_count=1,
    )


def test_non_root_policy_blocks_system_paths():
    rows = [
        _row(
            "com.example.userapp",
            "User App",
            primary_path="/data/app/com.example.userapp/base.apk",
        ),
        _row(
            "com.example.systemapp",
            "System App",
            primary_path="/system/app/SystemApp/SystemApp.apk",
        ),
    ]

    plan = planner.build_harvest_plan(rows, include_system_partitions=False)
    pkg_map = {pkg.inventory.package_name: pkg for pkg in plan.packages}

    assert "com.example.userapp" in pkg_map
    assert pkg_map["com.example.userapp"].artifacts, "user app should have artifacts to pull"

    assert "com.example.systemapp" in pkg_map
    assert pkg_map["com.example.systemapp"].skip_reason == "policy_non_root"


def test_scope_metadata_counts_social_subset():
    # Two social candidates: one user-scope, one system-scope (filtered).
    social_user = _row(
        "com.example.social1",
        "Social One",
        primary_path="/data/app/social1/base.apk",
        profile="Social",
    )
    social_system = _row(
        "com.example.social2",
        "Social Two",
        primary_path="/system/app/social2/base.apk",
        profile="Social",
    )
    other_app = _row(
        "com.example.other",
        "Other App",
        primary_path="/data/app/other/base.apk",
        profile="Shopping",
    )

    category_groups = {
        "Social": [social_user, social_system],
        "Shopping": [other_app],
    }
    allow = set(rules.GOOGLE_ALLOWLIST)

    selection = scope._scope_category_subset(  # type: ignore[attr-defined]
        category_groups,
        allow,
        {"Social"},
        label="Social",
    )
    assert selection is not None
    meta = selection.metadata
    assert meta.get("candidate_count") == 2
    # One user app should survive; the system-scoped one is filtered by policy.
    assert meta.get("selected_count") == 1
    excluded = meta.get("excluded_counts") or {}
    # Expect at least one policy exclusion
    assert sum(int(v) for v in excluded.values()) >= 1
