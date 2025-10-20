from scytaledroid.StaticAnalysis.modules.permissions.catalog import (
    classify_permission,
    load_permission_catalog,
)


def test_load_permission_catalog_returns_known_permissions():
    catalog = load_permission_catalog()
    descriptor = catalog.describe("android.permission.INTERNET")
    assert descriptor is not None
    assert "normal" in descriptor.protection


def test_classify_permission_prefers_manifest_levels():
    catalog = load_permission_catalog()
    strength_catalog, _ = classify_permission(
        "android.permission.INTERNET",
        catalog=catalog,
        manifest_levels={},
    )
    # Catalog classifies INTERNET as normal → weak guard.
    assert strength_catalog in {"weak", "unknown"}

    strength_override, levels = classify_permission(
        "android.permission.INTERNET",
        catalog=catalog,
        manifest_levels={"android.permission.INTERNET": ("signature",)},
    )
    assert strength_override == "signature"
    assert "signature" in levels
