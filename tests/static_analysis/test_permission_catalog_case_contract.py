from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.permissions.catalog import (
    PermissionCatalog,
    PermissionDescriptor,
)


def test_canonical_catalog_lookup_is_exact_case_when_requested() -> None:
    canonical = "android.permission.INTERNET"
    catalog = PermissionCatalog(
        entries={canonical: PermissionDescriptor(name=canonical, protection=("normal",))},
        version="v1",
        case_sensitive=True,
    )

    assert catalog.describe(canonical) is not None
    assert catalog.describe(canonical.lower()) is None


def test_legacy_catalog_lookup_remains_case_insensitive_by_default() -> None:
    canonical = "android.permission.INTERNET"
    catalog = PermissionCatalog(
        entries={canonical: PermissionDescriptor(name=canonical, protection=("normal",))},
        version="legacy",
    )

    assert catalog.describe(canonical.lower()) is not None
