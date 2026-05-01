from scytaledroid.Database.db_queries import views
from scytaledroid.Database.db_queries import (
    views_admin,
    views_bridge,
    views_dynamic,
    views_inventory,
    views_permission,
    views_static,
    views_web,
)


def test_views_facade_exports_union_of_domain_modules():
    domain_modules = (
        views_inventory,
        views_static,
        views_dynamic,
        views_web,
        views_permission,
        views_bridge,
        views_admin,
    )
    expected = []
    for module in domain_modules:
        expected.extend(module.__all__)

    assert views.__all__ == expected


def test_views_facade_symbols_exist_and_are_sql_strings():
    for symbol in views.__all__:
        value = getattr(views, symbol)
        assert isinstance(value, str)
        assert "CREATE OR REPLACE VIEW" in value
