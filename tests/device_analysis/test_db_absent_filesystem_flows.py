import builtins
import importlib
import sys


def _block_database_imports(monkeypatch):
    real_import = builtins.__import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        if str(name).startswith("scytaledroid.Database"):
            raise ImportError("blocked scytaledroid.Database import (test)")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded)


def test_harvest_scope_context_imports_without_db(monkeypatch):
    saved = {}
    for key in (
        "scytaledroid.Database.db_core.db_queries",
        "scytaledroid.Database.db_core.db_config",
    ):
        if key in sys.modules:
            saved[key] = sys.modules.pop(key)
    try:
        _block_database_imports(monkeypatch)

        scope_context = importlib.import_module("scytaledroid.DeviceAnalysis.harvest.scope_context")
        importlib.reload(scope_context)

        rows = scope_context.build_inventory_rows(
            [
                {
                    "package_name": "com.example.app",
                    "apk_paths": ["/data/app/com.example.app/base.apk"],
                    "split_count": 1,
                    "primary_path": "/data/app/com.example.app/base.apk",
                    "version_code": "1",
                    "version_name": "1.0",
                    "installer": "com.android.vending",
                }
            ]
        )
        assert rows and rows[0].package_name == "com.example.app"
    finally:
        sys.modules.update(saved)


def test_harvest_runner_imports_without_db(monkeypatch):
    saved = {}
    for key in (
        "scytaledroid.Database.db_func.harvest.apk_repository",
        "scytaledroid.Database.db_core.db_config",
        "scytaledroid.Database.db_utils.diagnostics",
    ):
        if key in sys.modules:
            saved[key] = sys.modules.pop(key)
    try:
        _block_database_imports(monkeypatch)

        runner = importlib.import_module("scytaledroid.DeviceAnalysis.harvest.runner")
        importlib.reload(runner)

        # Sanity: module import should succeed even if DB is absent.
        assert hasattr(runner, "execute_harvest")
    finally:
        sys.modules.update(saved)


def test_harvest_rules_imports_without_db(monkeypatch):
    saved = {}
    for key in ("scytaledroid.Database.db_core.db_queries",):
        if key in sys.modules:
            saved[key] = sys.modules.pop(key)
    try:
        _block_database_imports(monkeypatch)

        rules = importlib.import_module("scytaledroid.DeviceAnalysis.harvest.rules")
        importlib.reload(rules)

        assert isinstance(rules.GOOGLE_ALLOWLIST, set)
    finally:
        sys.modules.update(saved)
