# Repository Health Report

## Executive summary
- The main CLI now lazily imports heavy submenu modules, cutting import latency from ~0.94s to ~0.17s and improving interactive startup responsiveness.【F:main.py†L5-L158】【1929be†L1-L4】【d7c1ae†L1-L7】
- Static-analysis menu modules still perform eager imports of the entire pipeline, string engine, and repository helpers, adding ~0.57s of import overhead before a user even chooses a scan.【F:scytaledroid/StaticAnalysis/cli/menu.py†L13-L45】【9b238f†L1-L4】
- Logging setup eagerly creates the `logs/` directory and configures handlers at import-time, introducing filesystem side effects and work even when logging is unused.【F:scytaledroid/Utils/LoggingUtils/logging_core.py†L12-L62】
- Watchlist resolution executes repeated `IN (...)` queries without deduplicating package names, amplifying database load for large watchlists and allowing simple memoisation wins.【F:scytaledroid/DeviceAnalysis/watchlist_manager.py†L124-L140】
- MySQL connections are opened synchronously with credentials pulled from `db_config` and no TLS/pooling controls, which warrants a security review and hardened defaults.【F:scytaledroid/Database/db_core/db_engine.py†L21-L88】
- Added `scripts/check_repo_health.py` plus a `pyproject.toml` baseline so ruff, pyupgrade, and mypy can run consistently across CI and developer machines.【F:scripts/check_repo_health.py†L1-L159】【F:pyproject.toml†L1-L24】

## Prioritized findings
### P0 (must address soon)
- **CLI import latency**: although `main.py` now defers submenu imports, `StaticAnalysis` CLI still loads the full pipeline on import; split the menu into a thin dispatcher that lazy-loads detectors/pipeline code only when an option is chosen.【F:scytaledroid/StaticAnalysis/cli/menu.py†L13-L45】【9b238f†L1-L4】

### P1 (high-value improvements)
- **Logging side effects**: move `LOG_DIR.mkdir` and handler creation behind an explicit bootstrap routine so library consumers do not incur filesystem writes at import-time.【F:scytaledroid/Utils/LoggingUtils/logging_core.py†L12-L62】
- **Watchlist queries**: dedupe package names before building SQL placeholders and cache recent lookups by slug to avoid redundant round-trips when navigating the menu.【F:scytaledroid/DeviceAnalysis/watchlist_manager.py†L124-L140】
- **Database hardening**: extend `db_engine.py` to accept SSL parameters, enforce connection timeouts, and scrub credentials from error messages to guard against leakage when MySQL rejects a login.【F:scytaledroid/Database/db_core/db_engine.py†L21-L88】

### P2 (medium-term)
- **Static-analysis metadata drift**: severity labels, profile lists, and menu option definitions live in multiple modules; centralise them into a single constants module to avoid divergence when new detectors are added.【F:scytaledroid/StaticAnalysis/cli/menu.py†L49-L80】
- **Health tooling adoption**: wire `scripts/check_repo_health.py` into CI and extend it with optional import-profiler output so regressions in import latency are caught automatically.【F:scripts/check_repo_health.py†L1-L159】

## Fast wins
- Add a tiny helper that caches `_resolve_app_names` results for the current session to avoid repeat SQL queries when paging through watchlists.【F:scytaledroid/DeviceAnalysis/watchlist_manager.py†L124-L140】
- Replace the inline `list` construction in `_resolve_app_names` with `dict.fromkeys` or a `set` to trim duplicate placeholders before issuing SQL.【F:scytaledroid/DeviceAnalysis/watchlist_manager.py†L124-L140】
- Guard `logging_core.LOG_DIR.mkdir` behind `if not LOG_DIR.exists()` or move it into `configure_third_party_loggers` to prevent redundant directory creation on every import.【F:scytaledroid/Utils/LoggingUtils/logging_core.py†L12-L62】
- Extend `scripts/check_repo_health.py`’s import target list with `scytaledroid.StaticAnalysis.cli.menu` so slowdowns in the static-analysis workflow are surfaced quickly.【F:scripts/check_repo_health.py†L19-L63】
- Feed the new ruff configuration into CI (`ruff check` + `ruff format --check`) to standardise lint output across contributors.【F:pyproject.toml†L1-L14】

## Larger refactors
- **Static-analysis CLI modularisation**: split `scytaledroid/StaticAnalysis/cli/menu.py` into a light menu wrapper and separate executor modules so CLI startup stays snappy while heavy detector logic loads lazily.【F:scytaledroid/StaticAnalysis/cli/menu.py†L13-L45】
- **Logging subsystem consolidation**: unify `logging_core.py`, `logging_engine.py`, and `logging_utils.py` under a single configuration module that supports structured logging, loguru integration, and consistent filtering without cross-import side effects.【F:scytaledroid/Utils/LoggingUtils/logging_core.py†L12-L62】【F:scytaledroid/Utils/LoggingUtils/logging_engine.py†L1-L120】【F:scytaledroid/Utils/LoggingUtils/logging_utils.py†L1-L38】
- **Database abstraction refresh**: wrap MySQL access in context managers with pooled connections and explicit transaction boundaries so long-running static/dynamic analysis jobs do not exhaust the connector or leak connections.【F:scytaledroid/Database/db_core/db_engine.py†L21-L88】
