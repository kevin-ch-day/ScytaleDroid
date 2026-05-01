# Repo Ownership Map

Read-only ownership map for the current CLI repo and deployed Web repo. This
is a navigation aid for maintenance work, not a contract for refactoring.

## CLI / Main Repo

### `scytaledroid/DeviceAnalysis`

| Field | Notes |
| --- | --- |
| Owns | Device inventory, APK harvest, APK library management, device menus, scope planning, artifact storage helpers, ADB-facing collection flows. |
| Status | `active` |
| Main entrypoints | `main.py` → `handle_device`; `scytaledroid/DeviceAnalysis/device_hub_menu.py`; `device_menu/menu.py`; `harvest/runner.py`; `inventory/runner.py`; `services/static_scope_service.py`. |
| Common tasks that should start here | Inventory capture bugs, harvest scope bugs, APK retention/storage issues, ADB package collection issues, app/profile scoping for static analysis. |
| Common tasks that should not start here | Static detector logic, dynamic capture orchestration, DB schema ownership, Web rendering. |
| Related tests / smoke checks | `tests/device_analysis/*`, `tests/harvest/*`, `tests/inventory/*`; `./run.sh` → Device Inventory & Harvest; scripts under `scripts/device_analysis/`. |
| High-risk / large files | `harvest/summary.py` (large UX/output surface), `harvest/runner.py`, `harvest/scope.py`, `device_menu/dashboard.py`. These files combine collection logic and operator presentation, so changes ripple widely. |

### `scytaledroid/StaticAnalysis`

| Field | Notes |
| --- | --- |
| Owns | Static APK scan orchestration, detector pipeline, findings assembly, static persistence flow, CLI rendering for static sessions, static risk/permission logic. |
| Status | `active` |
| Main entrypoints | `main.py` → `handle_static`; `StaticAnalysis/cli/run.py`; `StaticAnalysis/services/static_service.py`; `cli/flows/run_dispatch.py`; `cli/persistence/run_summary.py`; `core/pipeline.py`. |
| Common tasks that should start here | Detector bugs, session finalization behavior, static findings/risk persistence, static run UX, score explanation and risk scoring logic. |
| Common tasks that should not start here | Device inventory/harvest bugs, Web page rendering, permission-intel DB cutover logic, dynamic telemetry capture. |
| Related tests / smoke checks | `tests/static_analysis/*`, `tests/persistence/*`, `tests/integration/test_persist_run_summary.py`, `tests/database/test_static_*`; full static run via `./run.sh`. |
| High-risk / large files | `cli/execution/results.py`, `cli/persistence/run_summary.py`, `cli/flows/run_dispatch.py`, `modules/string_analysis/extractor.py`, `modules/permissions/audit.py`. These are large, central orchestration surfaces. |

### `scytaledroid/DynamicAnalysis`

| Field | Notes |
| --- | --- |
| Owns | Dynamic session orchestration, guided runs, runtime evidence packs, PCAP capture/indexing, dynamic persistence, anomaly/ML preparation, dynamic menus and datasets. |
| Status | `active` |
| Main entrypoints | `main.py` → `handle_dynamic`; `DynamicAnalysis/menu.py`; `run_dynamic_analysis.py`; `core/orchestrator.py`; `controllers/guided_run.py`; `storage/persistence.py`; `tools/freeze_gate.py`. |
| Common tasks that should start here | Dynamic run bugs, freeze/dataset readiness, PCAP and telemetry issues, evidence-pack rebuild problems, dynamic run menu flow issues. |
| Common tasks that should not start here | Static detector changes, Web app page fixes, base DB schema ownership, device harvest rules. |
| Related tests / smoke checks | `tests/dynamic/*`, `tests/analysis/*`, `tests/ml/*`; scripts under `scripts/dynamic/`; dynamic menu flows in `./run.sh`. |
| High-risk / large files | `menu.py`, `ml/evidence_pack_ml_orchestrator.py`, `ml/artifact_bundle_writer.py`, `controllers/guided_run.py`, `pcap/dataset_tracker.py`, `core/orchestrator.py`. These are large orchestration files with many downstream effects. |

### `scytaledroid/Database`

| Field | Notes |
| --- | --- |
| Owns | DB engine/session layer, schema manifest, SQL/view definitions, DB tools, schema gates, maintenance utilities, compatibility boundaries, summary surfaces, permission-intel cutover helpers. |
| Status | `active` with `transitional` subareas (`db_utils/static_reconcile.py`, bridge posture helpers, some legacy views/tables). |
| Main entrypoints | `db_core/db_engine.py`; `db_queries/schema_manifest.py`; `db_queries/views.py`; `db_utils/database_menu.py`; `tools/bootstrap.py`; `tools/db_status.py`; `db_core/permission_intel.py`; `scripts/db/recreate_web_consumer_views.py`; `docs/maintenance/database_governance_runbook.md`. |
| Common tasks that should start here | Schema/view changes, read-model additions, DB cleanup/pruning, schema gates, permission-intel split, bridge freeze/deprecation, diagnostics around persistence surfaces. |
| Common tasks that should not start here | Static detector semantics, dynamic orchestration logic, PHP rendering, publication formatting. |
| Related tests / smoke checks | `tests/database/*`, `tests/db_utils/*`, `tests/db/*`, `tests/gates/test_static_gate.py`; DB tools menu in `./run.sh`; `python -m py_compile` for DB modules. |
| High-risk / large files | `db_queries/views.py` (largest DB contract file), `db_utils/menus/health_checks.py`, `db_utils/menu_actions.py`, `db_utils/reset_static.py`, `db_utils/static_reconcile.py`, `db_core/db_engine.py`. These are central contract and maintenance surfaces. |

### `scytaledroid/Reporting` and `scytaledroid/Publication`

| Field | Notes |
| --- | --- |
| Owns | Export/readiness services, publication bundle generation, numbers/QA services, research-oriented reporting, profile export workflows, contract-driven publication inputs. |
| Status | `active` with some `transitional` script wrappers outside the package. |
| Main entrypoints | `Reporting/menu.py`; `Reporting/menu_actions.py`; service modules listed in `docs/supported_entrypoints.md`; `Publication/contract_inputs.py`; `Publication/canonical_bundle_writer.py`. |
| Common tasks that should start here | Publication/export bugs, readiness/status summaries, profile export issues, scientific QA outputs, reporting layer consistency. |
| Common tasks that should not start here | Core static persistence, ADB collection, raw dynamic telemetry storage, Web route/controller fixes. |
| Related tests / smoke checks | `tests/analysis/*`, `tests/ml/*`, publication scripts under `scripts/publication/`, `scripts/operator/run_profile_v3_demo.sh`; docs in `docs/contracts/` and `docs/maintenance/`. |
| High-risk / large files | `Reporting/services/publication_exports_service.py`, `Reporting/menu_actions.py`, `Publication/canonical_bundle_writer.py`. These are long, high-fanout export surfaces. |

### `scripts`

| Field | Notes |
| --- | --- |
| Owns | Repo-local automation, operator helpers, gates, maintenance wrappers, profile tools, publication wrappers, static-analysis helpers. |
| Status | Mostly `transitional`; some scripts are supported wrappers, many are best-effort utilities. |
| Main entrypoints | See `docs/supported_entrypoints.md`; common wrappers include `scripts/publication/*`, `scripts/operator/*`, `scripts/static_analysis/*`, `scripts/profile_tools/*`. |
| Common tasks that should start here | One-off operator automation, CI-like gates, audits, support tooling around app-owned services. |
| Common tasks that should not start here | Core business logic changes that belong in `scytaledroid/`; schema design; long-term API decisions. |
| Related tests / smoke checks | `tests/gates/test_scripts_help_contract.py`, `tests/gates/test_no_new_legacy_term_leakage_docs_and_scripts.py`; run script `--help` or documented demo scripts. |
| High-risk / large files | Script drift is the main risk. Changes here often bypass app-owned service boundaries if not disciplined. |

### `migrations`

| Field | Notes |
| --- | --- |
| Owns | No active top-level `migrations/` directory exists in this repo. Historical SQL lives under `scytaledroid/Database/db_scripts/`. |
| Status | `legacy / absent` |
| Main entrypoints | `scytaledroid/Database/db_scripts/run_id_migration.sql`; `static_run_audit.py`. |
| Common tasks that should start here | Very targeted historical DB recovery or one-off migration review. |
| Common tasks that should not start here | Normal schema evolution; new schema work should start in `db_queries/schema_manifest.py` and related DB modules. |
| Related tests / smoke checks | None dedicated at the top-level; use DB snapshot/audit tooling. |
| High-risk / large files | SQL/script drift from current schema manifest. Treat as historical tooling, not live contract. |

### `profiles`

| Field | Notes |
| --- | --- |
| Owns | Frozen profile/catalog inputs, especially profile v3 app catalog and related reference inputs. |
| Status | `active` |
| Main entrypoints | `profiles/profile_v3_app_catalog.json`; profile tooling under `scripts/profile_tools/`; dynamic profile services under `DynamicAnalysis/services/`. |
| Common tasks that should start here | Catalog drift, profile membership review, profile validation, capture/export readiness checks. |
| Common tasks that should not start here | Static detector logic, DB cleanup, Web route changes. |
| Related tests / smoke checks | `scripts/profile_tools/*`; `tests/dynamic/test_profile_v3_*`; `tests/ml/test_freeze_cohort_policy.py`. |
| High-risk / large files | `profile_v3_app_catalog.json` is a critical frozen input. Treat changes as data-contract changes. |

### `docs`

| Field | Notes |
| --- | --- |
| Owns | Architecture notes, contracts, runbooks, phase plans, ownership matrices, maintenance audits, supported entrypoint documentation. |
| Status | `active`; some older docs are `transitional` or historical snapshots. |
| Main entrypoints | `docs/runbook.md`; `docs/supported_entrypoints.md`; `docs/database/contract_audit_v1_3.md`; `docs/maintenance/*`. |
| Common tasks that should start here | Phase planning, contract lookup, ownership lookup, operator workflow clarification, documenting accepted behavior. |
| Common tasks that should not start here | Determining actual runtime truth when code and docs differ; code should win. |
| Related tests / smoke checks | Doc gate tests under `tests/gates/*`; phase docs and ownership matrices are referenced during maintenance work. |
| High-risk / large files | Ownership and phase docs can drift from code. `docs/database/schema_domain_inventory.md` and `ownership_matrix_v1_3.csv` are dense and should be updated carefully. |

### `tests`

| Field | Notes |
| --- | --- |
| Owns | Unit, integration, DB, gate, dynamic, device-analysis, ML, and API regression coverage. |
| Status | `active` |
| Main entrypoints | `pytest`; targeted suites by domain (`tests/database/*`, `tests/device_analysis/*`, `tests/static_analysis/*`, `tests/dynamic/*`, `tests/gates/*`). |
| Common tasks that should start here | Finding regression coverage, identifying expected contracts, selecting smoke checks before/after changes. |
| Common tasks that should not start here | Using tests as the first source of architecture intent when code and docs disagree; verify in code too. |
| Related tests / smoke checks | This folder is the smoke-check source. Use narrow subsets for the module being touched. |
| High-risk / large files | `tests/conftest.py` affects broad test behavior; gate tests can fail due to wording or docs, not only runtime behavior. |

### Generated / local areas: `output`, `evidence`, `logs`, `data`

| Field | Notes |
| --- | --- |
| Owns | Generated artifacts, evidence packs, audits, session outputs, logs, and local data snapshots. |
| Status | `generated` / local-state |
| Main entrypoints | Written by CLI flows and scripts; read by audits, exports, and some rebuild/reporting helpers. |
| Common tasks that should start here | Inspecting the result of a run, troubleshooting persisted artifacts, validating evidence-pack outputs, reviewing audits. |
| Common tasks that should not start here | Treating local generated state as the source of truth for schema design or application logic. |
| Related tests / smoke checks | `tests/dynamic/*` and publication/export tests may expect generated artifact layouts indirectly; many scripts under `scripts/operator/` and `scripts/publication/` read these directories. |
| High-risk / large files | These can become large quickly and are environment-specific. Avoid baking assumptions about local generated contents into core code. |

## Web Repo (`/var/www/html/ScytaleDroid-Web`)

### `pages`

| Field | Notes |
| --- | --- |
| Owns | Route controllers for the read-only PHP UI. |
| Status | `active` with a mix of primary pages and legacy redirects/routes. |
| Main entrypoints | `/index.php` → `pages/index.php`; direct route files under `pages/`. |
| Common tasks that should start here | Page-level layout, filter UX, page-specific empty states, page-to-page linking, route redirects. |
| Common tasks that should not start here | Shared query logic, parameter normalization, shared score/session formatting. Those belong in `database/db_lib` and `lib/`. |
| Related tests / smoke checks | `php -l` on changed files; manual browser checks; no dedicated PHP test suite is present. |
| High-risk / large files | `pages/app_report.php`, `pages/findings.php`, `pages/permissions.php`, `pages/dynamic_run.php`. These are larger page controllers with mixed query/render responsibilities. |

### App-level pages

Included pages:
- `app_report.php`
- `app_findings.php`
- `app_permissions.php`
- `app_components.php`
- `app_strings.php`
- `app_dynamic.php`

| Field | Notes |
| --- | --- |
| Owns | One-app triage and drilldown surfaces. |
| Status | `active` |
| Main entrypoints | Usually reached from `apps.php` / `index.php`; shared context comes from `lib/app_detail.php` and `_partials/session_picker.php`. |
| Common tasks that should start here | App triage behavior, tab navigation, summary vs detail discipline, app-level empty states, app-level session behavior. |
| Common tasks that should not start here | Fleet-wide aggregations, base query/view definitions, score formatter changes, or route policy changes affecting multiple pages. |
| Related tests / smoke checks | `php -l`; manual app navigation through `app_report.php` and tab pages; DB-backed smoke via localhost. |
| High-risk / large files | `app_report.php` is the main high-risk page because it is the official landing page and can easily become a catch-all. `app_components.php` is currently provider-first and should be labeled honestly. |

### Fleet-level pages

Included pages:
- `index.php`
- `apps.php`
- `findings.php`
- `findings_group.php`
- `components.php`
- `permissions.php`
- `run_health.php`
- `dynamic.php`
- `dynamic_run.php`

| Field | Notes |
| --- | --- |
| Owns | Cross-app discovery, fleet triage, runtime run browsing, and health/trust surfaces. |
| Status | `active` |
| Main entrypoints | `pages/index.php`; direct links from sidebar; some pages deep-link into app-level pages. |
| Common tasks that should start here | Fleet filters, explorer drilldowns, run-health filtering, provider/permission pattern discovery, dynamic run review. |
| Common tasks that should not start here | App-session selection logic, shared rendering helpers, DB query templates. |
| Related tests / smoke checks | `php -l`; manual navigation with sidebar open; verify filters and page load against live DB. |
| High-risk / large files | `findings.php`, `permissions.php`, `dynamic_run.php`, `run_health.php`. They sit close to read-model and trust semantics. |

### Legacy routes

Included pages:
- `view_app.php`
- `android_permissions.php`
- `diag.php`

| Field | Notes |
| --- | --- |
| Owns | Redirect compatibility (`view_app.php`, `android_permissions.php`) and a maintenance/diagnostics page (`diag.php`). |
| Status | `legacy` for redirects; `diagnostics` for `diag.php` |
| Main entrypoints | Old bookmarks or manual diagnostics. |
| Common tasks that should start here | Redirect cleanup, explicit legacy messaging, maintenance-only diagnostics. |
| Common tasks that should not start here | New analyst-facing features. |
| Related tests / smoke checks | Manual redirect verification; `diag.php` should remain trusted/localhost-only in practice. |
| High-risk / large files | `diag.php` is sensitive because it exposes diagnostics; do not turn it into a primary analyst surface. |

### `lib`

| Field | Notes |
| --- | --- |
| Owns | Shared page helpers: request guards, rendering helpers, pagination, app-detail context, header/footer/sidebar framing. |
| Status | `active` |
| Main entrypoints | `lib/app_detail.php`; `lib/guards.php`; `lib/render.php`; `lib/header.php`; `lib/sidebar_navigation.php`. |
| Common tasks that should start here | Shared score/session rendering, shared request validation, shared app-context logic, page layout framing. |
| Common tasks that should not start here | Page-specific SQL or one-off feature queries. |
| Related tests / smoke checks | `php -l`; manual navigation across multiple pages using the same context. |
| High-risk / large files | `render.php` and `app_detail.php` are high-risk because they centralize score and session behavior. |

### `database/db_lib`

| Field | Notes |
| --- | --- |
| Owns | Web query templates and feature functions: SQL string library, query execution helpers, DB-backed page data functions. |
| Status | `active` |
| Main entrypoints | `database/db_lib/db_queries.php`; `database/db_lib/db_func.php`; `database/db_lib/db_utils.php`. |
| Common tasks that should start here | Adding or hardening page read models, shared query filters, DB-backed page helper functions, pagination/query behavior. |
| Common tasks that should not start here | HTML rendering, request guard behavior, page route decisions. |
| Related tests / smoke checks | `php -l`; manual page load against live DB; compare to expected `v_web_*` view contracts. |
| High-risk / large files | `db_func.php` and `db_queries.php` are the heaviest Web DB files and are central to read-model drift. |

### `database/db_core`

| Field | Notes |
| --- | --- |
| Owns | PDO engine and local DB credential/config loading for the Web app. |
| Status | `active` |
| Main entrypoints | `database/db_core/db_engine.php`; `database/db_core/db_config.php`. |
| Common tasks that should start here | Connection handling, credential source behavior, read-only DB engine fixes. |
| Common tasks that should not start here | Feature queries, page filters, or rendering logic. |
| Related tests / smoke checks | `php -l`; verify local config and localhost page load. |
| High-risk / large files | `db_config.php` is sensitive local config. `db_engine.php` is a small but security-critical file. |

### CSS / assets

| Field | Notes |
| --- | --- |
| Owns | Site-wide styling and page/component visual behavior. |
| Status | `active` |
| Main entrypoints | `assets/css/components.css`; `main_style.css`; `sidebar_nav.css`; `table_style.css`; `theme_style.css`. |
| Common tasks that should start here | Layout fixes, component styling, sidebar behavior, page polish, consistency changes. |
| Common tasks that should not start here | Semantic page restructuring or data-state behavior. |
| Related tests / smoke checks | Manual browser validation with sidebar open; bump/verify asset versioning via `config/config.php` when needed. |
| High-risk / large files | `components.css` is the largest CSS file and carries many shared patterns, so changes can ripple widely. |

### JS / assets

| Field | Notes |
| --- | --- |
| Owns | Minimal client-side behaviors and UI interactions. |
| Status | `active`, but small |
| Main entrypoints | `assets/js/script.js` |
| Common tasks that should start here | Small interactive behaviors, client-side toggles, UI polish that cannot be done cleanly in CSS alone. |
| Common tasks that should not start here | Data fetching, business logic, cross-page state. |
| Related tests / smoke checks | Manual browser validation; cache-busting/version checks if JS changes are not appearing. |
| High-risk / large files | Only `script.js`; keep scope small to avoid hiding business logic in frontend JS. |

### Diagnostics

| Field | Notes |
| --- | --- |
| Owns | Web-side diagnostics and maintenance-only inspection. |
| Status | `diagnostics` |
| Main entrypoints | `pages/diag.php`; `database/README.md` for DB usage notes. |
| Common tasks that should start here | Local debugging, confirming DB availability, verifying odd page behavior outside analyst-facing routes. |
| Common tasks that should not start here | New product features, analyst workflows, or primary run-health explanations. |
| Related tests / smoke checks | `php -l`; localhost-only access; compare output to DB state when diagnosing a page. |
| High-risk / large files | `diag.php` can easily become a dumping ground; keep it maintenance-only. |

## Quick routing guidance

- Start app-level triage work in `pages/app_report.php` and the app detail pages.
- Start fleet discovery work in `pages/findings.php`, `pages/components.php`, `pages/permissions.php`, or `pages/run_health.php`.
- Start Web data-shape changes in `database/db_lib/*` and only then wire pages.
- Start DB contract changes in `scytaledroid/Database/db_queries/*` and `views.py`.
- Start static pipeline changes in `scytaledroid/StaticAnalysis/*`.
- Start dynamic workflow changes in `scytaledroid/DynamicAnalysis/*`.
- Start harvest/inventory changes in `scytaledroid/DeviceAnalysis/*`.

## Current notable large / high-risk files

CLI repo:
- [scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py)
- [scytaledroid/StaticAnalysis/cli/execution/results.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/StaticAnalysis/cli/execution/results.py)
- [scytaledroid/StaticAnalysis/cli/persistence/run_summary.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/StaticAnalysis/cli/persistence/run_summary.py)
- [scytaledroid/DynamicAnalysis/menu.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/DynamicAnalysis/menu.py)
- [scytaledroid/Database/db_queries/views.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/Database/db_queries/views.py)
- [scytaledroid/Database/db_utils/menus/health_checks.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/Database/db_utils/menus/health_checks.py)
- [scytaledroid/Database/db_utils/menu_actions.py](/home/secadmin/Laughlin/GitHub/ScytaleDroid/scytaledroid/Database/db_utils/menu_actions.py)

Web repo:
- [database/db_lib/db_func.php](/var/www/html/ScytaleDroid-Web/database/db_lib/db_func.php)
- [database/db_lib/db_queries.php](/var/www/html/ScytaleDroid-Web/database/db_lib/db_queries.php)
- [assets/css/components.css](/var/www/html/ScytaleDroid-Web/assets/css/components.css)
- [pages/app_report.php](/var/www/html/ScytaleDroid-Web/pages/app_report.php)
- [lib/render.php](/var/www/html/ScytaleDroid-Web/lib/render.php)
- [pages/findings.php](/var/www/html/ScytaleDroid-Web/pages/findings.php)
- [pages/permissions.php](/var/www/html/ScytaleDroid-Web/pages/permissions.php)

These are the first files to inspect for cross-cutting regressions before making broad changes.
