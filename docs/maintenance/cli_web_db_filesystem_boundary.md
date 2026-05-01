# CLI ↔ Web ↔ Database ↔ Filesystem — roles and boundaries

**Status:** `maintenance` (operator/architecture router; code wins on conflicts.)

**Audience:** Agents and maintainers aligning the Python CLI repo (`ScytaleDroid`) with the separate Web repo (`ScytaleDroid-Web`, e.g. `/var/www/html/ScytaleDroid-Web`).

**Aligned V1 posture (explicit):**

| Layer        | Primary job |
|-------------|--------------|
| **CLI**      | Execution and research workflows (“run this now”). |
| **Database** | Normalized identity, relationships, summaries, queryable findings. |
| **Filesystem** | Durable artifacts: APKs, reports, PCAPs, receipts, manifests, exports. Hash identifies content; DB IDs relate rows; paths materialize blobs. |
| **Web UI**   | Review: read DB summaries and path hints; visualize; minimal or no execution. |

---

## 1. Which workflows are CLI-only right now?

Roughly everything that touches **ADB**, **local artifact stores**, **detector pipelines**, or **destructive/maintenance DB operations** stays in this repo via `./run.sh` menus and packaged modules.

**Examples (this repo owns them):**

- Device inventory refresh and DB snapshot sync (`scytaledroid/DeviceAnalysis/inventory/*`, workflow map: `workflow_entrypoint_map.md` → Device inventory).
- APK harvest planning and pull (`harvest/runner.py`, artifact store).
- Static analysis orchestration (`StaticAnalysis/cli/flows/run_dispatch.py`, detectors, persistence transaction).
- Dynamic analysis orchestration (`DynamicAnalysis/*`, PCAP/evidence packs, `storage/persistence.py`).
- Report/export/publication tooling (`Reporting/`, `Publication/`, gated scripts).
- DB utilities, schema bootstrap, resets, reconcile (`Database/db_utils/*`, `tools/*`).
- Run health JSON emission (`StaticAnalysis/cli/execution/run_health.py`) tied to CLI finalize paths.

There is **not** yet a stable, fully exposed `scytaledroid <subcommand>` surface for every menu workflow; repeatable flags exist in patches (see `docs/supported_entrypoints.md`). The mental model matches the CLI as the workflow engine until those entrypoints stabilize.

---

## 2. Which workflows are available in the Web UI?

The Web app is intentionally **read-oriented** routes under `pages/` (see `docs/maintenance/repo_ownership_map.md` → Web Repo).

**Typical analyst surfaces:**

- Fleet app directory / search (`apps.php`, `index.php`; SQL `v_web_app_directory`).
- Per-app drilldown (`app_report.php`, `app_findings.php`, `app_permissions.php`, `app_components.php`, `app_strings.php`, `app_dynamic.php`).
- Fleet explorers (`findings.php`, `findings_group.php`, `permissions.php`, `components.php`, `dynamic.php`, `dynamic_run.php`).
- Run health rollup (`run_health.php`).
- Legacy redirects (`view_app.php`, `android_permissions.php`); guarded diagnostics (`diag.php`, DB probes only).

The Web repo does **not** implement device sync, harvest, or static/detector execution in PHP.

---

## 3. Which Web UI pages read from DB tables/views?

Effectively **all** analyst pages execute SQL via `database/db_lib/db_queries.php` and `database/db_lib/db_func.php` against PDO.

**Dominant contracts:**

- `v_web_app_directory` — fleet directory row shape.
- `v_web_app_sessions` — package/session rollup and “usability” signals for picking a session.
- `v_web_app_findings` — static finding rows joined to preferred static run surfaces.
- `vw_static_finding_surfaces_latest`, `vw_static_risk_surfaces_latest` — static summary joins.
- `v_web_app_permissions`, `v_web_permission_intel_current` — permission matrix / intel snapshots.
- `v_web_static_session_health` — session-level health rollup.
- `v_web_runtime_run_index`, `v_web_runtime_run_detail` — dynamic run browsing (`dynamic_sessions` and related telemetry tables).

`diag.php` calls `app_diagnostics()` → counts over core tables (`runs`, `static_analysis_runs`, audit snapshots, dynamic tables, etc.).

---

## 4. Which Web UI pages read from filesystem artifacts?

**Today: almost none as a rendered source of truth.** Pages display **paths and JSON payloads already stored or derived in DB** (e.g. finding `evidence` JSON columns, dynamic `evidence_path` strings). Operators use those paths outside the PHP stack (file server, workstation mount, CLI workspace).

Finding “full report JSON under `output/`” is **not** opened server-side by the Web app in routine pages; reproducibility relies on CLI-generated files plus DB pointers.

*(If future work adds-on-disk report previews, treat that as explicit scope and shared path policy.)*

---

## 5. Which CLI workflows write DB rows?

**Device / APK:** inventory snapshots (`device_inventory_*`), harvest catalog (`android_apk_repository`, harvest path tables), apps/app_versions linkage — see `workflow_entrypoint_map.md` per workflow.

**Static:** full persistence transaction in `StaticAnalysis/cli/persistence/run_summary.py` and related stages — `static_analysis_runs`, `static_analysis_findings`, `findings` (legacy bridge), metrics/buckets/contributors (`run_id`-gated surfaces), permission matrix/risk (`static_permission_matrix`, etc.), `static_string_summary`, MASVS/audit rows when audits run, linkage tables (`static_session_run_links`), canonical correlation rows, finalize updates on `static_analysis_runs`, etc.

**Dynamic:** `DynamicAnalysis/storage/persistence.py` and cohort/session writers — rows under `dynamic_sessions` and telemetry/feature tables surfaced by runtime views.

**Reporting:** selectively reads DB for exports; specialized publication flows may write ledger-style rows per contract docs.

---

## 6. Which CLI workflows write only filesystem artifacts (or tolerate no DB persistence)?**

- **`dry_run`**: analysis may execute without persistence; skips DB transactional writes tied to finalize.
- **`persistence_ready=False`** (`SCYTALEDROID_PERSISTENCE_READY=0`): static scan/report generation can still proceed; **`persist_enabled` is false** — DB persistence skipped; operator messaging in `StaticAnalysis/cli/execution/results.py` notes suppressed evidence outputs.
- **Report JSON saves** when persistence gate allows saves (`scan_report.py`: report storage path alongside scan).
- **Run health JSON**: written under CLI session/output conventions when finalize emits it (`run_health_json_path` on `RunOutcome`).
- **Harvest/device**: materially uses DB for catalog in normal setups; purely-offline scripted flows could hypothetically omit DB but **that is not the happy path** for coordinated Web review.

Filesystem remains authoritative for **raw APK blobs**, PCAPs, large evidence bundles, baseline JSON dumps, manifests.

---

## 7. What happens when DB is disabled or unavailable?

Distinction matters:

**A. `persistence_ready` false / static persistence skipped**

- Detector runs may still execute; **`save_report`** may produce JSON artifacts where configured.
- **No** transactional static persistence (`persist_run_summary` early-aborts or skips DB stages per gate).
- **Web UI** still expects a DB; it does not replace persistence.

**B. Database engine down / misconfigured credentials**

- **Web**: PDO failures on every page (“DB error” paths in PHP controllers).
- **CLI**: workflows that **require** `require_canonical_schema()` / live SQL fail persistence or inventory sync; harvesting may degrade depending on runner paths.

Operational recovery: restore connectivity, rerun bootstrap (`schema_manifest` / canonical `ensure_all`), validate with DB menu tools and Web `diag.php`.

---

## 8. What tables/views are needed for Web static analysis UX?

minimum **usable** browsing:

- **`apps`** / **`app_versions`** — package identity joins.
- **`static_analysis_runs`** — session row for `session_stamp`, status, rollup columns.
- **`static_analysis_findings`** — rows joined by **`v_web_app_findings`** (canonical detail).
- Supporting surfaces joined by **`v_web_app_sessions`**: **`static_permission_matrix`**, **`static_string_summary`** (strings ready bit), **`permission_audit_apps`**, **`static_session_run_links`** — matching the rollup logic in `scytaledroid/Database/db_queries/views_web.py` (`CREATE_V_WEB_STATIC_SESSION_HEALTH`, session usability).

Supporting summary reads also hit **`vw_static_*`**, **`static_findings_summary`**, **`static_findings`** in some overlays.

If only catalog rows exist (no completed static run), `v_web_app_directory` may show **catalog-only** `source_state` — pages render empty/low-signal summaries by design.

---

## 9. What tables/views are needed for Web dynamic UX?

Browse/index/detail paths use **`v_web_runtime_run_index`** and **`v_web_runtime_run_detail`**, anchored on **`dynamic_sessions`** plus issue/feature tables referenced in those view definitions (`dynamic_session_issues`, feature/window aggregates as coded in `views_web.py`).

App-level dynamic summary pulls package-scoped aggregates from **`Database/db_lib/db_func.php`** helpers (see `app_dynamic_summary`, dynamic runs listing queries).

Without dynamic rows inserted by CLI persistence, dynamic pages remain empty while static may still populate.

---

## 10. Where are duplicated rules between CLI and Web (drift risks)?**

| Topic | Observation |
|-------|--------------|
| **Session “health” / usability** | Web reads **`v_web_static_session_health`** and `v_web_app_sessions` semantics defined **in SQL in this repo** (`views_web.py`). CLI emits **`run_health.json`** separately (`run_health.build_run_health_document`). **Same conceptual signal, two pipelines** — keep SQL view definitions aligned with telemetry JSON fields during contract changes (recent additions: capped findings rollup in CLI JSON vs DB columns `static_analysis_runs.*` after migration). |
| **Severity bucketing** | Persistence normalizes severities (`StaticAnalysis/cli/persistence/utils.py`); DB stores normalized `severity`; Web aggregates with `LOWER(severity)`. Raw tiers now have **`severity_raw`** column alongside normalized `severity` — Web can be extended later; avoid reinterpreting severities **only** in PHP. |
| **“Latest” package/run selection** | Web uses SQL windowing in views; CLI UX uses **`AppRunResult`** / finalize ordering. Prefer **single DB view precedence** (`vw_static_finding_surfaces_latest` “preferred_static_run_id” pattern) as the authoritative “what the Web shows” rule; CLI dashboards should converge to naming those rules, not reinvent them in Python string logic. |

**Prefer:** one backend rule (stored procedure / view / shared Python export consumed by thin Web layer). **Avoid:** recomputing risk scores or MASVS rollups independently in PHP.

---

## References (this repo)

- `docs/maintenance/workflow_entrypoint_map.md` — CLI workflow → modules → tables.
- `docs/maintenance/repo_ownership_map.md` — Web repo file ownership.
- `scytaledroid/Database/db_queries/views_web.py` — authoritative Web-facing SQL contracts.
- `StaticAnalysis/cli/execution/results.py` — persistence gate interaction with filesystem outputs.

## References (Web repo)

Path convention on deploy host (example):

- `/var/www/html/ScytaleDroid-Web/pages/*.php`
- `/var/www/html/ScytaleDroid-Web/database/db_lib/db_queries.php`
- `/var/www/html/ScytaleDroid-Web/lib/app_detail.php` — session/context selection atop DB views.

