# Database governance and recovery runbook

`maintenance` · operator and project-manager reference

This document answers: **what broke on live MariaDB**, **what we changed**, **how to reproduce the repair**, **how to prove health**, and **how to stop the same drift from recurring**. It complements (does not replace) `docs/database/schema_domain_inventory.md`, `docs/database/derived_index.md`, and `scytaledroid/Database/db_queries/schema_manifest.py`.

---

## 1. What was wrong in the live MariaDB schema

Roughly four independent problems stacked together:

### A. Object-type mismatch (critical)

Several names the **codebase treats as analytic SQL views** (`v_web_*`, `vw_static_*`, etc.) existed in production as **`BASE TABLE`**. MariaDB then rejected `CREATE OR REPLACE VIEW` with **error 1347** (“not of type VIEW”). The Web app and some tooling expected **live joinable views** over `static_analysis_*`, `apps`, and related tables—not materialized snapshot tables occupying the same names.

**Effect:** dashboards stayed empty or inconsistent; repair could not proceed without dropping/clarifying those objects first.

### B. Schema drift (missing columns)

The running **`static_analysis_runs`** row shape was **missing columns** referenced by modern view DDL and persistence flows (run-level reconcile / capped inventory fields). **`static_analysis_findings`** lacked **`severity_raw`**, referenced by **`v_web_app_findings`** and the Web explorer.

**Effect:** views failed to apply or partially failed (`Unknown column`), even after fixing object types.

### C. Charset / collation mismatch (`latin1` vs `utf8mb4`)

Legacy **`latin1`** string columns on hot join paths (often **`apps.package_name`**, file-provider surfaces, etc.) collided with join logic that assumed **`utf8mb4`** collations (`utf8mb4_unicode_ci` / `utf8mb4_general_ci`). MariaDB surfaced **error 1253**.

**Effect:** surfaced as red **SQL error** banners on some pages (e.g. Components) and brittle directory union logic.

Mitigation shipped in DDL/PHP uses **`CONVERT(... USING utf8mb4)`** on both sides of affected joins until a deliberate charset migration is scheduled.

### D. Semantic mismatch (Permission Intelligence versus “usable”)

Fleet **`v_web_permission_intel_current`** was effectively limited to **`usable_complete`** sessions—runs that satisfy **multiple** completeness pillars at once (not only permission matrix). Completed runs with **meaningful permission data** but **incomplete strings** (or similar) could register as **`partial_rows`** and **vanish from fleet permission views**.

**Mitigation:** filter widened responsibly (completed + partial where appropriate), fleet copy updated—**fleet stays useful**, **detailed app pages remain honest about incomplete pillars**.

---

## 2. What was changed (summary)

### On the database server

- **`ALTER TABLE`** added **nullable / safe** columns where missing (`static_analysis_runs` reconcile helpers; **`severity_raw`** on **`static_analysis_findings`**).

- **`DROP`** of **`BASE TABLE`** (and offending duplicate **`VIEW`**) stubs that **collided with reserved analytic view names** under **`v_*` / `vw_*`**, subject to backups and verification.

- **`CREATE OR REPLACE VIEW`** reapplied **in dependency order** from authoritative Python DDL strings (`scytaledroid/Database/db_queries/views_*.py`).

### In the Python/Web repositories

- **View SQL hardened** (`CONVERT` on union arms and risky joins).

- **`v_web_permission_intel_current`** semantics and related Web SQL aligned with fleet usefulness vs session honesty.

- **Tests updated** (`tests/database/test_web_view_static_preference.py`) so CI matches real DDL intent.

---

## 3. Golden schema ownership (authoritative layers)

### Authoritative DDL source

The **canonical machine-readable definitions** live in **`scytaledroid/Database/db_queries/`**, aggregated through **`schema_manifest.py`**, **`views.py`**, and related modules.

**Operational rule:** staging/prod/dev should be **advanced by applying DDL from this repo** (bootstrap, targeted ALTERs, recreate views)—not idiosyncratic naming of “helper tables” under **`v_`/`vw_`**.

### Naming contract (binding)

**No physical tables** should be introduced whose names match:

- **`v_*`** — reserved for **SQL VIEW** analytic/read-model surfaces consumed by tooling (Web-first `v_web_*`).
- **`vw_*`** — reserved for **SQL VIEW** “wire” joins over static/runtime (example: **`vw_static_finding_surfaces_latest`**).

If bulk exports or migrations need persisted rollups, use names such as **`mtrl_*`, `staging_*`, `snapshot_*`**—never **`v_`/`vw_*`**.

### Canonical tables vs views vs legacy (high level)

| Class | Examples | Role |
| --- | --- | --- |
| **Canonical transactional / persistence** | `apps`, `app_versions`, `static_analysis_runs`, `static_analysis_findings`, `static_permission_matrix`, `dynamic_sessions`, … | Source of truth for evidence; persists CLI outputs. |
| **Canonical analytic views (Web/read)** | `v_web_app_directory`, `v_web_app_sessions`, `v_web_app_findings`, `v_web_permission_intel_current`, … | Stable read-models; **VIEW only**. |
| **Static surface joins** | `vw_static_finding_surfaces_latest`, `vw_static_risk_surfaces_latest`, … | **VIEW** layers over SAR + rollup tables. |
| **Legacy compatibility** | Older tables noted in **`docs/database/schema_domain_inventory.md`** (`runs`, buckets bridges, harvest bridges, …) | **Explicitly classified**—do not repurpose **`v_*` names** for them. |

Detailed classification remains in **`docs/database/schema_domain_inventory.md`** (“CORE_KEEP”, **`WEB_VIEW_KEEP`**, **`LEGACY_ACTIVE_BRIDGE`**, …).

### DB users / layering (recommended posture)

Avoid sharing one super-user across app + analyst + migration.

| Concern | Suggested posture |
| --- | --- |
| **Migrator / DBA repair** | Account with DDL rights; used **only** for bootstrap/repair/automation—not Web runtime. |
| **Web PDO read user** | `SELECT`-bounded on operational DB views + minimal base tables **only if unavoidable**; ideally views-only. |
| **CLI persistence** | Service account scoped to **`static_analysis_*`**, **`apps`/`app_versions`**, etc., per operational policy. |
| **Permission-intel isolated DB** | Follow **`docs/database/permission_split_execution_phases.md`**—different namespace from core operational reads. |

---

## 4. Repeatable scripts (checked in)

| Path | Purpose |
| --- | --- |
| **`scripts/db/README.md`** | Short operator command sequence |
| **`scripts/db/check_schema_posture.sql`** | Read-only probes (expected **VIEW** names, any `v_*`/`vw_*` **BASE TABLE** violations, **`analysis_dynamic_cohort_status`** type, utf8 posture hints) |
| **`scripts/db/recreate_web_consumer_views.py`** | `posture`, **`semantic`** (source-vs-Web-view coherence), `counts`, guarded **`recreate`** with **`--layer full`/`manifest`/`web`** |
| **`scripts/db/view_repair_support.py`** | Helpers: manifest-ordered DDL + supplementary + web extension merge (used by the Python **`recreate`**) |
| **`scripts/db/smoke_web_db.sh`** | Wraps **`ScytaleDroid-Web/scripts/sd_web_db_smoke.php`** PDO smoke |

Destructive **`recreate`** steps require **`--confirm`**. Drops of non-empty **`v_*`/`vw_*`** **BASE TABLE** stubs additionally require **`--allow-drop-nonempty-tables`** with **`--confirm`**. Always **backup before drop**.

---

## 5. Health proof and row-count sanity

Minimum bar after recovery:

```bash
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts
SCYTALEDROID_WEB_ROOT=… ./scripts/db/smoke_web_db.sh
```

**PDO smoke** verifies “**SQL executes**”. **`semantic`** verifies **baseline counts print** plus **logical coherence** (e.g. `static_analysis_findings` non-empty but `v_web_app_findings` empty → exit **1**) so dashboards cannot silently regress.

Suggested **mental model** vs zeros:

| Surface | Interpretation hint |
| --- | --- |
| **`dynamic_sessions` non-zero, `v_web_app_directory` near zero** | Often **physical apps/static pipeline** not hydrated—dynamic-only fleet. Investigate ingestion, not just Web. |
| **directory non-zero but explorer zero** | Check **`vw_static_finding_surfaces_latest`** + findings persistence; reconcile pipeline. |

---

## 6. Columns added during recovery (nullable / safe)

| Table | Columns | Purpose |
| --- | --- | --- |
| **`static_analysis_runs`** | `findings_runtime_total`, `findings_capped_total`, `findings_capped_by_detector_json` | Persisted reconcile / cap rollup fields expected by newer views |
| **`static_analysis_findings`** | `severity_raw` | Persisted gated label parallel to capped severity |

Source of definitions: **`scytaledroid/Database/db_queries/canonical/schema.py`** ALTER blocks and persistence code paths.

---

## 7. Authoritative views recreated (layers)

- **`--layer full`** (default): views from **`ordered_schema_statements()`** in manifest order (admin/bridge/static/dynamic/reporting names such as **`v_run_overview`**, **`v_static_handoff_v1`**, cohort and artifact registry views), **plus** supplementary reporting views (`vw_dynload_hotspots`, `v_masvs_matrix`, …) when absent from the manifest, **plus** the **Web consumer extension** chain.
- **`--layer manifest`**: manifest-only (no web extension; use when Web DDL is applied elsewhere).
- **`--layer web`**: Web consumer stack only (legacy / targeted repair).

Representative **Web** tail (after manifest chain): **`vw_latest_apk_per_package`**, **`vw_*_permission_*`**, **`vw_static_{risk,finding}_surfaces_latest`**, **`v_web_*`**, **`v_web_runtime_{run_index,run_detail}`**.

---

## 8. Security and configuration hygiene (tracked)

**Problem:** Web trees historically held **`database/db_core/db_config.php`** with plaintext credentials—risky under version control exposure or shared hosts.

**Target posture:**

| Item | Guidance |
| --- | --- |
| **Secrets** | Prefer env (`SCYTALEDROID_DB_*`), secret manager, or **git-ignored local override** derived from **`db_config.example.php`**. |
| **Commits** | Example-only templates in repo; real credentials **never merged**. |
| **Rotation** | If credentials toured broad logs/chats/workflows, rotate the DB password and constrain grants. |

Web repo **`db_core/db_config.example.php`** should explain FPM **`SetEnv` vs getenv** quirks (already noted in sibling Web maintenance).

---

## 9. Long-term charset migration (planned, not immediate)

Immediate fix: **`CONVERT(... USING utf8mb4)` on joins** referencing legacy **`latin1`** keys.

Later (maintenance window, dry-run sizing, rebuild indexes):

Priority candidates often include **`apps.package_name`** and **`static_fileproviders`** / ACL join keys flagged by **`information_schema`** rows in **`check_schema_posture.sql`**.

**Do not blend** unchecked bulk `CONVERT()` table rewrites **with heavy static ingestion** windows without a phased plan.

---

## 10. Permission Intelligence semantics (product alignment)

**Fleet dashboards** should expose **meaningful aggregated permission prevalence** whenever **completed/static-backed permission rows exist**, even when other pillars lag.

**Detailed app pages / reports** retain **explicit warnings** for missing strings, incomplete audits, etc.

Formal filter rules live with **`CREATE_V_WEB_PERMISSION_INTEL_CURRENT`** in **`db_queries/views_permission.py`** and **`SQL_PERMISSION_INTEL_*`** in the Web **`db_queries.php`**—document changes there alongside UI copy (`pages/permissions.php`).

---

## 11. Risks that remain / anti-drift playbook

| Risk | Mitigation |
| --- | --- |
| Silent reintroduction of **`v_*` tables** | Enforce naming contract + periodic `posture`; code review rejects `CREATE TABLE v_` |
| Drift vs repo DDL | Tagged releases + scripted view recreation after upgrades |
| Web vs CLI reading different databases | Declare target DB **per environment**; add env banner in diagnostics |
| Over-broad DDL grants on Web credentials | Principle of least privilege; views-first reads |

---

## 12. Status summary for project notes (accurate capsule)

“The web-facing DB accumulated **stub tables pretending to be analytic views**, **missing columns versus current DDL**, and **`utf8mb4` vs `latin1` join mismatches**. We **dropped incompatible stubs**, **added safe nullable columns**, **reapplied view DDL from the repo**, tightened **JOIN charset safety**, and **relaxed Permission Intel filters** while keeping **truthful incompleteness** on drill-down pages.

**Operational follow-through:** scripted **posture + recreate (`scripts/db`)**, **`smoke_web_db.sh`**, **documentation index entry**, **deferring a planned charset migration**, and moving **secrets out of tracked web trees**.”**

---

## 13. Roadmap echoes (engineering backlog linkage)

Tracked next implementation waves (beyond this doc):

1. Schema posture CI hook (scheduled or gate).
2. Richer **`sd_web_db_smoke`** semantic checks (“zeros vs underlying counts”).
3. Centralized **`run_health`** database persistence surfaced identically CLI/Web.
4. Artifact identity redesign (orthogonal but sequenced separately).

