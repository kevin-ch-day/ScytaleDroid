# Permission Intel — ScytaleDroid S1 read-path audit

**Phase:** S1 (read-path / classification alignment; **no** `android_permission_obs_sample` writes).  
**Scope:** Documentation-only audit; codebase reviewed read-only except this file.  
**Non-goals:** No schema changes, no Erebus imports, no merge of Erebus and Scytale databases, no observation-table writes.

---

## Executive summary

ScytaleDroid already routes **shared PI dictionary/metadata reads and dict/queue writes** through **`scytaledroid.Database.db_core.permission_intel`** with env namespace **`SCYTALEDROID_PERMISSION_INTEL_DB_*`**. There is **no** evidence of silent fallback of PI-managed `android_permission_*` tables onto the **core** catalog: unqualified `android_permission_*` SQL appears only inside **`permission_intel.py`**, which uses a dedicated engine/session for the PI DSN.

**Gaps for S2+:** Local **hardcoded** triage helpers and a **YAML fallback catalog** can diverge from Erebus Contract A / LUT vocabulary; **`dict_unknown.triage_status`** values emitted by static are a **subset** of the full governance ledger. **Taxonomy** scaffolding (`perm_groups`) is **core DB only** and **deprecated map/overrides** are no-ops — orthogonal to PI triage but easy to confuse.

**Tests run (subset):** `pytest tests/static_analysis/test_run_dispatch_permission_intel_preflight.py tests/static_analysis/test_permission_flow_failures.py tests/database/test_schema_gate_permissions.py` → **18 passed**.

**S1.5 follow-up:** vocabulary contract + routing guard tests — see [permission_intel_scytaledroid_s1_5_classifier_contract.md](permission_intel_scytaledroid_s1_5_classifier_contract.md).  
**S2 design (observations, no implementation):** [permission_intel_scytaledroid_s2_observation_design.md](permission_intel_scytaledroid_s2_observation_design.md).  
**Erebus↔Scytale PI drift (migrations, queue, obs columns):** [permission_intel_schema_drift_erebus_vs_scytaledroid.md](permission_intel_schema_drift_erebus_vs_scytaledroid.md).  
**S2-P1A operational readiness (queue audit, static linkage):** [permission_intel_scytaledroid_s2_p1a_operational_readiness.md](permission_intel_scytaledroid_s2_p1a_operational_readiness.md).

---

## 1. Classification drift audit

### 1.1 ScytaleDroid surfaces reviewed

| File | Role |
| --- | --- |
| `StaticAnalysis/persistence/permissions_db.py` | Classify declared manifest strings; upsert **`dict_unknown`**; queue **`aosp_missing`**; **`update_oem_seen`**. |
| `Database/db_func/permissions/permission_dicts.py` | Thin wrappers: AOSP/OEM/prefix/vendor reads; **`upsert_unknown`**, **`insert_queue`**, **`update_oem_seen`** → **`permission_intel`**. |
| `Database/db_func/permissions/taxonomy.py` | **`perm_groups`** on **core** DB; permission map/overrides **deprecated** (`SELECT 0`). |

### 1.2 Internal count buckets (not PI columns)

`persist_declared_permissions` returns **`aosp`**, **`oem`**, **`app_defined`**, **`unknown`** — coarse counters for logging/metrics, **not** `triage_status` values.

### 1.3 `android_permission_dict_unknown.triage_status` values Scytale can emit

From **`permissions_db.py`**:

| `triage_status` | When |
| --- | --- |
| **`malformed`** | Internal whitespace, malformed prefix (`android.premission.*`), or token fails `_valid_permission_token` (no dot, etc.). |
| **`app_defined`** | Permission in **`custom_declared`** set and not resolved as AOSP/OEM earlier. |
| **`oem_candidate`** | Non-`android.permission.*` token, OEM prefix rule match (`fetch_vendor_prefix_rules`). |
| **`aosp_missing`** | `android.permission.*` but not in AOSP dict hit; GhostAOSP broadcast set only affects **notes**, not branch to separate triage. |
| **`new`** | Non-framework permission, no OEM dict hit, no prefix match. |

**Queue:** When `triage_status == "aosp_missing"`, **`insert_queue`** with `queue_action="aosp"` (Erebus queue-apply compatible), `source_system="static-analysis"`, `requested_by="static-analysis"`. Legacy `aosp_promote` is normalized in `permission_dicts.insert_queue`.

### 1.4 PI / Erebus concepts — coverage vs drift

| Concept | Scytale alignment | Drift / note |
| --- | --- | --- |
| **AOSP dictionary** | **Read** via `fetch_aosp_entries` / `fetch_aosp_protection_map` / catalog `fetch_aosp_permission_catalog_rows`. | **YAML catalog** (`modules/permissions/catalog.py` + `framework_permissions.yaml`) is a **local fallback** when DB load fails — duplicates AOSP semantics offline. |
| **OEM dictionary** | **Read** + **`update_oem_seen`**. | OK. |
| **dict_unknown / triage** | **Write** subset above. | Erebus contract doc lists many ledger states (`resolved_aosp`, `gms_known`, `in_review`, …). Scytale **only upserts intake-style statuses**; it does **not** drive resolution SPs or full LUT. |
| **OEM prefix / vendor metadata** | **Read** `android_permission_meta_oem_prefix` (+ vendor meta fetch exists in `permission_dicts`). | Scytale uses **longest-prefix loop** in Python; Erebus uses richer classifier ordering in **`permission_record.py`** — **behavioral drift risk**. |
| **app_defined** | Emitted as triage. | Matches naming; ensure FK/LUT on PI allows value (operator responsibility on DDL). |
| **oem_candidate** | Emitted. | Same. |
| **aosp_missing** | Emitted + queue. | Same. |
| **malformed** | Emitted. | Same. |
| **suspicious_token / policy_hold** | **Not** emitted as `triage_status` here. | **Research / governance** concepts (`v_permission_research_status_v2`, policy hold) are **Erebus primary** reporting; Scytale static path does not set them. |
| **GhostAOSP** | Hardcoded **`_GHOSTAOSP_BROADCAST_PERMS`** — **notes only**. | Duplicates “special case” knowledge that may also exist in Erebus taxonomy; prefer **PI notes / dict** long-term. |
| **Malformed prefix list** | **`_MALFORMED_PREFIXES = ("android.premission.",)`** | Local typo detector; could align with alias ledger if PI gains rows. |

### 1.5 Hardcoded logic that duplicates or bypasses PI

- **`permissions_db`:** `_GHOSTAOSP_BROADCAST_PERMS`, `_MALFORMED_PREFIXES`, `_valid_permission_token` rules.
- **`catalog.py`:** packaged **`framework_permissions.yaml`** + config paths; **`PermissionDescriptor.base_level`** maps protection tokens (`dangerous`, `signature`, …) — **display/risk** layer, not `dict_unknown`.
- **`permission_matrix.py` / `profile`:** **`_coerce_source`** / **`_infer_permission_source`** namespace heuristics (`framework`, `play_services`, `custom`) — **core static table** `source` column, not PI.

### 1.6 Recommendations (minimal, S1)

1. Document allowed **`triage_status`** strings Scytale may write and cross-check against deployed **`android_permission_triage_status_lut`** (or equivalent) on PI.  
2. Prefer **PI AOSP rows** for catalog when configured; treat YAML as **offline/dev only** in operator docs.  
3. Optionally add a **read-only** test or lint: triage literals in `permissions_db.py` ⊆ documented LUT (no code change to logic in S1).

---

## 2. Permission Intel routing validation

### 2.1 PI connection surface

**Module:** `scytaledroid.Database.db_core.permission_intel`  
**Config:** `SCYTALEDROID_PERMISSION_INTEL_DB_URL` or `SCYTALEDROID_PERMISSION_INTEL_DB_{NAME,USER,PASSWD,HOST,PORT}` (`db_config.resolve_db_config_from_root("SCYTALEDROID_PERMISSION_INTEL_DB")`).  
**Behavior:** `resolve_config()` **raises** if PI not configured — **no automatic alias to primary** for `session()` / `run_sql` in this module (Phase 5 posture in file docstring).

### 2.2 Functions that open / use PI

All SQL touching `android_permission_dict_*`, `android_permission_meta_oem_*`, governance/signal tables should go through **`permission_intel.run_sql`** / **`session`**. Call sites include:

- `permission_dicts.py` (all dict I/O)
- `permissions_db.py` (via `permission_dicts` + table name constants from `permission_intel`)
- `StaticAnalysis/modules/permissions/catalog.py` (`fetch_aosp_permission_catalog_rows`)
- `StaticAnalysis/cli/execution/pipeline.py` (`governance_ready` counts)
- `scripts/db/check_permission_intel.py`
- `Database/db_utils/schema_gate.py` (`intel_table_exists` for `MANAGED_TABLES`)
- `Utils/System/governance_inputs.py`, menu/health actions, `permission_support.py` (mixed — see below)

### 2.3 Core DB (`run_sql` from `db_core`)

**Primary** operational catalog (e.g. `scytaledroid_core_prod`):

- **`static_permission_matrix`**, **`static_analysis_*`**, **`perm_groups`**, permission cohort tables (`permission_audit_*`, `permission_signal_observations` per schema gate), diagnostics.

**This is correct** — PI facts are not copied into core for static matrix rows.

### 2.4 `android_permission_*` references outside `permission_intel.py`

Repo grep shows **table name strings** primarily **inside** `permission_intel.py` and **views** under `db_queries/views_permission.py` (view definitions may **reference** PI objects for web consumers — deployment-specific). No application Python file was found that runs raw `SELECT … FROM android_permission_dict_aosp` via **`Database.db_queries.run_sql`** (primary) for those tables; the read path is **`intel_db.run_sql`**.

### 2.5 Silent fallback risk

- **`is_permission_intel_configured()`** is **False** → static preflight warns; **`permissions_schema_gate`** **skips** PI table existence check (returns **`ok=True`** with **`msg="OK_SKIPPED"`** and a detail string) — operators may run **without** PI in **experimental** mode.  
- That is **explicit**, not silent routing of PI tables onto core.

### 2.6 `permission_support.py`

Uses **`intel_db`** for PI signal/catalog provisioning **and** **`run_sql`** for **core** app tables — by design; verify future edits keep **`android_permission_*` DML** on **`intel_db`** only.

---

## 3. Existing operator checks

### 3.1 `scripts/db/check_permission_intel.py`

**Proves:**

- PI DSN resolves; `describe_target()` works.  
- Each **`MANAGED_TABLES`** entry **exists** in PI.  
- Row counts for AOSP/OEM/unknown/queue tables.  
- **`governance_snapshot_count` / `governance_row_count`** > 0 via **`governance_ready()`** (same helper as static CLI).

**Does not prove:**

- Erebus **split** vs **unified** (Scytale always uses **its own** PI env — alignment with Erebus is **operational**, not enforced by script).  
- VT **`enrich_vt_*`** health, **`obs_sample`** pairing, or **MariaDB grants** for cross-DB SELECTs.  
- **Triage LUT** completeness vs Scytale-emitted statuses.

**Exit codes:** `0` = tables + governance OK; `1` = not configured / missing tables / query errors; `2` = configured but **governance_missing** (reminder).

### 3.2 `Database/db_utils/schema_gate.py` — `permissions_schema_gate()`

**Proves:** Core tables for “Permission Cohorts” module exist; **if** PI configured, **`MANAGED_TABLES`** all exist in **dedicated** PI.

**Does not prove:** Governance snapshots, dictionary row counts, or connectivity at runtime menu time beyond gate implementation.

### 3.3 `docs/database/shared_permission_intel_reconciliation.md`

Authoritative **cross-repo** narrative: Contract A tables, Scytale writers, future **`obs_sample`** — **keep in sync** with Erebus `android_permissions_schema_contract.md` when triage vocabulary changes.

### 3.4 `tests/static_analysis/test_run_dispatch_permission_intel_preflight.py`

**Proves:** Preflight **short-circuits** when dry_run / quiet+batch (no boom on `is_permission_intel_configured`); other cases exercise messaging paths.

**Does not prove:** Live MariaDB or parity with Erebus **`db_doctor`**.

### 3.5 Match Erebus split-catalog posture?

Scytale’s model is **already split-by-env** (core vs `SCYTALEDROID_PERMISSION_INTEL_DB_*`), analogous to Erebus **`EREBUS_DB_*`** vs **`EREBUS_PERMISSION_INTEL_DB_*`**. **Optional S1.5 doc tweak:** add one paragraph to `check_permission_intel.py` docstring or `AGENTS.md` stating “PI DSN should point at the **same** `android_permission_intel` catalog Erebus uses when operators want a single source of truth.” **No code change required** for parity.

---

## 4. Static analysis permission output contract

### 4.1 Extraction

- **`DetectorContext.permissions`:** **`declared`**, **`custom`**, **`dangerous`** (and details) feed **`build_permission_analysis`** (`modules/permissions/profile.py`).  
- Manifest indexing: **`index_manifest_permissions`** / evidence collectors.

### 4.2 Core DB tables (canonical static)

| Table | Writer | Permission-related columns |
| --- | --- | --- |
| **`static_permission_matrix`** | `StaticAnalysis/cli/persistence/permission_matrix.py` → `static_permission_matrix.replace_for_run` | **`permission_name`** (full string), **`package_name`**, **`run_id`**, **`apk_id`**, **`source`**, **`protection`**, **`guard_strength`**, **`flags`** (JSON with booleans + optional `catalog_source`, `protection_levels`), severity columns. |

**PI dict alignment:** Matrix stores **verbatim** manifest permission strings in **`permission_name`** — suitable for future join to **`constant_value` / `permission_string`** on PI.

### 4.3 SHA-256 at persistence time

- **`persist_permissions_to_db`** reads **`report.hashes.sha256`** and passes to **`persist_declared_permissions`**, but **`example_sample_id`** remains **`None`** and sha256 is **not** passed into **`upsert_unknown`** payload in current code — **S2 should add** explicit subject linkage (run id, artifact hash, device id).

### 4.4 Is this enough for future S2 `obs_sample` writes?

**Partially:** You have **normalized permission string**, **package_name**, **static_run_id** / **apk_id** on **`static_permission_matrix`**, and **SHA-256** on the report path for dict upserts. **Missing for S2:** explicit **producer** / **`source_system`**, mapping **subject id** to a key compatible with **`android_permission_obs_sample`** uniqueness (today Erebus: **`sample_id`** malware catalog). **Open design questions** (see §8).

---

## 5. High-risk files (touch carefully in S2)

| Path | Risk |
| --- | --- |
| `StaticAnalysis/persistence/permissions_db.py` | All PI triage emissions; queue side effects. |
| `Database/db_func/permissions/permission_dicts.py` | Single choke point for dict I/O — good, but any bypass breaks routing. |
| `Database/db_core/permission_intel.py` | DSN + all PI SQL. |
| `StaticAnalysis/modules/permissions/catalog.py` | YAML vs PI AOSP drift. |
| `StaticAnalysis/cli/persistence/permission_matrix.py` | Core matrix shape; S2 may add FK-like conventions. |
| `StaticAnalysis/cli/flows/static_run_preflight.py` | Operator expectations for paper-grade vs experimental. |
| `scripts/db/check_permission_intel.py` | Operator “green light” for PI. |

---

## 6. S2 readiness checklist

Answers reflect the **current** static + persistence code paths (pre–`obs_sample` writes).

| Question | Status | Notes |
| --- | --- | --- |
| Stable **APK SHA-256** at permission persistence time? | **Yes (on report path)** | `persist_permissions_to_db` reads `report.hashes["sha256"]` and passes it into `persist_declared_permissions`, but **sha256 is not written** into `dict_unknown` / queue payloads today (`example_sample_id` stays `None`). |
| **`apk_id`** available? | **At matrix persist** | `persist_permission_matrix(static_run_id=…, apk_id=…)` receives `apk_id` when the caller supplies it; **dict_unknown upsert** does not record `apk_id`. |
| **`static_run_id`** available? | **Yes (matrix)** | Carried on `static_permission_matrix.run_id`; **not** on `dict_unknown` rows from static. |
| **`package_name` / `version_code`** available? | **Yes** | From `report.manifest` for dict_unknown `example_package_name`; `version_code` is on manifest object but **not** stored on unknown upsert (only package in payload). |
| Link **matrix rows** back to APK identity? | **Partially** | `static_permission_matrix` has `run_id`, `apk_id`, `package_name`, `permission_name`; joins to artifact/registry tables are **run-scoped** / deployment-dependent. |
| **`source` label for Scytale** (obs / provenance)? | **TBD for S2** | Queue rows use `source_system="static-analysis"`. Erebus contract cites `virustotal` / `apk_manifest` / `other` for **`obs_sample.source`** — agree spelling before writes. |
| Distinguish **Erebus VT** vs **Scytale** in PI obs? | **Not without schema/contract extension** | Today **`UNIQUE(sample_id, permission_string)`** and malware-leaning `sample_id` semantics; **`source` is not in the unique key** — cross-producer collision risk until identity model is extended (see Erebus contract § Multi-producer). |

**Verdict:** **Ready for S2 design** (documentation + identity workshop). **Not ready** for blind `obs_sample` writes until `sample_id`/`source`/uniqueness questions are resolved with Erebus/DBA.

---

## 7. S1 conclusion: code changes needed?

**No mandatory code changes for S1** if the goal is alignment **documentation + operator clarity**. S1.5 adds **tests + classifier contract doc** only.

---

## 8. Proposed S2 identity model (open questions)

1. **Subject key:** Use **`static_run_id` + permission_string**, **`apk_id`**, or **global artifact sha256** as the stable join to PI?  
2. **`sample_id` column:** New surrogate for “static subject”, or nullable extension of malware `sample_id` semantics?  
3. **`source` / `source_system`:** e.g. `static-analysis`, `scytaledroid-device`, per APK vs per run.  
4. **Classifier parity:** Reuse Erebus **bucket/rule_fired** vocabulary on obs rows vs dict-only triage today.  
5. **Benign vs malware cohort:** Separate **reporting views** only, or separate **obs** partition columns?

---

## 9. Explicit non-goals (S1)

- No **`android_permission_obs_sample`** / **`android_permission_enrich_vt_*`** writes.  
- No schema / migration.  
- No importing Erebus Python modules.  
- No merging databases.
