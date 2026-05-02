# Shared Permission Intel — reconciliation (Erebus / ScytaleDroid / ObsidianDroid)

**Status:** architectural intent document only — no migrations, schema renames, or behavioral changes implied here.

**Intent:** evolve the existing **Erebus Contract A** / `android_permission_*` footprint as the spine for Contract v1. **Do not** spin up duplicate `permission_*` physical tables parallel to Contract A observations until reconciliation is complete.

**Repos referenced:**

| Repo | Path (this environment) |
|------|---------------------------|
| Erebus | `erebus-engine-fedora` |
| ScytaleDroid | `ScytaleDroid` |
| ObsidianDroid | `obsidiandroid` |

---

## 1. Concept reconciliation table

Column **Category** abbreviations: **D** = dictionary/reference, **O** = observation/fact ledger, **T** = triage/workflow, **G** = governance/policy/audit, **F** = feature / analysis output, **L** = legacy or mixed.

| Concept | Existing table/view/module | Repo owning / provisioning | Repo consuming (non-exhaustive) | Category | Current readers | Current writers | Disposition | Missing fields vs ideal Contract v1 | Risk |
|---------|----------------------------|----------------------------|----------------------------------|----------|-----------------|----------------|-------------|--------------------------------------|------|
| **Canonical dictionary** | No single unified table — **split dictionaries**: `android_permission_dict_aosp`, `android_permission_dict_oem`, `android_permission_dict_unknown` (+ optionally `android_permission_dict_queue` for workflow). | **Erebus** (MariaDB DDL + VT pipeline); **ScytaleDroid** targets same logical tables in **`android_permission_intel`** (dedicated DB) per `permission_intel_phase1`/operator provisioning. | Erebus CLIs/menus/API; Scytale static + DB utils; Obsidian joins in SQL. | D | Evidence pack queries; governance views; ML SQL; `permission_intel.py` helpers; `permission_dicts.py`. | Scrape/import (AOSP); OEM manual/import; VT pipeline upserts (`permission_record.py`); Scytale `permissions_db.persist_declared_permissions` → unknown OEM queue side. | **Keep** split dictionaries; treat “canonical dictionary” as a **logical** union across tables, not a new physical table. | Optional **materialized read model view** (`v_permission_dict_union_v1`) later if ergonomics suffer — not required Day 1. | Drift if Erebus and Scytale provision **different** subsets of DDL on two servers. |
| **AOSP dictionary** | `android_permission_dict_aosp` | **Erebus** (DDL + ingest); mirrored in **`android_permission_intel`** for Scytale. | Static analysis manifest catalog; Obsidian enrichment joins. | D | Obsidian `_fetch_permission_rows` LEFT JOIN `a`; Scytale `fetch_aosp_*`. | Erebus scrape + `android_permissions_queries.sql`; normalization migrations. | **Keep** | Versioning of scrape runs already on `android_permission_run_aosp_import` (Erebus). Align **semantic version** naming with governance snapshots across repos if needed. | Stale scrape vs live Google docs until refresh job runs. |
| **OEM dictionary** | `android_permission_dict_oem` (+ `vendor_id` FK metadata) | **Erebus** / shared intel DB | Obsidian joins; Scytale `fetch_oem_entries` | D | Consumers above | Operators; Erebus pipeline; Scytale `update_oem_seen` | **Keep** | `classification_source`/confidence semantics vs Contract v1 naming | OEM rows without disciplined vendor linkage |
| **Unknown dictionary / queue** | `android_permission_dict_unknown` + **`android_permission_dict_queue`** (workflow) + Erebus **LUT** `android_permission_triage_status_lut` (`0016`). | **Erebus** (full governance); **Scytale** intel DB mirrors dict + queue; triage FK hardening strongest on Erebus side. | Erebus queue API/diagnostics (`permission_queue_schema.py`, etc.); Scytale `upsert_unknown`/`insert_queue` from static. | D + **T** | Queue endpoints; diagnostics; governance views (`v_permission_triage_queue_v1`). | VT pipeline unknown upsert; Ops procedures; **`permissions_db.persist_declared_permissions`** (unknown upsert + `aosp_missing` queue). | **Extend** semantics only — **avoid** parallel “unknown_permissions_v2”. | Static path leaves **`example_sample_id` NULL**; could later reference `static_analysis_runs.id` or sha256 pointer without new tables. | Scytale triage strings must stay compatible with FK/LUT values present on deployed Erebus/intel DDL. |
| **Permission aliases / token normalization** | `android_permission_token_alias` (+ manifest alias normalization in pipeline) | **Erebus** (`0016`+, `permission_record.py`) | Future consumers join via raw token → canonical | D / **G** | Replay/audit tooling | **`permission_record.py`** bulk alias upsert | **Keep** | Scytale static normalization is **inline** (`permissions_db`) — optionally **reuse** alias ledger reads when persisting observations (phase 3). | Two normalization stories (Erebus alias ledger vs Scytale string rules) drifting. |
| **Prefix rules / prefix policy** | `android_permission_meta_oem_prefix`; **`android_permission_prefix_policy`**; policy events SPs (`0017`) | **Erebus** | Scytale reads prefixes via `fetch_vendor_prefix_rules` for **hints** (`oem_candidate`); classifier uses longest-prefix semantics in VT path | G + **D** helpers | Static analysis unknown path; classifier | Operators / SP **`sp_permission_prefix_policy_set`** | **Keep**; Scytale should **not** fork prefix tables. | “Candidate only” semantics (UNKNOWN + `OEM_CANDIDATE` bucket) enforced in **Erebus** doc contract — replicate as **documentation + shared classifier** later, not ad hoc SQL duplication. | Scytale `oem_candidate` triage ≠ Erebus obs `classification`/`bucket` unless aligned. |
| **Classification result** | **Persisted**: `android_permission_obs_sample`.`classification`, `bucket`, `rule_fired`; **Transient**: Scytale static heuristics in `persist_declared_permissions` + permission profiles (risk/capability) | Writer: **Erebus** `permission_record.py`; **Readers**: Obsidian, evidence pack — **no** persisted Contract A tuple on Scytale static path today except dict triage/status side-channels | O (when persisted) vs **F** (static-only) | Obsidian selects `classification`; Intel queries split by classification | **`permission_record.py`** (+ migration backfills); **not** `_build_permission_matrix` | **Extend** observation writes from Scytale to attach same tuple vocabulary **without** renaming columns | Static path lacks **bucket/rule/version** linkage to classifier | Divergent interpretations of APP_DEFINED vs unknown until unified |
| **Permission observation** | **`android_permission_obs_sample`** `(sample_id, permission_string)` UNIQUE; enrichment siblings `android_permission_enrich_*` | **Provisioned/shaped by Erebus**; **consumers**: Obsidian, Erebus tools | Obsidian **`analysis/orchestration/permission_features.py`**; **`database/db_permission_analysis_queries.py`** join `malware_sample_catalog` | **O** | Same + governance snapshot exports | **Erebus** VT/manifest ingestion **only** (no Scytale writer found) | **Extend** observation grain (nullable context columns OR subject abstraction) rather than **new ledger table** until proven necessary | `static_run_id`, `artifact_sha256`, `obs_subject_type`, optional `family_label`/device ids **nullable** for malware-only rows | If dual ledgers accidentally created, analytic joins fragment |
| **Triage override / triage audit** | `android_permission_triage_override`, `android_permission_triage_audit` / repair audit, **`android_permission_override_event`**, `sp_permission_triage_override_*`; queue rows | **Erebus** | Scytale does **operator-light** inserts into **unknown+queue**, not Contract A SP surface | **T + G** | Governance queue views/API | SPs / operator tooling | **Keep** | Scytale may **call** APIs/SPs in future vs writing dict directly — design choice | Bypassing SPs skips audit events |
| **Capability/risk tags** | **Operational DB (Scytale)**: `static_permission_matrix`, `permission_signal_observations`; **Intel**: `permission_signal_catalog`, `permission_signal_mappings`, `permission_cohort_expectations`; Obsidian derives **risk-ish counts** from `protection_level` + `classification` | **ScytaleDroid** schemas; **Obsidian** computes features | F + partial **G** | Web/handoff viewers; **`signal_evidence.persist_signal_observations`**; dashboards | Persistence stages + governance CSV import tooling | **Keep** semantic separation: **risk/signal/catalog** ≠ taxonomy `classification` | Link **signal rows** ↔ governance **version** (existing FK tooling in freeze/tests) ≠ obs ledger | Tags confused with lineage (`source`) or taxonomy (`bucket`). |
| **Dictionary/governance snapshots** | **Intel**: `permission_governance_snapshots`, `permission_governance_snapshot_rows` (Scytale); Erebus: governance snapshot scripts + `docs/governance_snapshot_contract.md` patterns | Operators import via **`permission_governance_import`** (Scytale); Erebus export paths | Freeze/affective scoring uses governance version | **G** | Import validation; risk actions referencing governance | CSV bundle load + Erebus export tooling | **Keep** | Optional cross-link column on obs rows (**classifier_bundle_version**) — nullable | Version skew between repos using different CSV generations |
| **ML/research feature views** | Obsidian **`permission_features.py`** builds dataframe from **raw SQL**; no stable DB view dependency today | **Obsidian** (feature orchestration); DB is **upstream** warehoused replica | — | **F** | Pipeline stages (`build_permission_feature_frame`) | Feature extractors write Parquet/feature stores downstream | **Wrap** upstream with **thin views** (Section 4) before physical DDL churn | N/A unless views miss columns ML needs |

---

## 2. Conceptual schema → Contract A physical mapping

Do **not** introduce these conceptual names as new tables unless a future phase proves a physical split is unavoidable. Map as follows:

| Conceptual alias (Contract v1 wording) | Contract A physical (today) |
|---------------------------------------|------------------------------|
| `permission_canonical` | Logical: rows in `android_permission_dict_aosp` ∪ `dict_oem` ∪ `dict_unknown` (distinct PK rules per table); optional future **read-only view**. |
| `permission_alias` | `android_permission_token_alias` (`raw_token`, `canonical_token`, `rule_version`, …). |
| `permission_prefix_rule` | `android_permission_meta_oem_prefix`; active policy linkage `android_permission_prefix_policy`. |
| `permission_classification_result` | Stored on **`android_permission_obs_sample`** as `classification` + `bucket` + `rule_fired` (plus `vendor_id`). **Absent** when only dict triage is updated without obs row — treat as intentional **ledger vs projection** distinction. |
| `permission_observation` | **`android_permission_obs_sample`** (+ optional linkage to enrichment tables). Not `static_permission_matrix`. |
| `permission_triage` | `android_permission_dict_unknown`.`triage_status` + workflow tables (`*_queue`, overrides, LUTs `android_permission_*_lut`). |
| `permission_capability_tag` | **System-specific**: Static capability grouping and catalog-driven profiles live in **Scytale** Python modules; **signals** catalogue in intel DB maps **risk signals**, not taxonomy buckets. Prefer **explicit join** semantics in docs (“capability_tags live in analytic layer / signal_catalog, not duplicated as obs columns”). |
| `permission_risk_tag` | `static_permission_matrix`/`static_permission_risk_vnext` (**Scytale**); `permission_signal_observations` (**Scytale** primary DB); not Contract A enums. |
| `permission_dictionary_version` | **`android_permission_run_aosp_import`** (per scrape); `perm_taxonomy_version` / tooling versions on Erebus run ledger (see `perm_taxonomy_updates.sql`); **intel** governance: `permission_governance_snapshots.governance_version` + **`snapshot_sha256`**. Consolidate naming in documentation as **dictionary_version** vs **classifier_bundle_version**. |

---

## 3. Observation grain — malware sample vs Scytale static

**Existing anchor:** `android_permission_obs_sample` is **`UNIQUE(sample_id, permission_string)`** with **`sample_id` typed as BIGINT** and semantics today = **malware specimen id** coherent with **`malware_sample_catalog`** joins in Obsidian.

**Requirement:** additionally support:

- Malware lineage: VT context, optional family label (often **joined** via `malware_sample_catalog`, not stored per permission row — **fine**).
- Scytale static: `static_run_id`, package, apk/session context, hashes.

### Recommended direction (minimal blast radius)

**Phase A — prefer extending the existing ledger** with **nullable discriminators**, not sibling tables:

- Add (when implemented in a future migration cycle, **not here**) nullable columns along the lines of:

  - `subject_kind` ENUM or VARCHAR — e.g. `malware_sample` | `static_run` | (future `device_snapshot`).
  - `static_run_id` BIGINT UNSIGNED NULL FK → **`static_analysis_runs`(id)** on the warehouse that hosts both domains **or** NULL when `subject_kind <> 'static_run'`.
  - `artifact_sha256` CHAR(64) NULL (denormalized convenience for both kinds).
  - Keep **`sample_id`** populated for legacy malware path; for static runs either repurpose semantics **only behind subject_kind** (still one BIGINT) **or** set `sample_id` NULL where inappropriate and require `static_run_id` — **preference:** keep **`sample_id` for malware only**, use **`static_run_id` column for static**, both nullable with CHECK-like app constraint (**subject_kind determines which FK is populated**).

- **Indexing:** composite unique constraint must migrate from `(sample_id, permission_string)` to a **predicate unique** compatible with MariaDB realities — most teams implement as:

  - `UNIQUE` on `(subject_kind, coalesce(sample_id,-1), coalesce(static_run_id,-1), permission_string)` **is awkward** → cleaner: **`observation_key` BINARY/CHAR hash** surrogate UNIQUE, or **`UNIQUE` partial indexes if/when infra supports**.

Document the **logical** uniqueness rule in Contract v1 as  
**“one row per `(subject_kind, subject_natural_key, normalized_permission_string)`”**  
and postpone physical FK choice until DBA picks hash vs composite unique.

### Not recommended initially

| Approach | Reason |
|---------|--------|
| **Separate observation tables** + compatibility views | High duplication unless absolutely required — contradicts anti-greenfield stance. Only revisit if FK/CHECK coupling between primary DB `static_analysis_runs` and intel-hosting obs proves operationally brittle. |
| **Unified subject table** enforced for every ingest | Powerful but heavyweight — defer until ≥2 observation kinds deployed in prod. |

**Obsidian impact:** stays stable if **`v_permission_obs_ml_enriched_v1`** (recommended name below) shields column experiments and exposes **`sample_id` + malware-only semantics** unchanged for banking cohort pipelines.

---

## 4. ScytaleDroid gap (smallest change)

**Facts:**

- **`static_permission_matrix`** is **`UNIQUE(run_id, permission_name)`**, operational **static analysis output**, not the shared taxonomy observation ledger (`docs/contracts/persistence_uow_tables.md`; `persist_permission_matrix` in `permission_matrix.py`).
- Scytale **already feeds** **`android_permission_intel`** via **`StaticAnalysis/persistence/permissions_db.py`**: **`android_permission_dict_unknown`** upserts and **`android_permission_dict_queue`** for `aosp_missing` promotions — **`example_sample_id` intentionally NULL** today.

**Smallest Contract v1–aligned incremental step:**

1. **Reuse** **`permission_record.py`**’s taxonomy tuple (**classification / bucket / rule_fired / vendor_id**) as the **single vocabulary** specification (callable as library or replicated SQL snippets **only until** shared package exists).

2. **After** taxonomy is available (offline call into shared classifier service **or** importable Python shim), **`persist_permission_matrix` completion hook** (or adjacent transaction stage) **UPSERTs** into **`android_permission_obs_sample`** with:

   - `subject_kind = 'static_run'`, `static_run_id = run_id`, `package_name`, `artifact_sha256` from `static_analysis_runs.sha256`, `permission_string` normalized consistently with **Erebus** token rules,
   - `classification`/`bucket`/`rule_fired` from shared classifier outputs,
   - `source = 'apk_manifest'` (already an allowed ENUM value on Contract A DDL).

3. Keep **`static_permission_matrix` unchanged** for existing web/handoff/session diagnostics — observations become **derivative joinable truth** for cross-cohort Permission Intel queries, not a replacement for severity columns.

This preserves static analysis pipelines while closing the **“no obs writer”** gap.

---

## 5. ObsidianDroid stability — recommended views

**Current coupling:** `analysis/orchestration/permission_features.py` issues **hand-written SQL**:

- `FROM android_permission_obs_sample ops`
- LEFT JOIN `android_permission_dict_aosp`, `dict_oem`
- Filters **only `sample_id IN (...)`** and uses **`classification`** + **`protection_level`** joins.

Separately **`database/db_permission_analysis_queries.py`** joins obs + catalog + enrichment `android_permission_enrich_vt_current`.

**Problem:** widening `obs_sample` with nullable subjects risks silent fan-out bugs if Obsidian joins assume `sample_id NOT NULL`.

**Recommendation:**

| View name | Purpose |
|-----------|---------|
| **`v_permission_obs_malware_v1`** | **Stable malware-only contract:** `WHERE subject_kind IS NULL OR subject_kind = 'malware_sample'` (or **`static_run_id IS NULL`** pre-migration) — exposes **`sample_id`, `permission_string`, `classification`, `bucket`, `rule_fired`, `vendor_id`, `source`, timestamps** + optional pre-joined **`protection_level`**, **`constant_value`** columns with fixed aliases matching today’s `_fetch_permission_rows` aliases (`permission_source` if desired as computed). |
| **`v_permission_obs_normalized_v1`** | **Unified read model:** all subject kinds projected to canonical columns (**`effective_subject_kind`**, **`malware_sample_id`**, **`static_run_id`**, **`permission_string`** …) for cross-domain analytics. |

**ML features:** refactor Obsidian **`_fetch_permission_rows`** to **`SELECT … FROM v_permission_obs_malware_v1`** (name negotiable — **explicit “malware”** avoids ambiguity). Optionally add **`v_permission_features_for_ml_v1`** wrapping normalized obs + hashed permission tokens only if notebooks need narrower surface.

Rename list in prompt (`v_permission_sample_features_v1`) — **defer** naming until feature owners pin column sets; **`v_permission_obs_malware_v1` + normalized superset view** suffice as stable boundaries.

---

## 6. Classification enum alignment — standard vocabulary

**Two orthogonal layers:**

| Layer | Purpose | Canonical values (recommended) |
|-------|---------|-------------------------------|
| **L1 — `classification`** (obs row coarse enum mirroring DDL) | `AOSP`, `GOOGLE`, `OEM`, `APP_DEFINED`, `UNKNOWN` — **already** `ENUM` on `android_permission_obs_sample`. | **Freeze** spelling; additive change only via **DB migration**. |
| **L2 — `bucket` strings** (`VARCHAR`) | Resolution policy outcome / taxonomy — aligns with **`android_permissions_schema_contract.md`** rules (`AOSP_EXACT`, `AOSP_HIDDEN_PRIV`, `GOOGLE_GMS`, `OEM_EXACT`, `OEM_CANDIDATE`, `APP_DEFINED_OTHER`, etc.). | **Single documented registry** (`docs/...taxonomy.md` or appendix to Contract doc) enforced by **migration seed + linter on CSV exports**, **not** second ENUM until MariaDB ergonomics validated. |

**Adjacent but distinct:**

- **`triage_status`** on **`dict_unknown`** (e.g. `new`, `aosp_missing`, `oem_candidate`, `malformed`, `app_defined`, …)` — aligns with **`android_permission_triage_status_lut`**, **not interchangeable** with L2 buckets.
- Scytale static uses words like **`app_defined`**, **`aosp_missing`** as **dictionary workflow** statuses — corresponds to **`permission_triage`**, **not** `bucket`.

**Recommendation on user’s scattered labels:**

| Label | Placement |
|-------|-----------|
| `AOSP_EXACT`, `AOSP_HIDDEN_PRIV` | **bucket** strings |
| `GOOGLE_GMS` | prefer **canonical** **`GOOGLE_GMS`** consistently (alias `GMS_NAMESPACE` internally if needed — document only one public string) |
| `OEM_EXACT`, `OEM_CANDIDATE` | **bucket** (`OEM_CANDIDATE` under strict-OEM posture = candidate not promoted) |
| `APP_DEFINED_OTHER` vs `APP_DECLARED` | Use **`APP_DEFINED_OTHER`** per Erebus default rule; **`APP_DECLARED`** only if distinguishing custom **definition** vs **use** becomes necessary — declare as **distinct bucket** subset. |
| `UNKNOWN` vs `MALFORMED` | **`MALFORMED`** sits in **dict_unknown triage** and static intake; **`UNKNOWN`** remains L1 classifier catch-all for unresolved obs row — docs must say **MALFORMED ≠ malicious**. |
| `DEPRECATED`, `IGNORED`, `IGNORE` | Prefer **dictionary/triage/catalog flags** (`is_deprecated` on AOSP dict; triage lut `ignore`) — avoid overloading **`bucket`** until needed. |

**Enforcement stance:** **`shared DB`** holds authoritative **historic tuples** (`classification`,`bucket`,`rule_fired`). **Canonical vocabulary** enforced by **migration comments + exporter validation + eventual shared classifier package** publishing the allowed set as data (JSON) — avoid copying **rule ordering** logic into three repos.

---

## 7. Behavior source of truth (today vs target)

**Today — rule ordering / classification:**

| Behavior | Location | Notes |
|----------|-----------|-------|
| **Contract A ingest classifier** ordering (AOSP exact → hidden → GMS namespaces → OEM exact → OEM prefix candidate posture → defaults) | **Erebus** `docs/data/android_permissions_schema_contract.md` + **`permission_record.py`** construction of obs rows (`has_bucket`,`has_rule_fired`) | **Authoritative behavioral spec** until extracted. |
| **Unknown triage heuristic for static manifests** (`malformed`, `app_defined`, `oem_candidate`, `aosp_missing`, queue insert) | **ScytaleDroid** **`StaticAnalysis/persistence/permissions_db.py`** | Overlaps **intent** but **not** bitwise identical tuple output vs Erebus. |
| **Protection / guard strength / severity** surface for static UX | **`StaticAnalysis/modules/permissions/*`** (`catalog.py`, `profile.py`, signals) | Capability/risk — **orthogonal** taxonomy. |

**Obsidian:** **consumes persisted results** — no authoritative classifier fork.

### Target (“north star”) extraction candidates

Later **extract** into a **`permission_intel_classifier`** artefact:

1. **`erebus-database/db_query/vt_android_permission_pipeline/permission_record.py`** taxonomy builder — core decision tree emitting `(classification,bucket,rule_fired,vendor_id)`.

2. **Shared rule metadata** sourced from **`android_permission_meta_oem_prefix`**, dictionaries, governance version id.

3. **Scytale** replaces inline triage branching for **OBS ledger** persistence with **`classifier.classify_manifest_permission(token, manifest_context) → Tuple`** aligned with (1).

4. **Thin DB SPs/views** unchanged — **behavior** centralized in Python package pinned by semver pinned alongside **`perm_taxonomy_version`**.

Until extraction ships, **`android_permissions_schema_contract.md`** clause ordering remains **semantic law** — Scytale should document deviations explicitly when writing **dictionary-only** statuses.

---

## 8. Phased plan (documentation / contracts only phase)

| Phase | Scope | Gates |
|-------|-------|-------|
| **P0 — locked** | This reconciliation circulated; taxonomy appendix lists **bucket** strings **+** **`triage_status` LUT**. | Maintainer sign-off on **L1 enum freeze**. |
| **P1 — views** | Add **`v_permission_obs_malware_v1`** (+ optional **`v_permission_obs_normalized_v1`**) via migration when ready; switch Obsidian to view reads. | Obsidian parity tests vs historical query results. |
| **P2 — obs grain DDL** | Nullable subject columns / uniqueness migration on **`android_permission_obs_sample`** coordinated **Erebus + warehouse DBA**. | No duplicate ledger table. |
| **P3 — Scytale upsert bridge** | Static pipeline writes obs rows referencing **`static_run_id`** + **`source='apk_manifest'`** + shared classifier tuples. | `static_permission_matrix` regressions unchanged. |
| **P4 — classifier package** | Extract shared library; pin versions on both repos; **`perm_taxonomy_version`** propagated to obs/metadata. | Remove duplicated branching in **`permissions_db.py`** for taxonomy (keep malformed hygiene). |

---

## 9. Open decisions (explicit)

1. Which **physical MariaDB instance** hosts `android_permission_obs_sample` once static runs ingest — identical DB as **`android_permission_intel`**, **`erebus_database_dev`**, or **federated replication**?

2. **Unique key** evolution strategy for **`(subject, permission)`** under MariaDB constraints.

3. Whether **`sample_id`** may remain **dual-use** (**always** malware) vs renaming column long-term (**breaking**) — reconcile favors **additive columns**.
