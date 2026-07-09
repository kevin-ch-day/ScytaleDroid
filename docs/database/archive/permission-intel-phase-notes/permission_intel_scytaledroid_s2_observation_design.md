# Permission Intel — ScytaleDroid S2 observation design

**Phase:** S2 **design only** (no PI observation INSERT in this deliverable). **§§11–16** lock **S2-P0 / S2-P1**: decision matrix, minimal field contract, queue normalization proposal, DDL split, preconditions.  
**Non-goals:** No schema changes, migrations, `android_permission_obs_sample` writes, D0–D4 workstreams, static pipeline refactor, or importing Erebus Python code into ScytaleDroid. **Allowed:** docs, cross-repo alignment, and **pure** transform tests (no DB).

**Prerequisites:** [S1 read-path audit](permission_intel_scytaledroid_s1_read_path_audit.md), [S1.5 classifier contract](permission_intel_scytaledroid_s1_5_classifier_contract.md). Cross-repo contract: Erebus `docs/data/android_permissions_schema_contract.md`.

---

## 1. Context (current posture)

- ScytaleDroid reads PI via `Database.db_core.permission_intel` and writes **governance-style** rows: `android_permission_dict_unknown`, `android_permission_dict_queue`, OEM `last_seen`, etc.
- **`android_permission_obs_sample`** and **`android_permission_enrich_vt_*`** are **not** written by Scytale today.
- Static analysis already produces: normalized **`permission_string`**, **`package_name`**, optional **`apk_id`** and **`static_run_id`** on **`static_permission_matrix`** (Scytale **core** DB), and **SHA-256** on the analysis report path (`persist_permissions_to_db` reads `report.hashes["sha256"]` but does not yet attach it to PI dict rows).

---

## 2. Proposed subject identity model

### 2.1 What is available at permission persistence time (today)

| Signal | Static APK analysis | Notes |
| --- | --- | --- |
| `permission_string` | Yes | Verbatim manifest string; aligns with PI dictionaries. |
| `package_name` | Yes | From manifest; also on matrix rows. |
| `version_name` / `version_code` | Yes (manifest) | Not stored on current `dict_unknown` upsert; easy to add to provenance payload later. |
| SHA-256 | Yes (artifact hash) | On report; should become **mandatory** for Scytale→PI obs semantics when the same package version is re-scanned. |
| `static_run_id` | Yes (when persisted) | Core DB `static_permission_matrix.run_id`. |
| `apk_id` | Sometimes | Core registry id when the run is wired to an artifact row; nullable in matrix writer. |
| Device inventory / runtime harvest | Separate flows (if any) | Not assumed in static path; design reserves labels for **device** observations. |

### 2.2 Canonical observation subject (recommendation)

For **reproducible research**, the stable cross-producer spine should be:

1. **`permission_string`** (join key across Erebus and Scytale).
2. **Artifact identity:** **`sha256`** of the APK **when** the observation is from static analysis of a concrete binary.
3. **Operational identity:** **`static_run_id`** (and optionally **`apk_id`**) for traceability inside Scytale and for joins back to `static_permission_matrix`.

**`sample_id` on `android_permission_obs_sample` today:** the column is **`INT UNSIGNED NOT NULL`** and participates in **`UNIQUE (sample_id, permission_string)`**. In Erebus, it is aligned with **malware catalog** semantics (`malware_sample_catalog.sample_id`) for VT-backed workflows. That makes a naive reuse of “whatever integer we have in Scytale” **unsafe** without a **disjoint allocation** or **schema evolution**.

### 2.3 Identity options (evaluate; pick one with Erebus/DBA)

| Option | Idea | Pros | Cons |
| --- | --- | --- | --- |
| **A — Synthetic PI subject registry** | Introduce a small PI (or Scytale-core) table that allocates a **dedicated `sample_id`** per `(producer, sha256)` or per `(producer, static_run_id)` before obs insert. | Keeps current **`UNIQUE(sample_id, permission_string)`**; explicit mapping; auditable. | Requires **new table + migration** and a writer contract (out of scope until approved). |
| **B — Reserved ID ranges** | E.g. high bit / offset so Scytale ids never collide with malware ids. | No bridge table if policy is strict. | **Fragile** operationally; easy to misconfigure; poor ergonomics. |
| **C — Extend uniqueness (future DDL)** | Add `producer` / `subject_key` / `obs_subject_type` and replace unique key with e.g. `(producer, subject_key, permission_string)` or include `source` in uniqueness. | Clean multi-producer model. | **Schema migration**; Erebus writer + analytics must agree. |
| **D — Observations only in Scytale core** | Duplicate obs-like table on core DB; PI remains VT/malware. | Avoids PI collision. | **Splits** the shared Permission Intel story; contradicts “shared PI” goal. |

**Recommended direction for implementation planning:** **Option A or C** — treat **collision avoidance** as a first-class requirement; reject **B** for production; avoid **D** unless regulators require an air gap.

**Bridge identity (naming):** whether the registry calls the key `obs_subject_id`, `pi_sample_id`, or reuses `sample_id` as “observation subject id” is a **wording** choice; the design requirement is: **one integer (or future composite key) that is unambiguous across producers**.

---

## 3. Source labeling model

### 3.1 Erebus today (`android_permission_obs_sample`)

Reference DDL (`android_permissions_schema.sql`) defines:

- `source ENUM('virustotal','apk_manifest','other') NOT NULL DEFAULT 'virustotal'`

So **fine-grained** producer strings such as `scytaledroid_static` **do not fit** the column without a **future ENUM extension** or **convention** that folds producers into the three buckets.

### 3.2 Proposed labeling (design)

| Scytale capability | Proposed `source` (obs_sample) | Proposed free-text / future column | Notes |
| --- | --- | --- | --- |
| Static APK manifest permissions | **`apk_manifest`** | `source_system = 'scytaledroid_static'` (if/when a VARCHAR column exists on obs, or on a bridge/registry row) | Matches “manifest-derived” semantics; distinguishes malware vs benign **only** via other dimensions (sha256 cohort, governance). |
| Device-installed app permission harvest | **`other`** *or* future ENUM value **`device_static`** / **`device_runtime`** after migration | `source_system = 'scytaledroid_device_harvest'` | Until ENUM grows, **`other` + source_system** (pattern used on `enrich_vt_event`) is the least invasive story **once** the table supports it. |
| Unknown / experimental | **`other`** | Explicit tag | Avoid overloading `virustotal`. |

**Queue vs obs:** Today Scytale queue rows use `source_system = 'static-analysis'`. For **obs_sample**, prefer **`scytaledroid_static`** (or **`scytaledroid`** + channel suffix) in a **VARCHAR provenance field**, not the ENUM, until cross-repo ENUM migration is scheduled.

**Comparison to Erebus:** `virustotal` remains VT/malware-primary; `apk_manifest` can carry **any** manifest extractor including Scytale static **if** operators accept that ENUM breadth; otherwise use `other` and document the mapping.

---

## 4. Table fit analysis (`android_permission_obs_sample`)

### 4.1 What fits as-is (conceptually)

- **`permission_string`**, **`package_name`**, **`sha256`**, **`classification` / `bucket` / `rule_fired` / `vendor_id`**: compatible with Scytale once a **shared classifier** or a **static-specific rule** produces the same tuple vocabulary as Erebus (or a defined subset).
- **Brownfield note:** Erebus writers may add optional columns (e.g. **`run_id`**) when present on the live table; Scytale should follow the same **introspection** pattern when implementation starts, not assume minimal DDL only.

### 4.2 What does *not* fit safely without follow-on work

- **`sample_id` + UNIQUE(sample_id, permission_string)** without **`source` in the key**: two producers could theoretically share an integer id space → **silent overwrite** or **incorrect upsert** behavior.
- **ENUM `source` cardinality**: too coarse for “which Scytale mode” unless extended.
- **Provenance depth**: version codes, device ids, tool versions may exceed current columns — may need **JSON** / **sidecar registry** / **migration**.

### 4.3 Adapter / bridge / alternate table

| Approach | When to use |
| --- | --- |
| **No adapter — direct obs_sample** | After **identity + ENUM** issues are resolved (Option A or C). |
| **Bridge/registry table** (recommended staging concept) | Maps `(producer, sha256, static_run_id, …)` → **`sample_id`** used in obs_sample; keeps PI table normalized. |
| **Producer-specific observation table** | Only if PI must remain VT-exclusive permanently — **not recommended** for shared intel. |
| **Extended uniqueness** | Best long-term if many producers; requires coordinated migration. |

**Design conclusion:** **`android_permission_obs_sample` can represent Scytale observations** provided **`sample_id` semantics and UNIQUE key** are made **producer-safe**. Until then, **do not** write rows.

---

## 5. Queue action normalization (`aosp_promote`)

### 5.1 Is `aosp_promote` an “official” PI queue action?

**No** — Erebus `permission_queue_apply.class_action_map` keys **`aosp`**, not `aosp_promote`. Scytale now emits **`aosp`** for `aosp_missing` rows, and **`permission_dicts.insert_queue`** normalizes legacy **`aosp_promote` → `aosp`** (see [permission_intel_schema_drift_erebus_vs_scytaledroid.md](../../permission_intel_schema_drift_erebus_vs_scytaledroid.md)).

### 5.2 Decision options

| Option | Action |
| --- | --- |
| **R1 — Scytale maps on write** | Before insert, map `aosp_promote` → **`aosp`** (or whatever Erebus `class_action_map` expects). |
| **R2 — Erebus normalizes on read/apply** | Queue apply treats `aosp_promote` as promotion intent equivalent to `aosp`. |
| **R3 — Shared LUT** | `android_permission_dict_queue` actions validated against a **PI LUT** maintained with migrations; both repos import **documentation + tests** only. |

**Recommendation:** **R1 + R2 in combination** for robustness — **R1 is implemented in Scytale** (`aosp` emission + `insert_queue` normalizes `aosp_promote`). **R2** remains valuable for **brownfield** queue rows already stored as `aosp_promote`. **R3** if queue verb sprawl continues.

### 5.3 What queue apply “expects”

Erebus `evaluate_queue_row` normalizes actions into a small set (`apply`, `defer`, `skip`, `reject`, …) and pairs with **`proposed_classification`**. Scytale’s payload leaves **`proposed_bucket` / `proposed_classification` null** for `aosp_missing` **→** **`aosp`** queue rows; **`class_action_map`** still maps **`aosp` → `AOSP`** when apply runs. Optionally populate explicit proposed fields after Erebus owner sign-off.

---

## 6. Provenance design

### 6.1 Minimum viable provenance (static)

| Field | Target | Storage idea |
| --- | --- | --- |
| SHA-256 | Required for static obs | `android_permission_obs_sample.sha256` (respect NOT NULL variants per deployment). |
| `package_name` | Required when known | Column exists. |
| `static_run_id` | Strongly recommended | Use **`run_id`** column when present (Erebus pattern); else registry/bridge. |
| `apk_id` | Optional | Bridge/registry or JSON blob; helps join to core catalog. |
| `version_code` / `version_name` | Recommended | Not in minimal DDL — **registry sidecar** or future columns. |
| Analysis tool / schema version | Recommended | `source_version`-style string; mirror `enrich_vt_event` naming where possible. |
| Observed time | Default | `observed_at_utc` (DB default acceptable if ingest is immediate). |

### 6.2 Device-harvest provenance (future)

Add **device snapshot id**, **inventory row id**, **OS build**, and **collection mode** (runtime vs static-on-device) — likely **`source_system`** + sidecar; avoid overloading `package_name` alone.

---

## 7. Comparison model (reporting)

### 7.1 Join spine

- **Primary analytic join:** `permission_string` → PI dictionaries / governance / rollups.
- **Cohort dimensions:**  
  - **Producer:** `source` ENUM + optional `source_system` / registry.  
  - **Subject class:** malware specimen (Erebus VT) vs **APK artifact** (Scytale sha256) vs **device installation** (future).  
  - **Time:** `observed_at_utc` and/or Scytale run timestamps.

### 7.2 VT malware vs real-device observations

Do **not** rely on `package_name` alone (many apps share names across builds). Prefer **`sha256`** for APK-static parity and a **device+package+snapshot** key for device cohorts.

**Reporting pattern:** `permission_string` in the GROUP BY; filters on `source` / `source_system` / subject registry; optional **governance snapshot version** for “what we believed at analysis time.”

---

## 8. Risks

| Risk | Mitigation |
| --- | --- |
| **`sample_id` collision** | Registry or extended UNIQUE key; never “guess” ids. |
| **ENUM too coarse** | Document `source_system` / bridge; plan ENUM migration. |
| **Classifier mismatch** | Reuse Erebus taxonomy emission or document static-only `rule_fired` prefix. |
| **Replay / re-run static** | Same sha256 → upsert semantics; define whether `observed_at_utc` refreshes or is preserved. |
| **Split DB grants** | PI vs primary catalog — ensure Scytale PI user can INSERT obs if/when enabled. |
| **Queue action drift** | **Mitigated in Scytale** (`aosp` + insert normalize); **R2** on Erebus for brownfield rows per §5 / §14. |

---

## 9. Open questions (for Erebus + Scytale + DBA sign-off)

1. **Authoritative subject id:** registry in PI vs Scytale core vs shared warehouse?  
2. **Should `apk_manifest` ENUM officially mean “any manifest extractor” or only non-Scytale?**  
3. **Is `run_id` on `obs_sample` guaranteed** in target deployments, or must Scytale work without it?  
4. **Device harvest:** same table or deferred phase?  
5. **Classifier:** must Scytale call Erebus-equivalent rules offline, or is a **lighter static tuple** acceptable for v1?  
6. **Retention:** are Scytale benign observations subject to different TTL than malware obs?

---

## 10. Recommended implementation phases (after design approval)

| Phase | Scope | Touch |
| --- | --- | --- |
| **S2-P0** | **Decision matrix + contracts signed** — identity, uniqueness, source/provenance, queue mapping; **no** `obs_sample` writes | Docs, cross-repo ticket, optional transform tests |
| **S2-P1** | **Queue / contract hardening** — Scytale **`aosp` + insert normalize** done; optional **Erebus R2** for legacy rows; freeze minimal observation payload helpers **without** PI INSERT | Residual Erebus small change; still **no** obs writes |
| **S2-P2** | **Subject registry or extended uniqueness** (DDL) — producer-safe ids | Migrations (future), Erebus + DBA |
| **S2-P3** | **Scytale observation writes** — `obs_sample` upsert behind flag + parity tests | Scytale `permission_intel` + static hook |
| **S2-P4** | **Reporting** — views / doctor checks comparing producers by `permission_string` | SQL / ops |

Sections **11–16** detail **S2-P0 / S2-P1** only (decision matrix, contract proposal, queue resolution, DDL split, preconditions).

---

## 11. S2-P0 — Decision matrix: observation identity options

Compare paths for letting Scytale contribute rows that **eventually** land in shared PI (typically `android_permission_obs_sample` or successor semantics).

| Criterion | **A. Shared subject registry / surrogate `subject_id`** | **B. Naive reserved `sample_id` ranges** | **C. Extend `obs_sample` uniqueness** (producer / source / sha256 / `static_run_id` / …) | **D. Producer-specific Scytale table only** | **E. Bridge / staging → PI** |
| --- | --- | --- | --- | --- | --- |
| **Idea** | PI (or shared) table allocates an integer **surrogate** per `(producer, artifact_sha256, …)`; `obs_sample.sample_id` holds that surrogate. | Convention: Scytale uses e.g. high-bit range so it never collides with malware ids. | Replace `UNIQUE(sample_id, permission_string)` with a key that includes producer and/or natural keys. | Scytale core DB holds `scytale_permission_observation`; PI unchanged. | Staging table in PI or core; ETL/promote into `obs_sample` after validation. |
| **Pros** | Keeps current PK shape; **auditable** mapping; explicit **collision avoidance**; works with brownfield Erebus writers if surrogate is the only `sample_id` meaning for non-VT. | No new table **if** range discipline holds. | **Conceptually clean** multi-producer model; natural keys visible in UNIQUE. | Zero collision risk **inside** PI; fastest to prototype locally. | Decouples ingest from canonical table; **review gate** before PI visibility. |
| **Cons** | New table + allocation logic; must define **idempotency** (same sha256 → same surrogate). | **Operationally brittle**; overflows; breaks if malware ids grow; **no DB enforcement** of range. | **Breaking** for analytics expecting old UNIQUE; Erebus VT writer + migrations must align; larger migration. | **Splits** shared Permission Intel; duplicate dictionaries/joins; not the platform direction. | **Two hops**; ETL complexity; still need **A** or **C** unless staging **is** the long-term home. |
| **Migration risk** | **Medium** — additive DDL for registry; may keep `obs_sample` UNIQUE as-is. | **High** (reputation risk) — silent wrong merges if violated. | **High** — uniqueness + possibly backfill. | **Low** on PI — **high** on analytics fragmentation. | **Medium** — staging DDL + promote rules. |
| **Query / reporting** | Join registry for sha256 / producer / Scytale ids; straightforward. | Simple until collision; then **wrong**. | Simple filters on producer columns; best long-term. | Cross-DB joins or exports; heavy. | Depends on promotion lag and staging schema. |
| **Erebus compatibility** | **Good** if VT continues using malware `sample_id` and registry assigns **disjoint** surrogates for Scytale. | **Poor** — not enforceable. | **Good** after coordinated migration. | **Poor** for unified PI dashboards. | **Good** if promotion produces rows compatible with Erebus. |
| **ScytaleDroid compatibility** | **Good** — sha256 + `static_run_id` / `apk_id` map cleanly to registry row. | **Deceptively easy** — discouraged. | **Good** after DDL. | **Easy** short-term; **bad** for shared spine. | **Good** for batched ingest. |
| **Cross-producer comparison** | **Yes** — same `obs_sample` + join to registry. | **Only if** range never fails. | **Yes** — best class of solution. | **Awkward** — union queries. | **Yes** after promotion. |

### 11.1 S2-P0 conclusion (identity)

- **Do not** adopt **B** for production.  
- **Do not** default to **D** unless policy mandates a Scytale-only ledger.  
- **Prefer A or C** (or **E** as a **temporary** gate feeding **A/C**).  
- Final choice between **A** and **C** is a **DBA + Erebus** tradeoff: **A** minimizes change to `UNIQUE(sample_id, permission_string)`; **C** is cleaner semantics long-term.

---

## 12. S2-P0 / S2-P1 — Recommended option summary

| Gate | Recommendation |
| --- | --- |
| **P0** | **Do not write `obs_sample` yet.** Lock the **decision matrix** (§11), **minimal field contract** (§13), **queue mapping** (§14), and **preconditions** (§16). |
| **P1** | **Design** (and optionally implement **code-only** pieces) for: (1) **optional Erebus R2** for legacy `aosp_promote` queue rows (**Scytale R1 done**); (2) **registry or uniqueness spec** ready for migration workshop — **no** obs INSERT. |
| **P2** (later) | **DDL**: subject registry **or** extended uniqueness + any `source_system` / provenance columns on PI. |
| **P3** (later) | **Scytale writer** + **`source` / producer** semantics; **reporting views** comparing Erebus vs Scytale on `permission_string` + cohort dimensions. |

**Primary recommendation:** **P2 implements Option A (registry + surrogate `sample_id`)** unless DBA drives **Option C** in one step; use **E** only if a **human/ops promotion** step is required before PI visibility.

---

## 13. S2-P0 — Minimal contract proposal (pre–PI write)

Scytale **must** be able to populate the following **logical** payload for each candidate observation row **before** any INSERT into PI is allowed. (Names are **contract** names; physical columns may differ until DDL catches up.)

| Field | Required? | Notes |
| --- | --- | --- |
| `permission_string` | **Required** | Verbatim manifest string; matches PI dictionaries / matrix `permission_name`. |
| `artifact_sha256` | **Required** (static APK path) | 64-char hex; primary **artifact** identity for research replay. |
| `static_run_id` | **Required** when matrix/run persisted | Traceability to `static_permission_matrix.run_id`. |
| `apk_id` | **Optional** | Core artifact registry id when available. |
| `package_name` | **Required** when known | From manifest. |
| `version_code` / `version_name` | **Recommended** | Manifest metadata; may live in registry sidecar until `obs_sample` grows columns. |
| `producer` | **Required** (logical) | Constant e.g. **`scytaledroid`** for filtering and registry allocation — not necessarily a column today. |
| `source` | **Required** (PI ENUM) | **Short-term:** map static manifest extraction to **`apk_manifest`** *if* operators accept ENUM breadth; otherwise **`other`** until ENUM extended. |
| `source_system` (or equivalent) | **Recommended** | Fine-grained label e.g. **`scytaledroid_static`** — requires **VARCHAR column or registry row** in a later DDL phase. |
| `observed_at_utc` | **Required** | Ingest or analysis completion time; timezone policy UTC. |
| Classifier tuple | **Recommended** | `classification` / `bucket` / `rule_fired` / `vendor_id` aligned with Erebus vocabulary **or** an explicitly prefixed static-only `rule_fired` documented in contract. |
| `dict_unknown.triage_status` (parallel) | **Optional** | Observations are **not** triage; if both dict and obs are written, document ordering and precedence. |

**Idempotency rule (design):** same **`(producer, artifact_sha256, permission_string)`** (plus agreed subject key) should **upsert**, not multiply unbounded duplicate facts — exact SQL behavior follows **A** or **C** from §11.

---

## 14. S2-P1 — Queue action normalization proposal

| Question | Short-term (P1) | Long-term |
| --- | --- | --- |
| Should **Erebus queue apply** accept `aosp_promote`? | **Yes (recommended):** treat **`aosp_promote`** as equivalent to **`aosp`** for promotion intent in `evaluate_queue_row` **or** pre-apply SQL normalize — **Erebus change**, small. | Same, documented in shared contract. |
| Should **Scytale map** before INSERT? | **Done (Scytale):** static emits **`aosp`**; **`insert_queue`** normalizes legacy **`aosp_promote`**. | Prefer **one canonical** verb; **R2** on Erebus for old rows still optional. |
| Should PI have a **`queue_action` LUT**? | **Optional for P1** — document allowed verbs in **cross-repo doc** + tests. | **Yes** if verb count grows: migration adds **`android_permission_queue_action_lut`** (or reuse governance LUT pattern) and optional CHECK/FK. |

**Concrete P1 recommendation:** **R1 done in Scytale.** **R2** still recommended on Erebus for **brownfield** queue rows that still say `aosp_promote`. Populate **`proposed_classification`** (or agreed defaults) when inserting queue rows for promotion, after Erebus owners confirm apply workflow.

**Not in scope for P1:** mandatory DB FK to a LUT (DDL).

---

## 15. DDL / non-DDL / coordination split

| Change class | Examples | Owner |
| --- | --- | --- |
| **Docs / tests only** | This doc; S1/S1.5; transform-only pytest building proposed observation dicts | Scytale (+ Erebus review) |
| **DB schema** | Subject registry table; extended UNIQUE on `obs_sample`; `source_system` on `obs_sample`; queue_action LUT | DBA + Erebus migrations; Scytale consumes |
| **Erebus coordination** | Queue apply accepts `aosp_promote`; obs writer semantics; malware `sample_id` vs surrogate policy | Erebus maintainers |
| **Scytale code (no DDL)** | Map queue verb; build observation payload; feature flag skeleton **without** INSERT | Scytale |

---

## 16. S2 implementation preconditions (before any `obs_sample` write)

1. **Identity decision** accepted (§11 — **A/C/E** path documented with owner).  
2. **Uniqueness contract** accepted (surrogate vs composite key; upsert semantics).  
3. **Source / provenance** labels accepted (`apk_manifest` vs `other`; `source_system` plan).  
4. **Queue action mapping** accepted (§14).  
5. **Test fixture** proves a **pure transform** from static inputs (e.g. matrix row + manifest + sha256) → **proposed observation dict** matching §13, **without** database INSERT (see `tests/database/test_permission_observation_contract_transform.py`).

---

## 17. Explicit non-goals (this document)

- No DDL, migrations, or D0–D4 execution.  
- No `android_permission_obs_sample` or `enrich_vt_*` writes.  
- No Erebus code import into ScytaleDroid.  
- No full static pipeline refactor.

---

## 18. S2-P1A operational readiness (evidence gate)

Before scheduling S2 **implementation**, run the read-only bundle and fill the evidence template:

- **[permission_intel_scytaledroid_s2_p1a_operational_readiness.md](../../permission_intel_scytaledroid_s2_p1a_operational_readiness.md)** — PI routing commands, queue audit, static→SHA256 linkage, legacy `aosp_promote` options, readiness checklist.  
- **Scripts:** `scripts/db/audit_permission_intel_queue_compatibility.py`, `scripts/db/audit_static_permission_observation_linkage.py`, `scripts/db/run_permission_intel_scytale_s2_readiness_audit.sh`.

---

## 19. Related documents

- [shared_permission_intel_reconciliation.md](shared_permission_intel_reconciliation.md)  
- Erebus `docs/data/android_permissions_schema_contract.md`  
- [permission_intel_scytaledroid_s1_5_classifier_contract.md](permission_intel_scytaledroid_s1_5_classifier_contract.md)  
- [permission_intel_schema_drift_erebus_vs_scytaledroid.md](../../permission_intel_schema_drift_erebus_vs_scytaledroid.md) — Erebus migrations vs Scytale `permission_intel` / queue semantics  
- [permission_intel_classification_taxonomy_refinement.md](permission_intel_classification_taxonomy_refinement.md) — custom triage vs `unknown`/obfuscation (pre–S2 obs writes)
