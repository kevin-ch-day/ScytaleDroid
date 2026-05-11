# Permission Intel — Erebus schema drift vs ScytaleDroid assumptions

**Purpose:** Deep reconciliation between **current Erebus** DDL/migrations/writers and **ScytaleDroid** `permission_intel` helpers, docs, and static writers. Use this when provisioning or debugging `SCYTALEDROID_PERMISSION_INTEL_DB_*` against a catalog that Erebus also migrates.

**Non-goals:** This is an operator/architect reference — not a migration runner.

**Sources checked (Erebus repo):** `src/data/sql/android_permissions_schema.sql`, `migrations/0042*.sql`–`0049*.sql`, `permission_record.py`, `permission_queue_schema.py`, `obs_sample_schema_contract.py`.

---

## 0. Deployment mental model (Permission Intel vs Erebus)

- **ScytaleDroid Permission Intel** targets the MariaDB catalog **`android_permission_intel`** (via `SCYTALEDROID_PERMISSION_INTEL_DB_*` / URL).
- **Erebus** uses **`EREBUS_*`** (or project-specific) env vars and its **own** database catalog. The two are **not** interchangeable in documentation, env files, or mental models — wrong DSNs produce confusing “missing governance” failures.

**Operational open points** (conventions, not blockers for this drift doc): whether both catalogs ever live on one MariaDB **server** as two database names; how governance CSV / snapshot imports land in `android_permission_intel` for paper-grade checks vs Erebus provenance (`source_system` on governance rows).

---

## 1. Reference DDL snapshot vs live brownfield

`android_permissions_schema.sql` is a **greenfield snapshot**. Erebus production writers **introspect** live columns for:

- **`android_permission_obs_sample`:** optional **`sha256`**, **`bucket`**, **`rule_fired`**, **`run_id`** (see §2).  
- **`android_permission_enrich_vt_event`:** **`run_id`**, natural-key UNIQUE (`0042`).  
- **`android_permission_dict_unknown`:** VT path uses a **slimmer** INSERT than Scytale’s upsert (§4).

Scytale operators should assume **brownfield** PI catalogs may **differ** from the snapshot; use `information_schema` or Erebus `db_doctor` on the PI database.

---

## 2. PI-only migrations Scytale should know about

| Migration | Table / change | Scytale impact |
| --- | --- | --- |
| **0042** | `android_permission_enrich_vt_event` UNIQUE `uq_enrich_vt_event_natural` | None (Scytale does not write enrich tables today). |
| **0044** | `android_permission_obs_sample.run_id BIGINT NULL`; `enrich_vt_event.run_id` | **Future obs writes:** Erebus already passes `run_id` when the column exists. Scytale should mirror that pattern (see S2 design). **Not** in reference snapshot DDL. |
| **0047** | New **`android_permission_event_slice`** | **Analytics slice** derived from VT events. **Not** in `permission_intel.MANAGED_TABLES`; `check_permission_intel.py` does not flag it — optional for operators to create via Erebus migrations. |
| **0046 / 0048** | VT-derived tables on **primary** catalog (`sha256` keyed) | Unrelated to Scytale PI dict writes. |

### 2.1 `MANAGED_TABLES` gap

`scytaledroid.Database.db_core.permission_intel.MANAGED_TABLES` lists Contract A dict/meta + governance + signal tables. It **does not** include:

- `android_permission_obs_sample` / `enrich_vt_*` / `run_aosp_import` (Scytale does not manage them yet).  
- **`android_permission_event_slice`** (new Erebus PI table).

**Recommendation:** Treat `event_slice` as **Erebus/ops** concern until Scytale reads it. Optionally extend `scripts/db/check_permission_intel.py` with an **informational** line if the table exists (docs-only unless product wants it).

---

## 3. `android_permission_obs_sample` — beyond the snapshot

Reference snapshot columns: `obs_id`, `sample_id`, `sha256`, `package_name`, `permission_string`, `classification`, `bucket`, `rule_fired`, `vendor_id`, `observed_at_utc`, `source`.

**Erebus additions (migrations / writers):**

- **`run_id`** (`0044`) — inserted on new rows when present; **not** updated on `ON DUPLICATE KEY` in current `permission_record` upsert (classification/sha256 refresh path).  
- **`sha256` / `bucket` / `rule_fired`:** feature-detected; some deployments use **NOT NULL** `sha256` (Erebus `obs_sample_schema_contract` warns).

**Scytale:** No writer yet — S2 design doc remains authoritative.

---

## 4. `android_permission_dict_unknown` — upsert semantics divergence

### 4.1 Scytale (`permission_intel.upsert_unknown_permission`)

Inserts full counter/example columns and applies:

```sql
triage_status = CASE WHEN triage_status = 'new' THEN VALUES(triage_status) ELSE triage_status END
```

So Scytale **only replaces** `triage_status` when the existing row is **`new`**.

### 4.2 Erebus VT (`permission_record` batch)

Uses a **different** `CASE` preserving many terminal states (`resolved_aosp`, `in_review`, `malformed`, `aosp_missing`, …) and conditional updates from incoming triage.

### 4.3 Risk

For the same `permission_string`, **interleaved** Scytale static and Erebus VT upserts can produce **order-dependent** `triage_status` and notes. This is a **governance** concern, not a column mismatch.

**Mitigation (operational):** treat `dict_unknown` as a **shared ledger** with explicit policy on which writer wins; consider aligning CASE logic in a future coordinated change (out of scope here).

---

## 5. `android_permission_dict_queue` — column expectations

Erebus `ensure_queue_schema` requires these columns to **exist**:  
`queue_id`, `permission_string`, `queue_action`, `proposed_classification`, `proposed_bucket`, `triage_status`, `status`, `processed_at_utc`, `processed_by`, `error_message`, `updated_by`.

Scytale `insert_permission_queue` INSERT list:  
`permission_string`, `queue_action`, `proposed_bucket`, `proposed_classification`, `triage_status`, `notes`, `requested_by`, `source_system`, `status`, `created_at_utc`, `updated_at_utc`.

**Typical MariaDB behavior:** omitted columns use **defaults** / **NULL** if allowed — OK when `processed_*`, `error_message`, `updated_by` are nullable.

### 5.1 Queue action compatibility (fixed in Scytale)

Erebus `permission_queue_apply.class_action_map` keys include **`aosp`** (maps to promotion/`apply` semantics). It does **not** include **`aosp_promote`**, which would surface as `unknown_action` in `evaluate_queue_row`.

**Scytale fix:** emit **`aosp`** for `aosp_missing` promotion rows and **`insert_queue`** normalizes legacy **`aosp_promote` → `aosp`** so older queued rows / callers remain safe.

**Operator evidence:** run `PYTHONPATH=. python scripts/db/audit_permission_intel_queue_compatibility.py` (read-only) against live PI — see [permission_intel_scytaledroid_s2_p1a_operational_readiness.md](permission_intel_scytaledroid_s2_p1a_operational_readiness.md).

---

## 6. Dictionary tables — alignment

| Area | Snapshot / Erebus | Scytale `permission_intel` |
| --- | --- | --- |
| **AOSP** | `dict_aosp` PK `constant_value` | SELECTs match snapshot shape; catalog helper reads `protection_level`, API levels. |
| **OEM** | `confidence` / `classification_source` ENUMs | Scytale SELECTs subset — OK. |
| **Prefix rules** | `match_type` ENUM `prefix`/`regex` | Scytale `ORDER BY CHAR_LENGTH(namespace_prefix) DESC, prefix_id ASC` — consistent with longest-prefix intent (verify Erebus classifier ordering separately). |
| **Vendor** | Snapshot notes optional `notes` on vendor | Scytale SELECT omits `notes` — OK for current use. |

---

## 7. Action checklist for ScytaleDroid maintainers

1. **Do not** treat `android_permissions_schema.sql` as the only truth — check **applied migrations** on the target PI catalog.  
2. **Queue:** ensure new rows use **`queue_action = 'aosp'`** for AOSP promotion intent (normalized in code).  
3. **Preflight:** `MANAGED_TABLES` existence checks are **necessary but not sufficient** for full Erebus PI parity (`event_slice`, obs columns).  
4. **S2:** when adding `obs_sample` writes, follow Erebus **column introspection** for `sha256`, `bucket`, `rule_fired`, `run_id`.  
5. **Cross-repo:** link Erebus `docs/ops/migrations.md` for PI-targeted files `0042`, `0044`, `0047`.

---

## 8. Related ScytaleDroid docs

- [permission_intel_scytaledroid_s1_read_path_audit.md](permission_intel_scytaledroid_s1_read_path_audit.md)  
- [permission_intel_scytaledroid_s1_5_classifier_contract.md](permission_intel_scytaledroid_s1_5_classifier_contract.md)  
- [permission_intel_scytaledroid_s2_observation_design.md](permission_intel_scytaledroid_s2_observation_design.md)
