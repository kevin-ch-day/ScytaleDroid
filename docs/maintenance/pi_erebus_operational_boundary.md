# Permission Intelligence vs Erebus — operational boundary (decision note)

**Status:** architecture / contract — **not** a migration plan.  
**Audience:** ScytaleDroid maintainers, Permission Intel DBAs, Erebus owners.  
**Companion:** `docs/database/permission_intel_schema_drift_erebus_vs_scytaledroid.md` (DDL drift), S2 observation design docs under `docs/database/`.

---

## 1. Ownership (normative)

| Concern | Owner |
| --- | --- |
| **Static scan results** (`static_analysis_*`, permission audit snapshots/apps on the **analyst core** catalog) | **ScytaleDroid** |
| **Local permission audit evidence** (core DB tables tied to `static_run_id`) | **ScytaleDroid** |
| **Dictionary + governance + signal catalog** in `android_permission_intel` | **Shared catalog** — ScytaleDroid **reads** for analysis; **governance imports** and operational tooling live in this repo’s scripts where documented |
| **Queue rows for unknown / triage permissions** (`android_permission_dict_unknown`, `android_permission_dict_queue` patterns) | **ScytaleDroid may emit** as designed today — **not** static *results* storage |
| **Global permission dictionary lifecycle, queue apply workflows, `android_permission_obs_sample` writers, cross-tool classification governance** | **Erebus / shared PI operational owners** — ScytaleDroid must not assume it can widen writes without joint contract |

---

## 2. ScytaleDroid read/write summary (current posture)

- **Reads (PI):** dictionary, governance snapshots/rows, signal catalog/mappings where integrated — used for classification and paper-grade gates (`check_permission_intel.py`, readiness scripts).
- **Writes (PI):** bounded helpers in `permission_intel.py` (unknown upsert, queue insert, OEM seen counters, governance import tools) — **observation sample table not yet a supported Scytale writer surface**.

---

## 3. Unresolved blockers before broader PI writes (especially `obs_sample`)

1. **`sample_id` semantics** vs Erebus malware catalog — disjoint allocation or schema evolution required before Scytale treats PI obs rows as first-class.  
2. **Producer / subject** uniqueness if multiple tools write the same logical permission observation stream.  
3. **Classifier / `rule_fired` / bucket** vocabulary parity with Erebus queue apply.  
4. **Who runs queue apply** and how Scytale-emitted rows transition to terminal states without forked semantics.  
5. **Cross-repo DDL contract** when Erebus migrations add columns Scytale introspection must honor (brownfield already noted in drift doc).

---

## 4. Explicit non-goals

- Importing Erebus Python into ScytaleDroid.
- Changing **`MANAGED_TABLES`** or expanding writes without DBA + Erebus sign-off.

---

## 5. When this note should be updated

- First Scytale writer to `android_permission_obs_sample` lands (or is rejected).
- Queue action / `class_action_map` contract changes on either side.
- Governance import path changes ownership.
