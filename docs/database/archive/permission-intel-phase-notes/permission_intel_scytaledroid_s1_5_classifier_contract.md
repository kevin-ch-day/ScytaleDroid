# Permission Intel — ScytaleDroid S1.5 classifier & vocabulary contract

**Phase:** S1.5 (tighten shared vocabulary before S2 observation design).  
**Non-goals:** No `android_permission_obs_sample` writes, no schema changes, no static pipeline refactor, no DB merge, no Erebus Python imports.

**Related:** [S1 read-path audit](permission_intel_scytaledroid_s1_read_path_audit.md). **S2 (observation design):** [permission_intel_scytaledroid_s2_observation_design.md](permission_intel_scytaledroid_s2_observation_design.md). **Schema drift (Erebus migrations vs Scytale):** [permission_intel_schema_drift_erebus_vs_scytaledroid.md](../../permission_intel_schema_drift_erebus_vs_scytaledroid.md). **Taxonomy refinement (custom triage vs obfuscation):** [permission_intel_classification_taxonomy_refinement.md](permission_intel_classification_taxonomy_refinement.md). Cross-repo vocabulary truth: Erebus `docs/data/android_permissions_schema_contract.md` (dict_unknown ledger narrative).

---

## 1. Scytale-emitted `dict_unknown.triage_status` values

Static analysis (`StaticAnalysis/persistence/permissions_db.py` → `permission_dicts.upsert_unknown`) may set:

| Value | Meaning (Scytale) |
| --- | --- |
| `malformed` | Internal whitespace, known typo prefix, or token fails validation (no dot, length, placeholder tokens). |
| `app_defined` | Declared custom permission (manifest custom set) not resolved as AOSP/OEM. |
| `oem_candidate` | Non-`android.permission.*` string with OEM prefix/meta match. |
| `aosp_missing` | `android.permission.*` not in AOSP dictionary (GhostAOSP strings still use this; see notes). |
| `new` | Non-framework permission with no OEM dict hit and no prefix rule. |

**Internal counters** (`aosp`, `oem`, `app_defined`, `unknown` in return dict) are **not** PI triage values.

---

## 2. PI / Erebus documented `dict_unknown` triage surface

Canonical narrative (Erebus contract + operator SQL) includes at least:

`resolved_aosp`, `resolved_oem`, `app_defined`, `gms_known`, `launcher_ecosystem`, `malformed`, `malicious_dga`, `brand_spoof`, `new`, `in_review`, `oem_candidate`, `aosp_missing`, `suspicious_token`.

Scytale **consumes** resolution states written by operators/Erebus; it does **not** emit them from static.

---

## 3. Exact overlaps and gaps

### 3.1 Overlap (Scytale emit ∩ PI documented)

`app_defined`, `malformed`, `oem_candidate`, `aosp_missing`, `new` — **all five** are in the PI documented set.

### 3.2 Gaps — PI-only (never emitted by Scytale static)

Examples: `resolved_aosp`, `resolved_oem`, `gms_known`, `launcher_ecosystem`, `malicious_dga`, `brand_spoof`, `in_review`, `suspicious_token`.

These are expected to be produced by governance, VT pipeline, or manual triage — not the static classifier.

### 3.3 Scytale-only

**None** for `triage_status`: every static emission is a subset of the documented PI ledger vocabulary.

### 3.4 Queue / workflow strings (separate from triage)

| Field | Scytale static value | Notes |
| --- | --- | --- |
| `queue_action` | **`aosp`** | Emitted only with `triage_status == aosp_missing`. Matches Erebus `permission_queue_apply.class_action_map` (`aosp` → `AOSP` / apply). |
| `source_system` / `requested_by` | `static-analysis` | Provenance for queue rows. |
| `status` (queue row) | Default `queued` | Set in `permission_dicts.insert_queue`. |

**Legacy:** `permission_dicts.insert_queue` maps **`aosp_promote` → `aosp`** so older callers remain valid.

**Deep drift:** [permission_intel_schema_drift_erebus_vs_scytaledroid.md](../../permission_intel_schema_drift_erebus_vs_scytaledroid.md) (PI migrations, queue column expectations, `dict_unknown` CASE differences).

---

## 4. Local hardcoded sets (drift vs PI)

### 4.1 `_GHOSTAOSP_BROADCAST_PERMS` (`permissions_db.py`)

- **Role:** Annotates notes for a fixed set of broadcast-related `android.permission.*` strings that may be absent from AOSP docs dictionary.
- **Recommendation:** **Keep local** short-term (low churn). **Medium-term:** prefer PI dictionary or alias notes so Erebus/Scytale share one truth.

### 4.2 `_MALFORMED_PREFIXES` (`permissions_db.py`)

- **Role:** Catches a known manifest typo namespace (`android.premission.`).
- **Recommendation:** **Keep local** as defense-in-depth; optional **PI alias** row if operators want unified reporting.

### 4.3 `framework_permissions.yaml` + `modules/permissions/catalog.py`

- **Role:** Offline AOSP-like protection metadata when PI DB/catalog load fails; `PermissionDescriptor.source` may be `catalog` / `dict_aosp`.
- **Recommendation:** **Keep** as dev/air-gap fallback; **do not** treat YAML as governance truth when PI is configured. Not a `triage_status` emitter.

### 4.4 Governance CSV import (`Database/tools/permission_governance_import.py`)

- **Role:** Loads **`permission_governance_snapshot_rows`** with arbitrary CSV `triage_status` (e.g. `UNREVIEWED`) — **governance projection**, not `android_permission_dict_unknown`.
- **Recommendation:** Out of scope for static triage contract; document separately if operators mix CSV labels with dict_unknown LUT.

---

## 5. Contract enforcement in repo

- **`tests/database/test_permission_intel_triage_vocabulary_contract.py`** — documents PI triage superset constants, asserts Scytale emissions ⊆ superset, pins literals.
- **`tests/database/test_permission_intel_sql_routing_guard.py`** — asserts `android_permission_{dict,meta,enrich,obs,…}` table fragments appear only in `permission_intel.py`.

---

## 6. S2 blockers (observation design — not dict triage)

| Blocker | Severity |
| --- | --- |
| **`obs_sample` identity** — disjoint `sample_id` space vs malware catalog, or DDL/uniqueness change | **Hard** |
| **`source` / `source_system` spelling** — align with Erebus `ENUM` / contract (`apk_manifest`, `other`, …) | **Hard** |
| **`queue_action` legacy `aosp_promote`** — Erebus apply did not recognize it; **mitigated** in Scytale (`aosp` + insert-time normalize). Rows already in PI with `aosp_promote` may still need Erebus R2 or manual fix | **Low** (residual brownfield queue rows) |
| **Provenance columns** — sha256 / `static_run_id` not stored on `dict_unknown` today | **Medium** (design-only until writes) |

**Classifier vocabulary:** Scytale `triage_status` emissions are **not** a blocker; they are a **subset** of the documented PI ledger (see §3).

---

## 7. S2 prep

When designing `obs_sample` writes:

- Reuse **verbatim** manifest permission strings aligned with `dict_unknown` / matrix `permission_name`.
- Resolve **`queue_action`** naming with Erebus queue apply before automation depends on it.
- Consider reading **PI alias / prefix** tables instead of growing `_MALFORMED_PREFIXES` / GhostAOSP lists.
