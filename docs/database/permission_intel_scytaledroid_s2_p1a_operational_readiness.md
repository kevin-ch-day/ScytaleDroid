# ScytaleDroid S2-P1A — Operational readiness (PI routing, queue, static → obs)

**Intent:** Evidence-driven validation before any `android_permission_obs_sample` writes.  
**Constraints:** Read-only on shared PI; no schema/migrations/obs inserts; no Erebus code import; no queue apply.

**Related:** [Permission Intel contract](permission_intel_contract.md), [schema drift vs Erebus](permission_intel_schema_drift_erebus_vs_scytaledroid.md), [archived S1/S2 phase notes](archive/permission-intel-phase-notes/).

---

## 1. PI routing vs live environment

### 1.1 Expected configuration

| Role | Env namespace |
| --- | --- |
| Scytale **core** evidence (runs, matrix, APK catalog) | `SCYTALEDROID_DB_*` |
| **Permission Intel** (shared `android_permission_*` dict/queue/governance) | `SCYTALEDROID_PERMISSION_INTEL_DB_*` or `SCYTALEDROID_PERMISSION_INTEL_DB_URL` |

### 1.2 Code-level guarantees (repo)

- All application SQL touching `android_permission_{dict,meta,enrich,obs,…}` table **names** is confined to `scytaledroid.Database.db_core.permission_intel` — enforced by `tests/database/test_permission_intel_sql_routing_guard.py`.
- **No `EREBUS_*` env** references under `scytaledroid/` (runtime). Scytale does not assume Erebus process env.
- PI never **silently** falls back to core for those tables: unconfigured PI → explicit errors / preflight warnings, not core routing.

### 1.3 Operator commands

```bash
cd /home/secadmin/Laughlin/GitHub/ScytaleDroid
export PYTHONPATH=.

# PI DSN resolution + table existence + governance row signal
python scripts/db/check_permission_intel.py
```

**Interpretation**

- Exit **0:** PI configured, `MANAGED_TABLES` exist, governance snapshot non-empty per `governance_ready` path used inside the script.
- Exit **1:** PI missing tables / connection errors.
- Exit **2:** PI configured but governance missing (paper-grade reminder).

**Gaps (after Erebus-side PI work)**

- `MANAGED_TABLES` does **not** include newer Erebus-only analytics objects (e.g. `android_permission_event_slice`) — absence does **not** mean Erebus is broken; it means Scytale preflight does not track that table.
- `check_permission_intel.py` does **not** validate queue row semantics — use §2 script.

### 1.4 Confirm catalog name

`describe_target()` prints `database=`. For shared intel, operators usually expect **`android_permission_intel`** (same physical catalog Erebus migrates for PI-target files). Compare with Erebus `EREBUS_PERMISSION_INTEL_DB_NAME` / DBA docs — **must match operator intent**, not a hardcoded constant in Scytale.

---

## 2. Queue compatibility (live evidence)

### 2.1 Read-only report (recommended)

```bash
cd /home/secadmin/Laughlin/GitHub/ScytaleDroid
export PYTHONPATH=.
python scripts/db/audit_permission_intel_queue_compatibility.py
# Optional machine summary:
python scripts/db/audit_permission_intel_queue_compatibility.py --json
```

Uses **`DATABASE()`** on the PI connection — do **not** hardcode `android_permission_intel.` in SQL when the DSN already selects the catalog.

### 2.2 What the script reports

1. **Grouped counts** by `queue_action`, `status`, `source_system`, `requested_by` (+ min/max `created_at_utc`).
2. **Legacy `aosp_promote` row count** + sample (up to 25). These rows would yield **`unknown_action`** under current Erebus `evaluate_queue_row` (no alias for `aosp_promote`).
3. **Recent Scytale/static rows** (`source_system` / `requested_by` in `static-analysis`, `scytaledroid`, `scytaledroid_static`).
4. **Active rows** (`status` in `queued`, `pending`, same as Erebus `QUEUE_ACTIVE_STATUSES`): dry **apply outcome** via `queue_row_apply_outcome` in `queue_apply_compat_check.py` (mirrors default **`aosp` → apply** map). Counts NULL/empty `proposed_*` for context (nulls are OK when `queue_action` is `aosp`).

### 2.3 Ad-hoc SQL (optional)

If you prefer raw mysql client, align column names with **live** `information_schema` — Scytale queue INSERT uses:

`permission_string`, `queue_action`, `proposed_bucket`, `proposed_classification`, `triage_status`, `notes`, `requested_by`, `source_system`, `status`, `created_at_utc`, `updated_at_utc`

(Not `proposed_triage_status` / `proposed_owner` — those were placeholders in an earlier sketch.)

### 2.4 Live findings template (fill after you run the script)

Paste operator output here when filing tickets:

- **legacy `aosp_promote` total:** ___  
- **active unknown_action samples:** ___  
- **recent static-analysis rows using `queue_action`:** ___  

*This document ships without live numbers — evidence is environment-specific.*

---

## 3. Legacy `aosp_promote` rows — options (no mutation in P1A)

| Option | Risk | Owner | Schema? | Migration? | Affects existing rows? | Tests |
| --- | --- | --- | --- | --- | --- | --- |
| **1 — Document only** | Rows stay **unapplyable** until manual fix | Shared | No | No | No | Audit script shows count |
| **2 — Erebus alias** | Low; normalize in apply | Erebus | No | No | Behavior only | Erebus unit tests for `aosp_promote` |
| **3 — One-time UPDATE** | Medium; wrong WHERE could corrupt queue | DBA + ops | No | No (data fix) | Yes | Backup + row count diff |
| **4 — LUT / governance** | Best long-term; more moving parts | Platform | Optional FK | Yes | Optional | Cross-repo contract tests |

**Current code posture (Scytale):** new inserts use **`aosp`**; **`insert_queue`** maps legacy **`aosp_promote` → `aosp`**.

**Instinct alignment:** Option **2** medium-term for brownfield; Option **4** long-term.

---

## 4. Static permission output → future observation payload

### 4.1 Field availability (core DB)

| Field | Where | Notes |
| --- | --- | --- |
| `permission_string` | `static_permission_matrix.permission_name` | Verbatim string. |
| `package_name` | Matrix column | Yes. |
| `static_run_id` | `static_permission_matrix.run_id` | FK to `static_analysis_runs.id` (see matrix DDL). |
| APK SHA-256 | `static_analysis_runs.base_apk_sha256` | Required column in `static_schema_gate` inventory. |
| `version_code` / `version_name` | `app_versions` via `static_analysis_runs.app_version_id` | Join in linkage audit. |
| `apk_id` | Matrix optional | Nullable; links to `android_apk_repository.id` when set. |
| Detector / tool version | `static_analysis_findings` / run metadata | Not part of matrix row — separate if needed for provenance. |
| Device harvest | Device inventory tables | Not assumed for static APK path. |

### 4.2 Read-only linkage audit

```bash
PYTHONPATH=. python scripts/db/audit_static_permission_observation_linkage.py
```

Reports: column presence, counts of matrix rows with missing run SHA-256, null `apk_id`, optional sha mismatch vs repository, and a small sample join.

### 4.3 Candidate join (reference)

```sql
SELECT spm.permission_name, spm.run_id, spm.apk_id, spm.package_name,
       sar.base_apk_sha256, sar.session_stamp, sar.status,
       av.version_code, av.version_name
FROM static_permission_matrix spm
JOIN static_analysis_runs sar ON sar.id = spm.run_id
LEFT JOIN app_versions av ON av.id = sar.app_version_id
LIMIT 20;
```

---

## 5. Local classifier heuristics — drift risk (no refactor)

| Mechanism | Verdict | Future |
| --- | --- | --- |
| `_GHOSTAOSP_BROADCAST_PERMS` | **Keep local** short-term | Move notes / dict coverage to PI |
| `_MALFORMED_PREFIXES` | **Keep local** | Optional PI alias ledger |
| `framework_permissions.yaml` | **Offline fallback** | PI AOSP dict is SoT when connected |
| Token validation (`_valid_permission_token`) | **Scytale-static heuristic** | Document; align with Erebus alias rules over time |
| Protection metadata in matrix | **Core DB** presentation | Not PI triage |

---

## 6. “ScytaleDroid ready for S2 implementation” checklist

Ready for **S2 implementation design review** (not blind production obs writes) only when:

- [ ] **Queue compatibility verified** — `audit_permission_intel_queue_compatibility.py` run on **production PI**; outcomes documented.  
- [ ] **Legacy `aosp_promote`** — count **zero** *or* **Erebus alias (option 2)** accepted/deployed *or* data fix planned.  
- [ ] **Observation identity** — option **A** or **C** (or E→A/C) selected with owner (see S2 doc §11).  
- [ ] **Transform** — static rows can build validated payloads (`validate_proposed_static_observation_row`); **SHA-256** available at transform time (`base_apk_sha256` join).  
- [ ] **Source/provenance** — `source` ENUM + `source_system` story agreed.  
- [ ] **Uniqueness** — `sample_id` / registry contract agreed with Erebus/DBA.  
- [ ] **Tests** — triage, routing guard, queue compat, transform edge cases green in CI.  
- [ ] **Erebus/PI owner** signs target DDL/bridge approach.

---

## 7. Bundled runner

```bash
./scripts/db/run_permission_intel_scytale_s2_readiness_audit.sh
```

Runs: `check_permission_intel.py`, queue audit, linkage audit, and the pytest bundle (continues with best-effort if DB env missing).

---

## 8. Recommendation snapshot

| Question | Answer |
| --- | --- |
| Ready for S2 **implementation**? | **No** until identity + uniqueness + source are signed; queue evidence logged. |
| Ready for S2 **design review**? | **Yes** after P1A scripts run once on shared PI + core. |
| Next single decision? | **Surrogate `sample_id` registry vs extended UNIQUE** (S2 §11), in parallel with **Erebus `aosp_promote` alias** if legacy rows exist. |
