# Artifact registry cleanup track (design)

Read-only reporting lives in `scripts/db/report_artifact_registry_integrity.py`.
This document records **policy categories** and a **future delete workflow** only — no
automated prune is implemented here.

## 1. Model summary (authoritative in code)

### Table: `artifact_registry`

Defined in `scytaledroid/Database/db_queries/canonical/schema.py`:

- `run_id` `VARCHAR(64)` — opaque join key interpreted with `run_type`.
- `run_type` — `'static'` or `'dynamic'` in current writers.
- `artifact_type` — e.g. `static_report`, `dep_snapshot`, `static_run_manifest`,
  `permission_audit_snapshot`, `dynamic_run_manifest`, paths from dynamic manifests.
- `host_path` / `device_path` — optional paths; `host_path` is populated from
  `record_artifacts` when a filesystem path is known.

### View: `v_artifact_registry_integrity`

Defined in `scytaledroid/Database/db_queries/views_admin.py`:

| `run_type` | `link_state` | Meaning |
|------------|----------------|--------|
| `dynamic` | `linked` | `dynamic_sessions.dynamic_run_id = artifact_registry.run_id` |
| `dynamic` | `dangling_dynamic_run` | No matching `dynamic_sessions` row |
| `static` | `linked` | `run_id` matches `^[0-9]+$` **and** `static_analysis_runs.id = CAST(run_id AS UNSIGNED)` |
| `static` | `dangling_static_run` | All other static rows (includes non-numeric `run_id`, missing SAR, etc.) |
| other | `unknown_run_type` | Unexpected `run_type` value |

**Static convention:** writers use `run_id=str(static_analysis_runs.id)` (numeric string).
There is **no** `session_stamp` column on `artifact_registry`; session is indirect via SAR.

**Dynamic convention:** `run_id` is the dynamic run identifier string (`dynamic_run_id`),
written from `DynamicAnalysis/storage/persistence.py` (`record_artifacts`).

### Who writes rows?

**Static** (`run_type='static'`, `run_id=str(static_run_id)`):

- `StaticAnalysis/cli/execution/artifact_publication.py` — baseline/plan/report/manifest_evidence.
- `StaticAnalysis/cli/persistence/dep_export.py` — `dep_snapshot`.
- `StaticAnalysis/cli/persistence/manifest_writer.py` — `static_run_manifest`.
- `StaticAnalysis/modules/permissions/audit.py` — `permission_audit_snapshot`.

**Dynamic** (`run_type='dynamic'`):

- `DynamicAnalysis/storage/persistence.py` — manifest + merged artifacts/outputs/observers.

Core helper: `Database/db_utils/artifact_registry.py` → `record_artifacts`.

### Existing maintenance (destructive when confirmed)

- `scytaledroid/DynamicAnalysis/storage/db_maintenance.py` — `find_artifact_registry_orphans`,
  `delete_artifact_registry_rows` (DB rows only).
- `scytaledroid/Utils/System/workspace_maintenance_menu.py` — `_prune_artifact_registry_orphans`
  (interactive menu; deletes orphan **registry** rows after prompts).

`reset_static.py` does **not** currently clear `artifact_registry` in the snippets reviewed for
this pass; full reset behavior should be re-checked if reset scope expands.

---

## 2. Policy categories (proposal)

Use these **labels** in runbooks and future tooling; they are not DB enums yet.

| Category | Description |
|----------|-------------|
| `linked_keep` | `link_state='linked'` — **never delete** in cleanup passes. |
| `dangling_recent_keep` | Dangling but `created_at_utc` within a short window (e.g. 7d) — may be mid-migration or replay; **keep** unless proven stale. |
| `dangling_old_export_first` | Older dangling rows — **export CSV/JSON** of keys + paths before any delete. |
| `dangling_db_only_candidate` | Dangling, `host_path` null/empty or path probe **missing** — safe **registry row** delete candidate after export. |
| `dangling_file_present_review` | Dangling but file **exists** — evidence may still be valuable; **human review** before registry delete. |
| `dynamic_dangling_review` | `dangling_dynamic_run` — correlate with evidence dirs and `dynamic_sessions` history before delete. |
| `static_dangling_safe_metadata_delete_candidate` | Dangling static, numeric `run_id`, confirmed no SAR and no downstream FK need — **metadata-only** delete candidate (still export-first). |

Non-numeric static `run_id` rows are **always** `dangling_static_run` under the current view;
treat as **legacy / mis-keyed** and review before any bulk action.

---

## 3. Design questions (recommended answers)

1. **Should cleanup delete only `artifact_registry` rows?**  
   **Default yes** for automated phases. Files under `output/` / `evidence/` remain authoritative;
   the registry is a derived index.

2. **Should it ever delete files under `output/evidence`?**  
   **Not in the same tool** as registry cleanup. If ever needed, a **separate** explicit
   filesystem workflow with its own dry-run, manifest, and backup — default **off**.

3. **Separate static vs dynamic cleanup?**  
   **Yes** in UX and batching: different join rules, different operator stakes, different
   evidence roots.

4. **Mandatory backup/export before delete?**  
   **Yes** for any non–dry-run batch: at minimum CSV of `(artifact_id, run_id, run_type, artifact_type, host_path)`.

5. **Age threshold?**  
   Start conservative: e.g. **90 days** for automatic *candidates*; **7 days** cooling-off
   for “recent dangling”. Tune with `report_artifact_registry_integrity.py` age buckets.

6. **Should dangling artifacts block session cleanup?**  
   **No** by default — they are ledger debt. Optionally **warn** in session supersession/cleanup
  menus if counts exceed a threshold.

---

## 4. Future delete workflow (not implemented)

When implemented, require:

- **Default dry-run** — print counts and sample only.
- **`--export PATH`** — write audit CSV/JSON before any mutation.
- **`--execute`** — explicit opt-in to run deletes (no silent default).
- **Transactions** — batched `DELETE FROM artifact_registry WHERE artifact_id IN (...)` with
  before/after counts.
- **Never delete** `link_state='linked'`.
- **Never delete** artifacts for runs tied to **current Web-default** session surfaces without
  product sign-off (define query when implemented).
- **Never delete** dynamic artifacts for `dynamic_sessions` that still exist (`linked` rows only
  anyway — dangling implies session gone; still verify evidence policy).

Filesystem deletion **only** if a separate flag (e.g. `--delete-host-files`) exists and is
documented as irreversible.

---

## 5. Tests (see repo)

- `tests/db/test_report_artifact_registry_integrity.py` — formatting + `--help` contract.
- Future: integration tests against a DB fixture for linked vs dangling classification mirror
  `v_artifact_registry_integrity` DDL in `tests/database/test_schema_manifest_static_handoff_view.py`
  style.
