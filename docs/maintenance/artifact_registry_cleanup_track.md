# Artifact registry cleanup track

Read-only reporting:

- `scripts/db/report_artifact_registry_integrity.py` — counts and dangling breakdowns.
- `scripts/db/report_artifact_registry_cleanup_candidates.py` — policy buckets (no DML).
- `scripts/db/report_artifact_registry_static_dangling.py` — static dangling row reason audit.
- `scripts/db/report_artifact_registry_static_legacy_overlap.py` — static dangling rows that still overlap legacy `runs`.
- `scripts/db/report_artifact_registry_static_session_retirement.py` — session-scoped retirement queue for the remaining legacy-overlap static rows.
- `scripts/db/report_artifact_registry_static_blocked_file_presence.py` — file-presence correlation for blocked static legacy sessions.

**Write-capable prune (implemented):** `scripts/db/prune_artifact_registry_dangling.py` — age-gated
dangling rows only, lightweight JSON/CSV/SQL receipt, ``DELETE`` only with ``--apply`` (never
deletes host files).

## 0. Operator policy (research / test installs)

ScytaleDroid is used as a **research and test** framework. **Low-trust alpha-era** derived
ledger rows in ``artifact_registry`` do not need indefinite preservation.

**Preserve (do not touch with registry prune tools):**

- Harvested **APK bytes** and repository / app-version **identity** inputs.
- **Inventory** snapshots and cohort metadata operators rely on for reruns.
- **Permission Intel** dictionaries and governance data (separate DSN / product boundary).

**Treat as disposable (this track):**

- ``artifact_registry`` rows that are **not** ``link_state='linked'`` and are **older than**
  configured age thresholds — the table is a **derived index**; static/dynamic analyses can be
  **rerun** from harvest + current schema when needed.

**Current good work** (e.g. session stamp ``20260513-all-full``) remains safe while runs still
exist in ``static_analysis_runs`` / ``dynamic_sessions``: linked registry rows are **never**
selected for prune.

**Filesystem:** prune tools **never** delete APKs or evidence files under ``output/``; only
``artifact_registry`` rows.

**Receipts:** a **lightweight** timestamped bundle (JSON + CSV + commented SQL listing ids) is
enough audit trail before delete — not a heavy archival programme.

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

**Do not use the workspace prune for bulk historical cleanup.** It deletes **all** rows returned
by `find_artifact_registry_orphans()` (every non-`linked` registry row matching the view) after
interactive prompts — suitable only for small, deliberate repairs.

- `scytaledroid/DynamicAnalysis/storage/db_maintenance.py` — `find_artifact_registry_orphans`,
  `delete_artifact_registry_rows` (DB rows only).
- `scytaledroid/Utils/System/workspace_maintenance_menu.py` — `_prune_artifact_registry_orphans`
  (interactive menu; deletes orphan **registry** rows after prompts).

**Read-only triage:** `PYTHONPATH=. python scripts/db/report_artifact_registry_cleanup_candidates.py`

**Static legacy closeout triage:** after a static-only prune reduces the truly detached rows, use
`report_artifact_registry_static_dangling.py` to classify what remains, then
`report_artifact_registry_static_legacy_overlap.py` and
`report_artifact_registry_static_session_retirement.py` to decide which legacy
session stamps are safe small-batch retirement candidates versus blocked by
still-present host files. For the blocked cohort, use
`report_artifact_registry_static_blocked_file_presence.py` before any further
delete planning.

**Scoped prune (preferred for bulk debt):** `PYTHONPATH=. python scripts/db/prune_artifact_registry_dangling.py` — see §4.

**Session-scoped static legacy prune (candidate sessions only):**
`PYTHONPATH=. python scripts/db/prune_artifact_registry_static_legacy_sessions.py`
targets only `artifact_registry` rows for static legacy-overlap session stamps
already classified by `report_artifact_registry_static_session_retirement.py`
as candidate retirement sessions. It writes a JSON/CSV/SQL/txt receipt bundle
first and refuses apply if any targeted row still has a present host file, any
selected session is blocked, or any row still overlaps canonical static tables.

`reset_static.py` intentionally omits `artifact_registry` from `STATIC_ANALYSIS_TABLES` (see
comment in that module). Expanding reset scope to the registry requires an explicit product
decision; use the prune script for ledger cleanup instead of widening static reset blindly.

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
| `static_nonnumeric_run_id_review` | Non-numeric static `run_id` — **legacy / mis-keyed**; investigate before bulk delete. |
| `static_numeric_missing_sar_candidate` | Mid-age (between recent and old thresholds) static numeric `run_id` with no SAR and **blank** `host_path` — export then registry delete candidate. |
| `unknown_link_review` | Unexpected `link_state` / `run_type` combination — inspect manually. |

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
   Implemented for registry prune as the JSON/CSV/SQL bundle from ``prune_artifact_registry_dangling.py`` (§4).

5. **Age threshold?**  
   Start conservative: e.g. **90 days** for automatic *candidates*; **7 days** cooling-off
   for “recent dangling”. Tune with `report_artifact_registry_integrity.py` age buckets.

6. **Should dangling artifacts block session cleanup?**  
   **No** by default — they are ledger debt. Optionally **warn** in session supersession/cleanup
  menus if counts exceed a threshold.

---

## 4. Implemented prune workflow (`prune_artifact_registry_dangling.py`)

| Step | Behavior |
|------|------------|
| Select | ``v_artifact_registry_integrity`` with ``link_state <> 'linked'`` (never SAR/dynamic-linked rows). |
| Age | ``created_at_utc < UTC_TIMESTAMP() - INTERVAL max(--min-age-days, --cooling-off-days) DAY`` (defaults 90 / 7). Optional ``--include-null-created-at`` for NULL timestamps. |
| Receipt | With ``--receipt-dir``, writes ``artifact_registry_prune_<timestamp>.{json,csv,sql}`` **before** any ``DELETE``. JSON uses envelope ``scytaledroid.artifact_registry_prune_receipt.v1`` (``meta`` + ``artifact_rows``); CSV is flat rows; SQL lists commented ``DELETE`` batches. |
| Delete | Only with ``--apply``; **requires** ``--receipt-dir`` when the candidate set is non-empty. |
| Counts | Prints total ``artifact_registry`` rows before, candidate count, deleted count, total after (when ``--apply`` ran deletes). |
| Files | **No** filesystem deletes; **no** APK removal. |

Suggested operator flow:

1. ``report_artifact_registry_cleanup_candidates.py`` (optional) — confirm buckets.
2. ``prune_artifact_registry_dangling.py --min-age-days …`` — dry-run counts.
3. ``prune_artifact_registry_dangling.py --receipt-dir data/state/artifact_registry_prune`` — write receipt, still dry-run.
4. Same command **+** ``--apply`` — receipt then batched ``DELETE``.

Workspace menu **prune all orphans** remains a last-resort hammer (all non-linked rows).

**Receipt JSON format:** new runs emit ``scytaledroid.artifact_registry_prune_receipt.v1`` with top-level
``meta`` and ``artifact_rows``. Older receipts in ``data/state/artifact_registry_prune/`` may be a bare
array (pre-change exports); treat those as legacy when scripting parsers.

### Operational cadence (after an initial prune)

- **Expect new dangling rows over time** whenever SAR or `dynamic_sessions` rows are removed but
  `artifact_registry` was not cascaded (no FK by design). That is normal; it is not a signal to
  re-panic about alpha-era “unknown” data if you already adopted the research policy in §0.
- **Re-run** `report_artifact_registry_integrity.py` on a schedule or after large DB resets; use
  age buckets to see whether debt is mostly **7–90d** (waiting game) vs **90d+** (prune candidates
  at default `--min-age-days 90`).
- **Static vs dynamic:** run `prune_artifact_registry_dangling.py` with `--run-type static` and/or
  `dynamic` so linked rows for live sessions stay untouched while each ledger is trimmed on its own
  schedule.
- **Session spot-check:** optional SQL join from `v_artifact_registry_integrity` to
  `static_analysis_runs` filtered by `session_stamp` (as in operator notes) confirms linked rows for
  a golden session stamp. Multi-table session rollups for a **stamp list**:
  `scripts/db/sql/report_static_session_stamp_cohort_rollups.sql`.

---

## 5. Tests (see repo)

- `tests/db/test_report_artifact_registry_integrity.py` — formatting + `--help` contract.
- `tests/db/test_report_artifact_registry_cleanup_candidates.py` — formatting + mocked SQL contract.
- `tests/db/test_artifact_registry_prune.py` — cutoff math, receipt bundle, prune orchestration mocks.
- Future: integration tests against a DB fixture for linked vs dangling classification mirror
  `v_artifact_registry_integrity` DDL in `tests/database/test_schema_manifest_static_handoff_view.py`
  style.

---

## 6. RFC (future schema / ops; not implemented)

- **Nullable `session_stamp` or `source_session_stamp`** on `artifact_registry` for new rows
  would make session-scoped triage and retention policies cheaper without replacing `run_id`
  join semantics for static/dynamic.
- **Operator menu wiring** for prune (optional): keep script as primary surface until UX review.
- **Indexes** — once delete batches are defined, add covering indexes aligned with
  `v_artifact_registry_integrity` filters (`run_type`, `link_state`, `created_at_utc`) only
  after measuring production plans (avoid speculative DDL in this track).
