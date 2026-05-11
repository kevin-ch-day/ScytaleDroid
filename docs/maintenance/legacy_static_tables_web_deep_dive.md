# Web repo — static data path vs legacy five (deep dive)

**Web tree referenced:** `/var/www/html/ScytaleDroid-Web` (read on analyst workstation; not part of the Python git workspace).

**Purpose:** explain how ScytaleDroid-Web loads static exposure data, why the loose grep for `findings` / `metrics` is noisy, and where the **one** legacy **`runs`** reference lives.

**Checkpoint verdict (current tree — docs only, no schema / no Web code changes here):**

- Web **`v_web_*`** and **`vw_static_*`** surfaces are the main read contract.
- Findings Explorer is canonical-by-contract via **`v_web_app_findings`**.
- Per-app findings use **`static_analysis_findings`** joined to **`static_analysis_runs`**.
- Loose **`findings`** greps hit UI/CSS/PHP names or SQL **aliases** (e.g. `vw_static_finding_surfaces_latest findings`), not the legacy **`findings`** base table.
- The **only** legacy base-table SQL dependency found: **`SQL_DIAG_COUNTS`** — `(SELECT COUNT(*) FROM runs) AS runs`, diagnostics-only through **`app_diagnostics()`** / **`pages/diag.php`**.
- **No** direct Web SQL dependency found for legacy **`findings`**, **`metrics`**, **`buckets`**, or **`contributors`** (tight `FROM`/`JOIN` pattern).

**Larger DB conclusion (unchanged):** legacy static tables remain **compatibility / historical keep** in the Python repo; Web is **not** a major blocker except that one diagnostic **`runs`** count.

**Optional future Web-only cleanup (no DB changes):** rename diagnostic payload key **`runs`** → **`legacy_runs_total`** (or similar) and label as legacy static registry / **`runs`** table; clarify **`static_runs`** as canonical (e.g. **`canonical_static_runs_total`**). Track in Web repo when doing a small UX pass — not required to close the checkpoint.

---

## 1. Architecture: views first, canonical tables where needed

From `database/README.md` and `database/db_lib/db_queries.php`:

- **Preferred contract:** `v_web_*` views (e.g. `v_web_app_directory`, `v_web_app_sessions`, `v_web_app_findings`, `v_web_static_session_health`, `v_web_runtime_run_index`) — built/maintained from the **Python** repo (`recreate_web_consumer_views.py` et al.); Web assumes **SELECT-only**.
- **Consumer views:** `vw_static_finding_surfaces_latest`, `vw_static_risk_surfaces_latest` — “latest surface” rollups for directory and risk joins.
- **Direct base tables** appear only where the UI needs ad hoc joins or aggregates the views do not wrap — notably **`static_analysis_runs`**, **`static_analysis_findings`**, **`static_findings_summary`**, **`static_string_summary`**, **`static_fileproviders`**, plus **`apps` / `app_versions`**, **`permission_audit_snapshots`**, and dynamic/analysis tables.

So: **fleet and app pages do not query legacy `findings` / `metrics` / `buckets` / `contributors` base tables** under the tightened SQL grep; they go through **views** or **canonical static** tables.

---

## 2. The misleading SQL alias `findings`

In `db_queries.php` (app directory / report header SQL), the fragment:

```sql
LEFT JOIN vw_static_finding_surfaces_latest findings
```

uses **`findings` only as a table alias** for the view `vw_static_finding_surfaces_latest`. Columns like `findings.canonical_high` are **view columns**, not the legacy **`findings`** base table.

**Takeaway:** word-boundary greps on `\bfindings\b` in this file are **not** evidence of legacy table use.

---

## 3. Findings Explorer and app findings pages

- **Explorer:** `SQL_FINDINGS_EXPLORER_*` selects from **`v_web_app_findings`** (`db_queries.php` ~355–378), with filters built in `db_findings_explorer.php` / `db_filters.php`.
- **Per-app list:** `SQL_APP_FINDINGS_LIST` reads **`static_analysis_findings`** joined to **`static_analysis_runs`** and **`apps`** (~198–214).

So “Findings” in the UI is **canonical static** + **web view contract**, not legacy **`findings`**.

---

## 4. Session health and quality

- **`v_web_static_session_health`** — session-level usability row (`SQL_STATIC_SESSION_HEALTH_BASE`).
- **Quality rollup** — `SQL_STATIC_SESSION_QUALITY` aggregates **`static_analysis_runs`** only (completed / in-progress / failed counts, `session_count`).

No legacy five here.

---

## 5. The only legacy base-table hit: `runs` count (diagnostics)

**Definition:** `SQL_DIAG_COUNTS` in `db_queries.php` (~690–703):

```sql
SELECT
  (SELECT COUNT(*) FROM runs) AS runs,
  (SELECT COUNT(*) FROM static_analysis_runs) AS static_runs,
  ...
```

**Plumbing:**

- `database/db_lib/db_app_reads.php` → **`app_diagnostics()`** maps the row to `'runs'` and `'static_runs'` (and audit/dynamic counts).
- **`pages/diag.php`** — plain-text diagnostic page; gated by **`SCYTALEDROID_WEB_ENABLE_DIAG`** (`1`/`true`/`yes`) **or** localhost (`127.0.0.1` / `::1`). Otherwise **404**.

**Operator meaning:** `runs` is **legacy registry row count**; `static_runs` is **canonical ledger**. They are intentionally side-by-side for DB sanity checks, not for end-user “findings truth.”

**Improvement (later, Web repo):** rename output keys / labels to **`legacy_runs`** / **`legacy_runs_total`** and echo as `legacy_runs:` vs `static_runs:` to match the Python-side “compatibility reduction plan.”

---

## 6. What the Web README lists vs legacy five

`database/README.md` **required** objects include **`static_findings_summary`** and **`static_findings`** as “compatibility/details bridge” — those are **not** the legacy **`findings`** mirror table; they are the **derived** baseline tables from the Python model.

Legacy **`runs` / `findings` / `metrics` / `buckets` / `contributors`** are **not** listed as required Web contracts. Only **`runs`** appears implicitly via **`SQL_DIAG_COUNTS`** (diagnostics only).

---

## 7. Dynamic “runs” vs legacy `runs`

Several PHP pages use **`$runs`** or English “runs” for **dynamic** session lists (`dynamic_sessions`, `v_web_runtime_run_index`). That is **unrelated** to the legacy **`runs`** static mirror table except naming collision in prose and variables.

---

## 8. Grep tips for the next pass

| Goal | Pattern idea |
| --- | --- |
| Legacy **base** table use | `\b(FROM|JOIN|INTO)\s+`runs`` or same for other four names |
| Avoid GitHub noise | exclude `.github/` or require `database/` path |
| Distinguish alias | inspect line: `JOIN vw_... findings` vs `FROM findings` |

---

## 9. Relation to Python maintenance docs

- Python reader inventory: **`legacy_static_reader_dependency_map.md`** §3 (+ **§8** edge cases). Short entry + baseline grep: **`legacy_static_tables_consumer_audit.md`** (index).
- Relabel / migrate sequencing: **`legacy_static_table_compatibility_reduction_plan.md`**
- This file: **how** the Web layer is structured so greps are interpreted correctly.

No Web or Python code was changed to produce this note.
