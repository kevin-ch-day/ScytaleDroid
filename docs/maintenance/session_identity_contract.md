# Session identity contract (static analysis)

**Status:** maintenance / policy — normative for **new** Python and script SQL.  
**Audience:** authors of persistence, diagnostics, reconcile, and Web-facing SQL in this repo.  
**Runtime truth:** when this doc disagrees with code, fix the code **or** update this doc in the same change set.

---

## 1. Terms

| Term | Definition |
| --- | --- |
| **`session_stamp`** | Column on **`static_analysis_runs`** (and on several canonical child / rollup tables such as `static_string_summary`, `risk_scores`). Often matches the CLI “session folder” token. Used in **`WHERE sar.session_stamp = %s`** when the query is intentionally scoped by that column. |
| **`session_label`** | Column on **`static_analysis_runs`**. Human/session scope key used in many canonical joins and in **`reconcile_static_session`**. Persistence audit direct counts filter canonical SAR rows by **`session_label`** when reconciling DB truth. |
| **`static_run_id`** | Primary key **`static_analysis_runs.id`** for one persisted static run. **Canonical** child tables reference this as **`run_id`** or **`static_run_id`** depending on table (see schema). |
| **Legacy `runs.run_id`** | Primary key of the **legacy mirror** table **`runs`**. **Not** interchangeable with `static_analysis_runs.id`. |
| **`runs.session_stamp`** | Legacy mirror session discriminator; used only when joining **`runs`** (and rows keyed by legacy `runs.run_id`). |
| **`risk_scores.session_stamp`** | Rollup table column; must align with how rollups were written for the session (typically the same string as SAR `session_stamp` for that batch). **Not** a join key into `static_analysis_findings`. |

---

## 2. Canonical vs legacy joins

### Canonical (required for new code)

- **Hub:** `static_analysis_runs` (`sar`), keyed by **`sar.id`** = `static_run_id` for the run.
- **Child facts:** `static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, and other SAR children must be scoped with:

  ```text
  JOIN static_analysis_runs sar ON sar.id = <child>.run_id   -- or static_run_id per table
  WHERE sar.session_label = %s   -- or sar.session_stamp = %s when the product filter is stamp-scoped
  ```

- **Forbidden pattern:** `FROM static_analysis_findings WHERE session_label = %s` (and similarly **`session_stamp` on child tables that do not have that column**). Session scope lives on **`static_analysis_runs`**, not on arbitrary child tables.

### Legacy compatibility (diagnostics, reconcile, optional mirror)

- **`runs`**, legacy **`findings`**, **`metrics`**, **`buckets`**, **`contributors`**: join through **`runs.session_stamp`** and **`runs.run_id`** as today’s readers do. Treat empty/absent tables as **normal** for canonical-only deployments (`AGENTS.md`).
- **Do not** assume legacy `metrics.run_id` equals `static_analysis_runs.id` without reading the call site: **two semantics** exist in this codebase (see `legacy_static_reader_dependency_map.md` §6). **Mechanical** global replace on `metrics` / `metrics.run_id` is **forbidden** without per-query classification.

---

## 3. When one CLI string is used for both `session_label` and legacy `runs.session_stamp`

In typical single-session CLI flows, operators pass one token that is written as both **`session_stamp`** and **`session_label`** on `static_analysis_runs`, and the same string may appear on **`runs.session_stamp`** when historical mirror rows exist.

When **`session_label` ≠ `session_stamp`** on SAR (edge flows, retries, or tooling that sets them differently):

- Canonical reconciliation and **audit direct counts** that filter by **`session_label`** may **not** match legacy mirror queries keyed by **`runs.session_stamp`**.
- **Persistence audit fallback** documents that bridge and canonical paths may need different tokens in those edge cases; prefer **`reconcile_static_session(session_label)`** when available.

---

## 4. Quick reference: which column for a probe?

| Goal | Prefer |
| --- | --- |
| “All SAR rows for this operator session folder” | Usually **`static_analysis_runs.session_stamp`** if the operator passed the filesystem/CLI stamp. |
| “Same scope as reconcile / persistence audit canonical counts” | **`static_analysis_runs.session_label`** — confirm caller matches your intent. |
| “Legacy mirror package coverage” | **`runs.session_stamp`** (and joins through **`runs.run_id`**). |
| “Per-run permission facts / risk rows” | Filter by **`run_id` / `static_run_id`** = **`static_analysis_runs.id`**, not legacy `runs.run_id`. |

---

## 5. Related documents

- `docs/maintenance/legacy_static_reader_dependency_map.md` — reader inventory; **`metrics.run_id`** warning.
- `docs/maintenance/session_static_health_hygiene_plan.md` — aligning `session_static_health.py` with this contract (planned).
- `docs/maintenance/next_pass_docs_policy_implementation_plan.md` — rollout checklist for this policy slice.
