# `session_static_health.py` hygiene plan (canonical-first)

**Status:** **implemented** in `scripts/db/session_static_health.py` (canonical gate subset + legacy SKIP/INFO + exit `1` on canonical SQL errors). Session identity contract: `docs/maintenance/session_identity_contract.md`.  
**Goal:** align `scripts/db/session_static_health.py` with `scripts/db/audit_static_session.py` and `session_identity_contract.md` so operators get **canonical-first**, **legacy-optional** output without treating empty mirrors as failure.

---

## 1. Current comparison

### `audit_static_session.py` (reference behavior)

- Canonical persistence sections first (`static_analysis_runs`, `static_analysis_findings`, matrix, strings, rollups).
- **Legacy mirror** block uses **`diagnostics.check_required_tables`** for `runs`, `metrics`, `buckets`, `findings`; missing tables → **SKIP** rows with explicit status (not exit 2/3 for “empty legacy”).
- Documents that empty legacy mirror is **OK** for canonical-only catalogs.
- Optional **MASVS view** strict mode is a separate flag (`--strict-masvs-views`).

### `session_static_health.py` (current)

- **Primary filter:** `static_analysis_runs.session_stamp = :session` (arg `--session`); docstring says “session_stamp on static_analysis_runs”.
- **Canonical:** findings via SAR join; matrix / vnext / `permission_audit_apps` via `run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp=…)`.
- **Legacy findings:** `try` / `except` around `findings` + `runs` join — on missing table prints **`ERROR:`** in the label line (exception string), but **exit code stays 0** unless the initial SAR query fails. So it is **not** a hard failure, but **wording reads like failure** to operators.
- **vnext missing:** prints informational “table not present”; skew section skipped — good pattern to mirror for legacy.
- **Package hint:** prints ad hoc SQL with **string interpolation** of `session` (escaped for quotes only) — security/robustness debt vs parameterized examples in `audit_static_session` copyable SQL appendix.

---

## 2. Proposed direction (implementation pass — later)

1. **Docstring / `--help`:** State explicitly that `--session` is the **`static_analysis_runs.session_stamp`** selector today; link **`session_identity_contract.md`** for `session_label` vs `session_stamp` and optional future `--session-label` flag if product wants both probes in one script.
2. **Legacy block:** Mirror **`check_required_tables`** gating from `audit_static_session.py` before touching `findings`/`runs`. If absent: print **`SKIP (legacy findings mirror absent)`** (or **INFO**), **no** stack-style `ERROR:` line for expected catalog layout.
3. **Ordering:** Keep canonical sections first; label the legacy subsection **“Legacy mirror (compatibility)”** with one-line reminder: empty is normal.
4. **Exit codes:** Preserve **0** when SAR query succeeds even if legacy skipped; reserve **1** for DB/import errors and empty `--session` only (align with audit script semantics where practical).
5. **Optional:** Add `--session-label` to run the same canonical probes against **`session_label`** for operators who scope that way — **only** if tests are added; otherwise defer.

---

## 3. Tests / verification (when implemented)

- **Manual:** run against a catalog **without** legacy `findings`: expect **SKIP/INFO**, exit **0**, canonical counts unchanged.
- **Automated (if added):** thin subprocess or golden stdout test under `tests/gates/` or `tests/scripts/` — only if the team accepts script output contracts in CI.

---

## 4. Out of scope here

- **No** `metrics` migration, **no** `views_bridge`, **no** reset list changes, **no** Web repo.
