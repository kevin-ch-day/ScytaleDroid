# Legacy static table compatibility reduction plan

**Status:** planning only. **No removals, DDL, migrations, or drops.** Builds on [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) §3, [legacy_static_tables_consumer_audit.md](legacy_static_tables_consumer_audit.md) (index), and the read-only schema audit checkpoint.

**Goal:** reduce operator confusion (“is this still truth?”) without breaking compatibility readers or reconciliation.

---

## Principles

- **Canonical static truth** remains `static_analysis_*`, `static_session_*`, permission cohort tables, and related first-class surfaces per `AGENTS.md`.
- Legacy five (`runs`, legacy `findings`, `metrics`, `buckets`, `contributors`) are **historical archive + compatibility** — labels should say so explicitly anywhere they surface in CLI/menus/audit text.
- **Web repo** is out of tree here (operator layout: **`/var/www/html/ScytaleDroid-Web`** — adjust if your deploy differs). Any physical archive/drop requires a **separate Web grep** there first (see §Web).

---

## 1. Operator-facing labels (relabel only)

**Intent:** add or strengthen wording: **legacy**, **compatibility**, **historical**, **not canonical static truth**.

| Area | Suggestion | Risk |
| --- | --- | --- |
| DB menus / `query_runner.py` | Prefix section titles and copy-paste SQL comments: “Legacy (compatibility)” | Low — copy only |
| `db_verification.py` | Section headers for legacy mirror counts vs canonical counts | Low |
| `audit_static_session.py` | Banner line: legacy counts informational | Low |
| `session_static_health.py` | Same for any legacy block | Low |
| `run_persistence_queries.py` / reconcile summaries | Clarify “legacy mirror drift” vs “canonical missing” in operator strings | Low–medium (wording sensitivity per AGENTS) |
| `static_run_audit.py` | Template SQL comments | Low |

**Bucket:** **relabel only** — no query or schema changes in this slice.

---

## 2. Diagnostic-only readers (candidate for legacy/compat section)

These are valuable for triage but **not** primary success criteria for canonical-only cohorts.

| Reader | Role today | Proposal |
| --- | --- | --- |
| `query_runner.py` | `legacy_runs` count, “Findings (legacy)” entries | Group under a **“Legacy compatibility (informational)”** submenu or collapsed section; label SQL snippets |
| `db_verification.py` | Totals / evidence for legacy tables | Same sectioning in output; keep logic, clarify headers |
| `scripts/db/audit_static_session.py` | Legacy counts not treated as failure | Strengthen intro + per-block labels (already partly documented) |
| `scripts/db/session_static_health.py` | Legacy JOIN counts | Same |

**Bucket:** **relabel + optional UX grouping** (still **keep as compatibility reader**). If a future flag exists (e.g. “hide legacy diagnostics”), gate **display only** — not removal of SQL without product sign-off.

---

## 3. Readers that should remain (canonical vs legacy drift)

**Do not hide** behind “legacy optional” in a way that implies irrelevance — they answer “does stale mirror disagree with canonical?”

| Reader | Why keep prominent |
| --- | --- |
| `static_reconcile.py` | Core reconcile / missing-package logic uses legacy joins where present |
| `run_persistence_queries.py` | Session-level parity counts (canonical vs legacy) |
| `db_verification.py` | Same family — operator expects both columns in one pass until legacy retired |
| `bridge_posture.py` | Single posture registry for tools/docs |

**Bucket:** **keep as compatibility reader** (primary reconciliation/drift story).

---

## 4. Migrate later (higher effort — do not start without RFC)

These tie reporting or views to legacy shapes; reducing them is **migration work**, not a label pass.

| Reference | Issue | Direction (later) |
| --- | --- | --- |
| `risk_actions.py` | SQL joins `metrics` | Prefer `static_permission_matrix` / `risk_scores` / vnext read models once reporting sign-off |
| `dep_view.py` | Optional `metrics` join | Same; or drop branch when metrics table unused in all target catalogs |
| `masvs_summary_report.py` | `FROM findings` legacy SQL | Already partially gated by env/docs; tighten toward `static_analysis_findings` / `static_findings` only |
| `views_bridge.py` | `runs` + `buckets` | Replace consumers with canonical views or deprecate view after Web grep |

**Bucket:** **migrate later** — sequencing after Web grep and contract updates.

---

## 5. `contracts.SCIENTIFIC_UOW_TABLES` (future migration note)

**Now:** **keep** — persistence tooling and tests may assume this frozen set includes legacy names for transaction envelope / observability.

**Later decision:**

- Option A: **Split** into `CANONICAL_UOW_TABLES` vs `LEGACY_COMPAT_TABLES` (same union for backward compatibility, clearer docs).
- Option B: **Remove** legacy names from the scientific set once no writer and no runtime reader depends on them for UoW boundaries.
- Document in changelog when changed — **gates** and **persistence tests** may assert membership.

**Bucket:** **do not touch yet** — add a short comment block in `contracts.py` when touching the file for any other reason (“legacy names: historical UoW envelope; not INSERT targets”).

---

## 6. Web repo grep (required before archive/drop)

**Checkout:** **`/var/www/html/ScytaleDroid-Web`** (adjust per deploy).

**Tight SQL pattern (table use, not English “findings”):**

```bash
grep -RInE '\b(FROM|JOIN|UPDATE|INSERT INTO|DELETE FROM)\s+`?(runs|findings|metrics|buckets|contributors)`?\b' . \
  --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules --exclude='*.log'
```

**Result (checkpoint grep):** Only **`runs`** appears — `database/db_lib/db_queries.php` subselect **`(SELECT COUNT(*) FROM runs) AS runs`**. No hits on legacy **`findings`**, **`metrics`**, **`buckets`**, **`contributors`** with this pattern. Canonical static tables are referenced heavily in the same file (`static_analysis_runs`, `static_analysis_findings`, …) as expected.

See **`legacy_static_tables_web_deep_dive.md`** for view vs base-table structure (`v_web_app_findings`, `vw_static_finding_surfaces_latest AS findings`, `diag.php` gating).

**Follow-ups (still no DDL here):**

- Relabel that dashboard/diag field as **legacy registry count** vs **`static_runs`** so operators are not confused.
- Re-run after Web changes; other hosts may carry forked SQL.

**Bucket:** **Web grep requirement closed for this tree** — narrow **`runs`** read (`SQL_DIAG_COUNTS` → `app_diagnostics()` / `diag.php` only). Legacy **`findings`/`metrics`/`buckets`/`contributors`** not used in Web SQL under the tightened pattern. Web is **not** a major blocker vs Python’s compatibility keep story.

**Archive/drop:** still blocked for all five in **Python** until readers/menus migrate. **`runs`** additionally appears in Web **diagnostics** only — optional later **Web** relabel of keys (`legacy_runs_total`, `canonical_static_runs_total`) with **no DB changes** (see `legacy_static_tables_web_deep_dive.md` checkpoint verdict).

---

## Summary buckets

| Bucket | Items |
| --- | --- |
| **Keep as compatibility reader** | `static_reconcile.py`, `run_persistence_queries.py`, `db_verification.py` (drift sections), `bridge_posture.py`, `views_bridge.py` (until migrated), `risk_actions.py` / `dep_view.py` (until migrated), `masvs_summary_report.py` (until migrated), `menu_actions.py`, `permission_flow.py`, `static_run_audit.py`, `analysis_integrity.py`, `db_schema_snapshot.py` |
| **Relabel only** | Menu titles, audit script intros, verification section headers, query_runner labels/SQL comments |
| **Migrate later** | `risk_actions.py`, `dep_view.py`, `masvs_summary_report.py` legacy SQL, `views_bridge.py` consumers |
| **Web grep** | Done on **`/var/www/html/ScytaleDroid-Web`** (tight SQL pattern): only **`runs`** count in `db_queries.php`; re-run after releases |
| **Do not touch yet** | `contracts.SCIENTIFIC_UOW_TABLES` membership (comment-only ok), physical schema, `reset_static` delete order |

---

## Suggested sequencing (when work resumes)

1. **Relabel pass** (CLI/menus/audit strings only) — smallest diff, highest confusion reduction.
2. **Web grep** — repeat on release cadence; checkpoint shows only **`runs`** SQL (see §6).
3. **Optional UX:** group legacy diagnostic queries under one menu heading (no SQL removal).
4. **RFC:** one consumer at a time from **migrate later** with tests + Web smoke.
5. **Contracts split or trim** — after readers down to zero for that table.

---

## Explicit non-goals (this plan)

- No `DROP TABLE`, no migrations, no narrowing `reset_static` table list without replacement story.
- No removal of reconcile/verification reads until canonical-only story is signed off.

**Phased deprecation (full “better way”):** `legacy_static_deprecation_playbook.md` — ordered phases, exit criteria, verification gates; **DDL last** after readers and data disposition.
