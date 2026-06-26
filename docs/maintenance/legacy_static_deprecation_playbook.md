# Legacy static tables — deprecation playbook (better-than-drop)

**Audience:** operators and maintainers after the read-only audits (`static_schema_audit.py`, [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md), short index [legacy_static_tables_consumer_audit.md](legacy_static_tables_consumer_audit.md), [legacy_static_tables_web_deep_dive.md](legacy_static_tables_web_deep_dive.md)).

**Problem with “prune and remove tables first”:** legacy five still have **Python readers**, **`reset_static`** deletes, **`contracts.SCIENTIFIC_UOW_TABLES`**, populated **historical rows**, and **MASVS / reconcile / risk** paths. Dropping tables before code and data policy catches up **breaks** production workflows and loses evidence.

**Better way:** treat legacy as a **compatibility surface to retire in layers**, with **exit criteria** per layer. **DDL last**; **labels and read-path cuts first**.

---

## Principles

1. **Canonical truth** stays `static_analysis_*`, session links, permission cohort, and Web `v_web_*` / `vw_static_*` — unchanged from `AGENTS.md`.
2. **No physical `DROP TABLE`** until: (a) no remaining **required** reader in this repo + Web, (b) **data disposition** signed off (archive vs retain read-only), (c) **smoke** passes.
3. **Empty legacy tables** are normal for some cohorts; **non-empty** tables are **historical**, not necessarily “wrong” — deletion is a **governance** choice, not a hygiene default.

---

## Phase 0 — Freeze semantics (current checkpoint)

- Schema audit + dependency map / consumer index + Web grep documented.
- Legacy = **compatibility / historical keep** until later phases complete.

**Exit:** team agrees this playbook is the controlling narrative (replaces ad hoc “just delete”).

---

## Phase 1 — Reduce confusion (no schema, low risk)

- **CLI / menus / audits:** label legacy counts as *legacy registry / compatibility*, not “missing static”.

**Partially applied (Python repo):** `scytaledroid/Database/db_utils/menus/query_runner.py` (active session downstream + digest: split **Canonical persistence** vs **Legacy mirror**; clearer orphan message); `scytaledroid/StaticAnalysis/cli/execution/db_verification.py` (footer keys for legacy tables); `scripts/db/audit_static_session.py` (legacy banner); `scytaledroid/StaticAnalysis/cli/persistence/contracts.py` (UoW legacy-name comment); `tests/static_analysis/test_diagnostic_output_helpers.py` (assert string for renamed canonical findings label).
- **Web (optional):** rename diagnostic keys (`legacy_runs_total` vs canonical count) — `legacy_static_tables_web_deep_dive.md`.
- **Docs:** point operators to canonical tables for “truth” questions.

**Exit:** new operators can answer “where is truth?” without reading Python.

---

## Phase 2 — Quarantine new dependencies

- **No new** `FROM`/`JOIN` on legacy five without RFC + reviewer.
- Grep / CI optional: fail PR if new SQL references legacy names outside an allowlist (later).
- **Precision map:** use [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) for **file/function-level** call sites, false positives, **`metrics.run_id` semantic split** (canonical `static_analysis_runs.id` vs legacy `runs.run_id`), and the **Phase 2 reader-retirement ordering** buckets before changing code.

**Exit:** debt stops growing.

---

## Phase 3 — Retire read paths (ordered, still no `DROP`)

Use **`bridge_posture.py`** and **[legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) §3** as the primary checklist (the [consumer index](legacy_static_tables_consumer_audit.md) is the short entry page). Suggested **order** (each step = PR-sized, with tests):

1. **Diagnostics-only** paths that only *display* legacy totals (easy to gate or remove display).
2. **`query_runner.py` / menu** legacy SQL — move under “Legacy (informational)” or hide behind env (display only).
3. **`db_verification.py`** — separate “canonical required” vs “legacy informational” sections (behavior unchanged first; then tighten).
4. **`audit_static_session.py` / `session_static_health.py`** — same labeling; counts remain optional.
5. **`masvs_summary_report.py`** legacy `findings` SQL — migrate to canonical/static_findings paths; env gates already documented elsewhere.
6. **`dep_view.py`** optional `metrics` branch — remove or switch when no catalog needs it.
7. **`risk_actions.py`** `metrics` joins — migrate to `static_permission_matrix` / `risk_scores` / views per reporting owners.
8. **`views_bridge.py`** — deprecate view or replace consumers; **high coordination** with any SQL outside repo.
9. **`static_reconcile.py` / `run_persistence_queries.py`** — **last** major readers; they encode drift semantics between canonical and legacy.

**Exit per table:** grep shows **zero** `FROM`/`JOIN`/required subselects on that table in `scytaledroid/` and Web (tight pattern), except `reset_static` / explicit archive tooling.

---

## Phase 4 — Contracts and reset

- **`contracts.SCIENTIFIC_UOW_TABLES`:** document then split or trim legacy names when UoW boundaries no longer need them (tests + persistence review).
- **`reset_static.py`:** only narrow `STATIC_ANALYSIS_TABLES` / delete paths **after** Phase 3 exit for that table — otherwise resets leave orphans or confuse operators.

**Exit:** contract and reset behavior match “legacy tables optional / absent.”

---

## Phase 5 — Data disposition (before DDL)

- **Export** or **document retention** for rows in legacy five (legal/audit/compliance as applicable).
- Decide: **retain empty tables**, **truncate** in controlled maintenance, or **`DROP`** after archive.

**Exit:** written decision + evidence location (dump path, ticket, runbook).

---

## Phase 6 — DDL (last)

- **`DROP TABLE`** (or rename to `_archived_*`) in a **controlled migration** with backup, rollback notes, and **`smoke_web_db.sh`** + targeted pytest slices.

**Exit:** schema matches code; no orphan views; Permission Intel / core gates re-run as applicable.

---

## Verification gates (repeat after each phase)

| Gate | Command / action |
| --- | --- |
| Python legacy SQL grep | Same tight patterns as [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) “Re-verify command” |
| Web grep | Same as Web deep dive |
| Tests | `pytest tests/database tests/db tests/persistence tests/static_analysis -q` (expand as touched) |
| Web smoke | `SCYTALEDROID_WEB_ROOT=… ./scripts/db/smoke_web_db.sh` when views/consumers change |
| Operator | Spot-check DB menus + one session reconcile report |

---

## What *not* to do

- **`DROP`** because tables look “stale” or empty in one environment.
- Remove **`static_reconcile`** legacy joins before **reporting and MASVS** consumers are migrated (surprise drift loss).
- Change **`v_static_handoff_v1`** or handoff contracts as part of legacy cleanup (orthogonal; high risk per `AGENTS.md`).

---

## Appendix A — Table compatibility reduction (merged, Wave W1) {#legacy-static-table-compatibility-appendix}

*Former standalone doc: `legacy_static_table_compatibility_reduction_plan.md` (archived content merged here; file removed to reduce duplicate maintenance.)*

**Status:** planning only. **No removals, DDL, migrations, or drops.** Builds on [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) §3, [legacy_static_tables_consumer_audit.md](legacy_static_tables_consumer_audit.md) (index), and the read-only schema audit checkpoint.

**Goal:** reduce operator confusion (“is this still truth?”) without breaking compatibility readers or reconciliation.

### A.1 Principles

- **Canonical static truth** remains `static_analysis_*`, `static_session_*`, permission cohort tables, and related first-class surfaces per `AGENTS.md`.
- Legacy five (`runs`, legacy `findings`, `metrics`, `buckets`, `contributors`) are **historical archive + compatibility** — labels should say so explicitly anywhere they surface in CLI/menus/audit text.
- **Web repo** is out of tree here (operator layout: **`/var/www/html/ScytaleDroid-Web`** — adjust if your deploy differs). Any physical archive/drop requires a **separate Web grep** there first (see §A.6 Web).

### A.2 Operator-facing labels (relabel only)

**Intent:** add or strengthen wording: **legacy**, **compatibility**, **historical**, **not canonical static truth**.

| Area | Suggestion | Risk |
| --- | --- | --- |
| DB menus / `query_runner.py` | Prefix section titles and copy-paste SQL comments: “Legacy (compatibility)” | Low — copy only |
| `db_verification.py` | Section headers for legacy mirror counts vs canonical counts | Low |
| `audit_static_session.py` | Banner line: legacy counts informational | Low |
| `session_static_health.py` | Same for any legacy block | Low |
| `run_persistence_queries.py` / reconcile summaries | Clarify “legacy mirror drift” vs “canonical missing” in operator strings | Low–medium (wording sensitivity per `AGENTS`) |
| `static_run_audit.py` | Template SQL comments | Low |

**Bucket:** **relabel only** — no query or schema changes in this slice.

### A.3 Diagnostic-only readers (candidate for legacy/compat section)

These are valuable for triage but **not** primary success criteria for canonical-only cohorts.

| Reader | Role today | Proposal |
| --- | --- | --- |
| `query_runner.py` | `legacy_runs` count, “Findings (legacy)” entries | Group under a **“Legacy compatibility (informational)”** submenu or collapsed section; label SQL snippets |
| `db_verification.py` | Totals / evidence for legacy tables | Same sectioning in output; keep logic, clarify headers |
| `scripts/db/audit_static_session.py` | Legacy counts not treated as failure | Strengthen intro + per-block labels (already partly documented) |
| `scripts/db/session_static_health.py` | Legacy JOIN counts | Same |

**Bucket:** **relabel + optional UX grouping** (still **keep as compatibility reader**). If a future flag exists (e.g. “hide legacy diagnostics”), gate **display only** — not removal of SQL without product sign-off.

### A.4 Readers that should remain (canonical vs legacy drift)

**Do not hide** behind “legacy optional” in a way that implies irrelevance — they answer “does stale mirror disagree with canonical?”

| Reader | Why keep prominent |
| --- | --- |
| `static_reconcile.py` | Core reconcile / missing-package logic uses legacy joins where present |
| `run_persistence_queries.py` | Session-level parity counts (canonical vs legacy) |
| `db_verification.py` | Same family — operator expects both columns in one pass until legacy retired |
| `bridge_posture.py` | Single posture registry for tools/docs |

**Bucket:** **keep as compatibility reader** (primary reconciliation/drift story).

### A.5 Migrate later (higher effort — do not start without RFC)

| Reference | Issue | Direction (later) |
| --- | --- | --- |
| `risk_actions.py` | SQL joins `metrics` | Prefer `static_permission_matrix` / `risk_scores` / vnext read models once reporting sign-off |
| `dep_view.py` | Optional `metrics` join | Same; or drop branch when metrics table unused in all target catalogs |
| `masvs_summary_report.py` | `FROM findings` legacy SQL | Already partially gated by env/docs; tighten toward `static_analysis_findings` / `static_findings` only |
| `views_bridge.py` | `runs` + `buckets` | Replace consumers with canonical views or deprecate view after Web grep |

**Bucket:** **migrate later** — sequencing after Web grep and contract updates.

### A.6 `contracts.SCIENTIFIC_UOW_TABLES` (future migration note)

**Now:** **keep** — persistence tooling and tests may assume this frozen set includes legacy names for transaction envelope / observability.

**Later decision:** Option A: split into `CANONICAL_UOW_TABLES` vs `LEGACY_COMPAT_TABLES`; Option B: remove legacy names once no writer/runtime reader depends on them for UoW boundaries. Document in changelog when changed.

**Bucket:** **do not touch yet** — add a short comment block in `contracts.py` when touching the file for any other reason (“legacy names: historical UoW envelope; not INSERT targets”).

### A.7 Web repo grep (required before archive/drop)

**Checkout:** **`/var/www/html/ScytaleDroid-Web`** (adjust per deploy).

**Tight SQL pattern (table use, not English “findings”):**

```bash
grep -RInE '\b(FROM|JOIN|UPDATE|INSERT INTO|DELETE FROM)\s+`?(runs|findings|metrics|buckets|contributors)`?\b' . \
  --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules --exclude='*.log'
```

**Result (checkpoint grep):** Only **`runs`** appears — `database/db_lib/db_queries.php` subselect **`(SELECT COUNT(*) FROM runs) AS runs`**. No hits on legacy **`findings`**, **`metrics`**, **`buckets`**, **`contributors`** with this pattern. Canonical static tables are referenced heavily in the same file (`static_analysis_runs`, `static_analysis_findings`, …) as expected.

See **`legacy_static_tables_web_deep_dive.md`** for view vs base-table structure (`v_web_app_findings`, `vw_static_finding_surfaces_latest AS findings`, `diag.php` gating).

**Follow-ups (still no DDL here):** relabel that dashboard/diag field as **legacy registry count** vs **`static_runs`**; re-run after Web changes.

**Bucket:** **Web grep requirement closed for this tree** — narrow **`runs`** read only. Legacy **`findings`/`metrics`/`buckets`/`contributors`** not used in Web SQL under the tightened pattern.

### A.8 Summary buckets

| Bucket | Items |
| --- | --- |
| **Keep as compatibility reader** | `static_reconcile.py`, `run_persistence_queries.py`, `db_verification.py` (drift sections), `bridge_posture.py`, `views_bridge.py` (until migrated), `risk_actions.py` / `dep_view.py` (until migrated), `masvs_summary_report.py` (until migrated), `menu_actions.py`, `permission_flow.py`, `static_run_audit.py`, `analysis_integrity.py`, `db_schema_snapshot.py` |
| **Relabel only** | Menu titles, audit script intros, verification section headers, query_runner labels/SQL comments |
| **Migrate later** | `risk_actions.py`, `dep_view.py`, `masvs_summary_report.py` legacy SQL, `views_bridge.py` consumers |
| **Web grep** | Done on **`/var/www/html/ScytaleDroid-Web`** (tight SQL pattern): only **`runs`** count in `db_queries.php`; re-run after releases |
| **Do not touch yet** | `contracts.SCIENTIFIC_UOW_TABLES` membership (comment-only ok), physical schema, `reset_static` delete order |

### A.9 Suggested sequencing (when work resumes)

1. **Relabel pass** (CLI/menus/audit strings only).
2. **Web grep** — repeat on release cadence.
3. **Optional UX:** group legacy diagnostic queries under one menu heading (no SQL removal).
4. **RFC:** one consumer at a time from **migrate later** with tests + Web smoke.
5. **Contracts split or trim** — after readers down to zero for that table.

### A.10 Explicit non-goals (this plan)

- No `DROP TABLE`, no migrations, no narrowing `reset_static` table list without replacement story.
- No removal of reconcile/verification reads until canonical-only story is signed off.

**Phased deprecation (full “better way”):** this playbook (phases above) — ordered phases, exit criteria, verification gates; **DDL last** after readers and data disposition.

---

## Related docs

- `legacy_static_reader_dependency_map.md` — **authoritative planning map** for legacy-five **readers** (this repo), false positives, `metrics.run_id` warning, Phase 2 retirement buckets, **§2.1.1** mirror-helper wiring (merged). **§8** records follow-up gaps: indirect `table_counts` over the whole catalog, `health_checks_permission` → `contributors`, `v_run_overview` smoke chain, CSV/matrix drift if it reappears, **`status_actions` vs `schema_gate`** (resolved — §8.5), and **`run_persistence_queries` reconcile bridge** shape (**fixed** — §8.6).
- `legacy_static_phase2a_policy_alignment_plan.md` — **completed** Phase 2A record + verification commands (stub).
- `legacy_static_tables_consumer_audit.md` — **index**: tables in scope, INSERT grep, legend; points here for per-table readers. Relabel / UX sequencing: see **Appendix A** above.
- `legacy_static_tables_web_deep_dive.md` — Web contract; single `runs` diagnostic.
- `static_database_schema_audit_plan.md` — read-only inventory semantics.

This playbook is the **better way**: sequenced, reversible early steps, explicit data and DDL gates at the end.
