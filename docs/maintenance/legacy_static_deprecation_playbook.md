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
| Tests | `pytest tests/database tests/db_utils tests/persistence tests/static_analysis -q` (expand as touched) |
| Web smoke | `SCYTALEDROID_WEB_ROOT=… ./scripts/db/smoke_web_db.sh` when views/consumers change |
| Operator | Spot-check DB menus + one session reconcile report |

---

## What *not* to do

- **`DROP`** because tables look “stale” or empty in one environment.
- Remove **`static_reconcile`** legacy joins before **reporting and MASVS** consumers are migrated (surprise drift loss).
- Change **`v_static_handoff_v1`** or handoff contracts as part of legacy cleanup (orthogonal; high risk per `AGENTS.md`).

---

## Related docs

- `legacy_static_reader_dependency_map.md` — **authoritative planning map** for legacy-five **readers** (this repo), false positives, `metrics.run_id` warning, Phase 2 retirement buckets. **§8** records follow-up gaps: indirect `table_counts` over the whole catalog, `health_checks_permission` → `contributors`, `v_run_overview` smoke chain, CSV/matrix drift if it reappears, **`status_actions` vs `schema_gate`** (resolved — §8.5), and **`run_persistence_queries` reconcile bridge** shape (**fixed** — §8.6).
- `legacy_static_phase2a_policy_alignment_plan.md` — **completed** Phase 2A record + verification commands (stub).
- `legacy_static_tables_consumer_audit.md` — **index**: tables in scope, INSERT grep, legend; points here for per-table readers.
- `legacy_static_table_compatibility_reduction_plan.md` — relabel vs migrate buckets.
- `legacy_static_tables_web_deep_dive.md` — Web contract; single `runs` diagnostic.
- `static_database_schema_audit_plan.md` — read-only inventory semantics.

This playbook is the **better way**: sequenced, reversible early steps, explicit data and DDL gates at the end.
