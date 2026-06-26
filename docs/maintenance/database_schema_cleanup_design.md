# Database schema cleanup and Web source-of-truth — design proposal

**Status:** design / phased plan — **no destructive SQL** in initial implementation.  
**Goal:** move from ad hoc inspection to a **DB-first** contract where **MariaDB (canonical tables + owned views)** is the **source of truth** for the Web; filesystem JSON remains **supporting evidence**, not the primary query surface.  
**Constraints (stated by product):** no destructive SQL in the first implementation wave; **no detector behavior changes**; **do not backfill** broken historical sessions to appear valid; prefer **fresh reruns** over repair of bad legacy rows.

**Related:** [database_target_schema_v2.md](database_target_schema_v2.md) (**target** domain model and V2 views — prefer for new work), [database_cleanup_audit_plan.md](database_cleanup_audit_plan.md) (read-only audit SQL pack; see Section 9 for SQL inventory), [legacy_static_deprecation_playbook.md](legacy_static_deprecation_playbook.md), [session_identity_contract.md](session_identity_contract.md), `scytaledroid/Database/db_queries/views_web.py` (`v_web_app_sessions`).

---

## Evidence baseline (operator DB — examples)

These facts drive disposition rules; recompute in your environment before any later prune.

| Session | Shape | Notes |
| --- | --- | --- |
| `20260511-all-full` | Interrupted partial | Many `FAILED` + `user_abort` / `SIGINT`; partial findings/permission rows; **no** session links / rollups — expected when finalize never ran. |
| `20260509-all-full` | Mixed | Completed + failed; at least one **real** `static_persistence_failures` row (`permission_risk.write` / duplicate canonical permission collision). |
| `20260429-all-full` | Broken historical | Predominantly `persist_error`, near-zero findings — **do not backfill**; treat as legacy noise / prune candidate after export + supersession. |

**`is_canonical` on `static_analysis_runs`:** today this is effectively a **per-`session_label` “representative winner”** flag (you observed exactly one `is_canonical=1` per session). That is **not** the same as “this row is the package-level canonical truth for all time.” Session-level summaries must not overload this field semantically; surface clarity in `static_analysis_sessions` + views instead.

---

## 1. `static_analysis_sessions` — first-class session aggregate

### 1.1 Purpose

Introduce a **single session header row** per logical static batch (keyed by **`session_stamp` + `scope_label`**, matching `static_session_rollups` and many child tables) so operators and the Web can answer:

- What **happened** to this session (completed, interrupted, mixed, broken)?
- What **counts** exist at aggregate level (runs, packages, findings, permission rows, links, rollups, handoff)?
- Is this session **safe for paper-grade / dynamic handoff** surfaces?
- Has a **later session** superseded this one for retention/cleanup?

`static_analysis_runs` remains the **grain-one-row-per-analysis-attempt** (per `app_version_id` / APK identity for that attempt). It holds **per-run** status, hashes, abort signals, detector outputs linkage, and **`session_stamp` / `session_label` / `scope_label`** as foreign context. **`static_analysis_sessions` does not replace runs**; it **summarizes and classifies** the set of runs sharing a session key.

### 1.2 Proposed columns (additive DDL — future phase)

Natural key aligned with rollups: **`PRIMARY KEY (session_stamp, scope_label)`** (both `VARCHAR`, same widths as `static_session_rollups`).

| Column | Type | Role |
| --- | --- | --- |
| `session_stamp` | `VARCHAR(128)` | Stable session id (existing convention). |
| `scope_label` | `VARCHAR(191)` | Scope partition (default `''` if unused). |
| `session_label` | `VARCHAR(191)` NULL | Human / operator label when distinct from stamp. |
| `profile_key` / `scenario_id` | optional | If you want session-level routing without inferring from runs. |
| `session_status` | `ENUM` or `VARCHAR(32)` | Aggregate machine status: `OPEN`, `CLOSED_OK`, `CLOSED_PARTIAL`, `CLOSED_BROKEN` (exact enum TBD). |
| `session_disposition` | `VARCHAR(64)` | Classification from §2 (e.g. `interrupted_partial_session`). |
| `disposition_detail_json` | `JSON` NULL | Evidence: abort histogram, persist failure ids, “missing finalize” flags. |
| `expected_package_count` | `INT UNSIGNED` NULL | From planner / profile manifest when known. |
| `completed_run_count` | `INT UNSIGNED` | `status=COMPLETED` runs in session. |
| `failed_run_count` | `INT UNSIGNED` | Includes user abort + persist errors — detail in JSON / disposition. |
| `interrupted_run_count` | `INT UNSIGNED` | Subset failed where `abort_reason` in (`user_abort`, …) and/or `abort_signal` set. |
| `persist_error_run_count` | `INT UNSIGNED` | Subset tied to `static_persistence_failures` or `persist_error` style statuses. |
| `total_findings_rows` | `BIGINT UNSIGNED` | Sum or max policy — document whether “sum across runs” or “latest per package.” |
| `total_permission_matrix_rows` | `BIGINT UNSIGNED` | Aggregated from child tables. |
| `total_permission_risk_rows` | `BIGINT UNSIGNED` | Same. |
| `total_string_summary_rows` | `INT UNSIGNED` | Session-scoped string summaries. |
| `session_link_rows` | `INT UNSIGNED` | Rows in `static_session_run_links` for this `session_stamp` (+ scope if modeled). |
| `rollup_present` | `TINYINT(1)` | Whether `static_session_rollups` has a row. |
| `runs_with_handoff_hash` | `INT UNSIGNED` | Count runs where `static_handoff_hash` non-null (or view-equivalent). |
| `paper_grade_ready` | `TINYINT(1)` | Boolean gate; **false** for interrupted/mixed/broken unless policy explicitly allows. |
| `paper_grade_blockers_json` | `JSON` NULL | Structured reasons (governance, missing audit snapshot, incomplete session, etc.). |
| `superseded_by_session_stamp` | `VARCHAR(128)` NULL | Optional retention pointer when a later successful session replaces this label class. |
| `superseded_by_scope_label` | `VARCHAR(191)` NULL | Keep scope aligned. |
| `cleanup_status` | `VARCHAR(32)` | `none`, `export_pending`, `prune_candidate`, `archived`, `pruned` — operator workflow only. |
| `first_run_created_at` / `last_run_activity_at` | timestamps | From `MIN`/`MAX` over runs. |
| `updated_at_utc` | timestamp | Maintainer for backfill jobs. |

**Honest backfill rule:** initial population **only** copies **observed aggregates** from existing tables; **do not** infer “completed_full_session” for broken April data. Broken sessions remain classified as broken in this table.

### 1.3 How it differs from `static_analysis_runs`

| Aspect | `static_analysis_sessions` | `static_analysis_runs` |
| --- | --- | --- |
| Grain | One row per **session** (+ scope) | One row per **analysis attempt** (per capture / app version context). |
| Identity | `session_stamp` / `scope_label` | `id`, `app_version_id`, APK hashes, `artifact_set_hash`. |
| Status | **Aggregate** session outcome | **Per-package** pipeline status, abort, hashes. |
| Web default | Header for “which sessions exist” and “which are usable” | Joined for drill-down; not the first row operators scan for batch health. |
| Canonical winner | N/A (or optional “preferred session” pointer) | `is_canonical` remains per-session-label winner among **runs** — document separately; may later be deprecated for Web in favor of session disposition + `vw_*_latest` rules. |

---

## 2. Session disposition model

### 2.1 Classifications

| Class | Definition (operational) |
| --- | --- |
| `completed_full_session` | Session intent was full cohort; **all** expected runs `COMPLETED`; finalize produced links/rollups per policy; no open persistence failures for session. |
| `completed_profile_session` | Same as above but scoped profile (not “all apps”); counts match expected profile size. |
| `interrupted_partial_session` | Operator/system interrupt dominates (`user_abort`, `SIGINT`, etc.); partial child rows may exist; links/rollups often missing. |
| `mixed_completed_failed_session` | Non-trivial mix of `COMPLETED` and `FAILED` / other terminal states; may include **one-off** persistence failures on a subset of packages. |
| `broken_persist_error_session` | Persistence or schema errors dominate (`persist_error`, `static_persistence_failures` rows, repeated zero-finding failures). |
| `broken_missing_artifacts_session` | Runs marked complete but **missing** required hashes, handoff JSON paths, or child rows per **documented** completeness checks. |
| `legacy_historical_session` | Old pipeline era; known bad patterns; superseded by newer contracts — **no rewrite** of old rows. |
| `prune_candidate` | Policy-approved for removal after export + verification + supersession (see §6). |

Assignment can be **rule-based** in the hygiene job: start from histograms of `sar.status`, `abort_reason`, child counts, `static_persistence_failures`, presence of rollups/links.

### 2.2 Web visibility by default

| Disposition | Default Web catalog | Notes |
| --- | --- | --- |
| `completed_full_session` | **Visible** | Primary directory / “latest good” pools. |
| `completed_profile_session` | **Visible** | Same, with profile/scenario filters. |
| `interrupted_partial_session` | **Hidden** from primary “latest usable” selectors | Optional **operator toggle** “show partial / aborted evidence.” |
| `mixed_completed_failed_session` | **Partially visible** | Web should prefer **completed runs** and/or **latest usable-complete** logic (`v_web_app_sessions.session_usability` already approximates this — tighten with disposition). |
| `broken_persist_error_session` | **Hidden** | Hygiene report + DB menu only unless explicit audit mode. |
| `broken_missing_artifacts_session` | **Hidden** | Same. |
| `legacy_historical_session` | **Hidden** or “archive” tier | Never paper-grade default. |
| `prune_candidate` | **Hidden** | Until pruned or disposition reset after mistaken flag. |

This aligns with the stated rule: **Web defaults to completed/usable sessions**, not failed or interrupted historical noise.

---

## 3. Read-only session hygiene report (implement first)

### 3.1 Deliverables (non-destructive)

**Existing building block:** `scripts/db/session_static_health.py` — per-`session_stamp` read-only probe (runs, legacy mirror line, persistence audit file hints). The hygiene report **extends** that idea to **all sessions** (or top-N by recency) plus **disposition** and **prune_candidate** hints.

1. **`scripts/db/session_hygiene_report.py`** (or equivalent under `scripts/db/`)  
   - Inputs: optional `--session-stamp`, `--json`, `--limit`.  
   - Output: per-session table: disposition **proposal**, run status histogram, abort histogram, child counts (findings, matrix, risk, strings, links, rollups), `COUNT` from `static_persistence_failures`, handoff hash coverage, **cleanup candidate** flag with **reason string**.  
   - **Must not** contain `DELETE`, `UPDATE`, `TRUNCATE`, `ALTER`.

2. **Optional view `v_static_session_hygiene_v1`** (second small PR if desired)  
   - Read-only `SELECT` aggregating from `static_analysis_runs` + left joins to children.  
   - Keeps phpMyAdmin / BI consumers aligned with the same logic as the script.  
   - Register in `schema_manifest.py` / `recreate_web_consumer_views.py` per existing posture.

### 3.2 Classification hints (implementation detail)

Reuse patterns from `v_web_app_sessions` (per-run usability) but **aggregate to session**:

- If ≥1 `static_persistence_failures` for runs in session → elevate toward `mixed_*` or `broken_persist_error_session` depending on prevalence.  
- If failed runs are **mostly** `abort_reason=user_abort` and links=0 → `interrupted_partial_session`.  
- If failed runs mostly `persist_error` and findings≈0 → `broken_persist_error_session` / `legacy_historical_session`.

The script should print **`confidence`** (`high`/`medium`/`low`) when heuristics disagree (e.g. mixed interrupt + one persistence row).

---

## 4. Web source-of-truth model

### 4.1 Physical tables (canonical static truth)

The Web (and external BI) should treat these as **authoritative** for static results:

- `apps`, `app_versions` — package/version identity.  
- `static_analysis_runs` — run grain, status, session keys, hashes, handoff fields.  
- `static_analysis_findings` — detector rows (`run_id`).  
- `static_permission_matrix` — permission **facts** per run (see §5).  
- `static_permission_risk_vnext` — permission **risk projection** per run (derived).  
- `static_string_summary`, `static_string_samples`, `static_string_sample_sets` — string evidence (supporting).  
- `static_session_run_links`, `static_session_rollups` — session finalize artifacts.  
- `static_persistence_failures` — operator/diagnostic truth for “what broke at write time.”

**Not** primary static truth: legacy mirror (`runs`, legacy `findings`, `metrics`, `buckets`, `contributors`) — retirement per §8.

### 4.2 Views the Web should prefer

Existing façade (this repo owns DDL):

- `v_web_app_directory`, **`v_web_app_sessions`**, `v_web_app_findings`, `v_web_app_permissions`, `vw_static_finding_surfaces_latest`, `vw_static_risk_surfaces_latest`, `v_web_static_session_health` (session rollup health), `v_static_handoff_v1` (dynamic — **do not alter casually**).

### 4.3 Views to add or adjust (phased)

| Artifact | Action |
| --- | --- |
| `v_web_app_sessions` | **Narrow default:** add disposition join (from `static_analysis_sessions` once it exists, or inline heuristic CTE in a **new** `v_web_app_sessions_v2` during transition). Prefer filtering out `interrupted_partial_session` / `broken_*` from **default** `WHERE` in Web-facing wrapper view (keep `v_web_app_sessions` stable until Web repo is grepped). |
| `v_web_sessions_catalog` (new) | One row per `(session_stamp, scope_label)` with aggregate counts + `session_disposition` + `paper_grade_ready` — **operator + Web** “session picker.” |
| `v_run_identity` | Keep for **per-run** identity; document join: `vri.run_id = CAST(sar.id AS CHAR(64))`. Optionally add **`session_stamp` / `session_label`** in a **new** `v_run_identity_with_session_v1` view only (avoid changing `v_run_identity` contract per `AGENTS.md`). |

**Principle:** Web reads **views** for presentation; **no** second physical “cache truth” for static findings.

---

## 5. Permission schema pain point (`use_biometric` duplicate)

### 5.1 What the code does today

- `static_permission_risk_vnext` enforces **`UNIQUE (run_id, permission_name)`** (`static_permission_risk.py` DDL).  
- Python `_persist_permission_risk_vnext` dedupes by **`perm.lower()`** before upsert and logs **`duplicate_permission_skipped`** warnings when the manifest emits multiple keys that collapse to one canonical string.

### 5.2 Why a DB error can still surface

Hypotheses to validate on the failing row (read-only):

1. **Collation mismatch** on `permission_name`: unique index comparison differs from Python’s `lower()` (Unicode / Turkish dotless i / pad space edge cases).  
2. **Two writers**: rare race or a path that **bypasses** the Python dedupe (e.g. backfill SQL from `risk_actions.py` uses `LOWER(spm.permission_name)` with **different** collation than vnext insert).  
3. **`static_permission_matrix`** contains **two fact rows** that are distinct under matrix uniqueness but **collapse** when lowercased for risk — matrix DDL uniqueness may not match risk uniqueness.

### 5.3 Design direction (phased — **no detector change**)

| Layer | Role | Proposal |
| --- | --- | --- |
| `static_permission_matrix` | **Fact** table: “this run declared/saw this permission string with these attributes.” | Keep as fact. Consider **unique key** `(run_id, permission_name)` with explicit **utf8mb4** collation consistent across matrix and risk. |
| `static_permission_risk_vnext` | **Derived** risk row per run. | Keep one logical row per **canonical permission id** per run. |
| Column split (additive) | Disambiguate raw vs canonical | Add **`raw_permission_name`** (nullable) **or** store canonical in `permission_name` and add **`permission_name_original`** — pick one naming convention and migrate writers in a **later** PR. |
| Uniqueness | Stable identity | **`UNIQUE(run_id, canonical_permission_key)`** where `canonical_permission_key` is normalized with the **same** rules as the DB (prefer `LOWER` in SQL generation or a stored generated column). |
| `static_permission_observations` (optional) | Many raw strings → one canonical | Only if you need **audit** of colliding raw strings; otherwise **JSON array** on matrix row for “aliases seen” is enough. |

**Phase ordering:** (1) read-only view `GROUP BY run_id, normalized_key` for Web to never double-count; (2) collation alignment on risk + matrix; (3) additive columns + writer merge policy **in persistence only** (still not “detector”); (4) optional observations table if compliance needs immutable alias history.

---

## 6. Cleanup / prune strategy

### 6.1 Principles

- **Do not backfill** broken historical sessions.  
- **Prefer fresh reruns** for scientific truth.  
- **Prune** only with **export → preview → verify → delete** discipline.

### 6.2 Safe prune candidates (policy sketch — not executed here)

| Target | When safe |
| --- | --- |
| `20260429-all-full` | After **mysqldump** (or `audit_static_session.py` + documented SQL exports), and after a **newer completed session** covers the same intent; mark `prune_candidate` in session header. |
| Failed tail of `20260509-all-full` | **Selective** row delete is higher risk than **session-level** policy; prefer **leaving** completed rows, documenting failed packages, rerunning failed packages in a **new** session — only delete if legal/retention allows and dynamic links absent. |
| `20260511-all-full` (user-aborted) | **Later** — after debugging SIGINT behavior and after superseding **full** successful run; export row counts first. |

### 6.3 Export-before-delete

- Per session: `PYTHONPATH=. python scripts/db/audit_static_session.py --session …` (legacy + canonical blocks as implemented).  
- Bulk: `mysqldump` restricted to affected tables + `WHERE session_stamp=…` where supported, or full table dump to cold storage.  
- Archive **row counts JSON** signed into ticket.

### 6.4 Verify-after-delete

- Re-run hygiene script: session absent or `cleanup_status=pruned`.  
- `recreate_web_consumer_views.py` + `smoke_web_db.sh` (Web tree).  
- `pytest tests/database tests/db -q` slice.

### 6.5 Child dependency order (session-scoped prune)

**Preferred mechanical approach:** `DELETE FROM static_analysis_runs WHERE session_stamp = ? AND scope_label = ?` (narrow further if selective) and rely on **`ON DELETE CASCADE`** where defined (`static_analysis_findings`, `static_permission_matrix`, `static_permission_risk_vnext`, `static_session_run_links`, `static_fileproviders`, etc. — see `canonical/schema.py`).

**Tables that may NOT cascade** (require explicit `DELETE` or orphan policy):

- `risk_scores` — keyed by `package_name` + `session_stamp` + `scope_label` (no FK to `static_analysis_runs`).  
- `static_string_summary` / samples / sample sets — session-scoped strings.  
- `static_session_rollups` — delete row for `(session_stamp, scope_label)`.  
- `permission_audit_snapshots` / `permission_audit_apps` — `static_run_id` is **nullable** without FK to runs; **audit** before run delete (SET NULL vs snapshot delete policy).  
- `masvs_control_coverage` — keyed by `run_id`; typically removed with run if writer cleans — confirm FK in your deployed schema.

Always print **PREVIEW counts** per table before destructive files (Section 9).

---

## 7. Collation normalization

### 7.1 Normalize first (observed drift)

| Object | Why first |
| --- | --- |
| `static_session_run_links` | Joins to `apps.package_name` / `static_analysis_runs` in Web views already use `CONVERT(... COLLATE utf8mb4_unicode_ci)` workarounds — high join cost and bug surface. |
| `masvs_control_coverage` | Observed `latin1` drift; any future join to utf8mb4 packages risks silent mismatch. |
| `schema_version` | Only if information_schema shows mixed collations on text columns that participate in joins — low priority unless proven. |

### 7.2 Plan shape (no `ALTER` generation in this doc)

1. Export `information_schema.COLUMNS` for **all** varchar/text columns where collation ≠ target (choose **one** utf8mb4 collation for the catalog, e.g. `utf8mb4_unicode_ci` to match parts of `views_web.py`).  
2. Maintenance window: **convert links + masvs** in a single change batch; avoid partial state.  
3. **Rollback:** restore from pre-migration dump; or keep migration **additive** (new columns copied, cutover in view) — heavier but safer.

### 7.3 Risk

- **Medium:** silent row split/merge in Web if collation changes how `UNIQUE` keys dedupe.  
- **Mitigation:** `PREVIEW` distinct counts before/after on `(session_stamp, package_name)` for links; verify `v_web_app_sessions` row counts for a golden package set.

---

## 8. Legacy mirror retirement

Follow **`legacy_static_deprecation_playbook.md`** exit criteria in order:

1. **Reader retirement** in this repo (`bridge_posture.py`, `static_reconcile`, `v_run_overview` consumers, etc.).  
2. **Web grep** — no out-of-repo SQL depending on legacy five.  
3. **Export** legacy tables to cold storage.  
4. **DDL last** — drop or truncate only after `v_run_overview` is redefined or removed.

**When rows can be emptied:** only after (1)–(3) signed off; **never** as first move.

---

## 9. Migration approach — staged SQL / scripts

Under e.g. `sql/migrations/db_cleanup/` (exact tree TBD), stage artifacts:

| Stage | Contents | Destructive? |
| --- | --- | --- |
| `01_readonly_audit/` | SELECT packs, `information_schema` exports | No |
| `02_additive_schema/` | `CREATE TABLE static_analysis_sessions`, indexes | No |
| `03_backfill_sessions/` | `INSERT … SELECT` aggregates from runs — **honest** disposition only | No (writes data — run in maintenance window; still not DELETE) |
| `04_views_web/` | `CREATE OR REPLACE VIEW` for session catalog / narrowed app sessions | No |
| `05_prune_helpers/` | **Parameterized** `PREVIEW.sql` / `VERIFY.sql` only | No |
| `06_destructive_prune/` | `DELETE` / `ALTER` — **each file** must start with commented **PREVIEW** and end with **VERIFY** queries | **Yes** — last, CAB + backup |

**Rule:** every file under `06_*` includes:

```sql
-- PREVIEW: row counts / sample keys
-- … SELECT-only …
-- ACTION: (commented until approved)
-- VERIFY: expected zero rows / orphan checks
```

---

## 10. Recommended first implementation PR

**Goal:** operational visibility with **zero schema risk** and **zero destructive SQL**.

**Scope:**

1. Add **`docs/maintenance/database_schema_cleanup_design.md`** (this document).  
2. Add **`scripts/db/session_hygiene_report.py`** — read-only aggregation + disposition proposal + “cleanup candidate” hints.  
3. Add **`tests/scripts/test_session_hygiene_report.py`** (or under `tests/database/`) — unit tests with mocked `run_sql` / captured query shapes and classification edge cases (interrupt-only vs persist failure).  
4. Optional one-line cross-link from **`database_cleanup_audit_plan.md`** §11 to this doc.

**Explicitly out of first PR:** new base tables, view DDL changes, `ALTER`, `DELETE`, persistence writer edits, detector changes.

### Files to create / update

| Path | Action |
| --- | --- |
| `docs/maintenance/database_schema_cleanup_design.md` | **Create** (this file). |
| `docs/maintenance/documentation_authority_index.md` | **Update** — index under Database / maintenance. |
| `docs/maintenance/database_cleanup_audit_plan.md` | **Update** — short pointer to this design doc. |
| `scripts/db/session_hygiene_report.py` | **Create** — read-only report CLI. |
| `tests/database/test_session_hygiene_report.py` or `tests/scripts/…` | **Create** — mocked DB tests. |

**Second PR (additive schema):** `static_analysis_sessions` DDL in `canonical/schema.py` + `schema_manifest.py` + migration SQL under `02_additive` + backfill script under `03_` (still no DELETE).

### Tests needed

- `pytest tests/database/test_session_hygiene_report.py -q` (new).  
- `python -m py_compile scripts/db/session_hygiene_report.py`.  
- After any view PR: `pytest tests/database tests/db -q` + `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture`.

### SQL audit commands (read-only)

Reuse **`database_cleanup_audit_plan.md` Section 9** plus session slices:

- Session child counts union (already in audit plan Section 11.C pattern).  
- `SELECT session_stamp, scope_label, status, abort_reason, COUNT(*) FROM static_analysis_runs GROUP BY 1,2,3,4`.  
- `static_persistence_failures` joined to `sar.session_stamp`.

### Risk level

| PR | Risk |
| --- | --- |
| First PR (doc + read-only script + tests) | **Low** — no runtime DB contract change. |
| Second PR (additive `static_analysis_sessions` + backfill) | **Medium** — new table and writer coordination; mitigate with idempotent backfill and feature flag. |
| View narrowing / Web defaults | **Medium–High** — changes visible data in Web; requires Web smoke + consumer grep. |
| Collation / destructive prune | **High** — maintenance window + backups mandatory. |

---

## Revision log

| Date | Note |
| --- | --- |
| 2026-05-09 | Initial design proposal from operator evidence + repo DDL references. |
