# Operational database scripts (web read models)

These tools support **recovery**, **governance**, and **smoke verification** after the operational MariaDB/MySQL schema has drifted from the Python-defined DDL (`scytaledroid/Database/db_queries/`).

Full narrative for project leads: **`docs/maintenance/database_governance_runbook.md`**.

## One-shot operator doctor

From repo root (same env as static analysis), run:

```bash
chmod +x scripts/db/scytaledroid_doctor.sh   # once
./scripts/db/scytaledroid_doctor.sh
```

This executes: primary DB ping → view **posture** → **semantic** checks → `check_permission_intel.py` → optional Web DB smoke when `SCYTALEDROID_WEB_ROOT` points at your ScytaleDroid-Web checkout.

Skip flags (environment):

| Variable | Effect |
| --- | --- |
| `SCYTALEDROID_DOCTOR_QUICK=1` | Only Primary DB + Permission Intel (skips posture, semantic, web). |
| `SCYTALEDROID_DOCTOR_SKIP_POSTURE=1` | Skip posture step. |
| `SCYTALEDROID_DOCTOR_SKIP_SEMANTIC=1` | Skip semantic step. |
| `SCYTALEDROID_DOCTOR_SKIP_INTEL=1` | Skip Permission Intel doctor. |
| `SCYTALEDROID_DOCTOR_SKIP_WEB=1` | Skip Web smoke even if `SCYTALEDROID_WEB_ROOT` is set. |

## Environment

Python scripts use **`pymysql`** and expect:

| Variable | Purpose |
| --- | --- |
| `SCYTALEDROID_DB_HOST` | default `localhost` |
| `SCYTALEDROID_DB_PORT` | default `3306` |
| `SCYTALEDROID_DB_USER` | required |
| `SCYTALEDROID_DB_PASSWD` | optional in dev, empty string allowed (**canonical**; matches app `db_config.py`). |
| `SCYTALEDROID_DB_PASS` | **Legacy only:** some standalone `scripts/db/*.py` helpers accept this name for compatibility; **the main application reads `SCYTALEDROID_DB_PASSWD` only** (see `AGENTS.md`). Prefer `PASSWD` everywhere. |
| `SCYTALEDROID_DB_NAME` | required |

Run from repo root so imports resolve:

```bash
cd /path/to/ScytaleDroid
export SCYTALEDROID_DB_USER=… SCYTALEDROID_DB_NAME=… SCYTALEDROID_DB_PASSWD=…
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic
PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts
```

## Command sequence (operator runbook shorthand)

1. **Backup** the database (logical dump or snapshot).
2. **Posture**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py posture`  
   Optionally: `mariadb … < scripts/db/check_schema_posture.sql`
3. **Semantic smoke** (empty-dashboard detector): `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py semantic`
4. **Dry-run view order**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate --dry-run [--layer full|manifest|web]`
5. **Safe alters**: add nullable columns if missing (`--apply-safe-alters` on recreate).
6. **Drop stubs** only after review: any conflicting `BASE TABLE` whose name matches **`^v_.*` / `^vw_.*`** (`--drop-conflicting-tables --confirm`). Non-empty stubs need **`--allow-drop-nonempty-tables --confirm`**.
7. **Recreate views**: default **`full`** (bootstrap manifest chain + supplementary + web extensions). Narrow with **`--layer manifest`** (DDL from `ordered_schema_statements()` only) or **`--layer web`** (web-consumer extensions only):

   ```bash
   PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py recreate \
     --layer full \
     --apply-safe-alters --drop-conflicting-tables --confirm
   ```

8. **PHP smoke** (requires ScytaleDroid-Web):  
   `SCYTALEDROID_WEB_ROOT=/path/to/ScytaleDroid-Web ./scripts/db/smoke_web_db.sh`
9. **Counts**: `PYTHONPATH=. python scripts/db/recreate_web_consumer_views.py counts`
10. **Permission Intel** (dedicated `android_permission_intel` DB + paper-grade governance):  
   `PYTHONPATH=. python scripts/db/check_permission_intel.py`  
   Use **`SCYTALEDROID_PERMISSION_INTEL_DB_PASSWD`** (or `…_URL`), not `…_PASS` — see script header.

11. **S2-P1A readiness (read-only, optional):**  
   `PYTHONPATH=. python scripts/db/audit_permission_intel_queue_compatibility.py`  
   `PYTHONPATH=. python scripts/db/audit_static_permission_observation_linkage.py`  
   Or bundle: `./scripts/db/run_permission_intel_scytale_s2_readiness_audit.sh`  
   Narrative: `docs/database/permission_intel_scytaledroid_s2_p1a_operational_readiness.md`;
   contract summary: `docs/database/permission_intel_contract.md`.

## Dynamic root-domain normalization migration

Dynamic domain observations retain their existing heuristic aggregation `root_domain`
while a separate pinned-Public-Suffix-List registrant boundary and resolver
provenance are added. Review the exact observation-ID worklist before applying:

The distinction is intentional. RFC 8499 defines a public suffix in registry-control
terms, and the PSL PRIVATE section also models boundaries between mutually
untrusting tenants on privately operated platforms. Those boundaries are useful
for security analysis but are not interchangeable with this repository's
historical domain aggregation key. The migration therefore adds
`registrable_domain_psl` without rewriting `root_domain`. The bundled PSL version
and file SHA-256 are stored with each derived row; the PSL is not used as a DNS
validity oracle.

- DNS terminology: https://www.rfc-editor.org/rfc/rfc8499
- PSL purpose and limitations: https://publicsuffix.org/learn/
- PSL format and update guidance: https://publicsuffix.org/list/

```bash
PYTHONPATH=. python scripts/db/migrate_dynamic_domain_normalization.py --write-bundle
```

After a database backup and receipt review, apply the additive schema and the
bounded `(observation_id, dynamic_run_id)` updates:

```bash
PYTHONPATH=. python scripts/db/migrate_dynamic_domain_normalization.py \
  --apply --confirm --json
```

Apply mode always writes a preflight worklist and result receipt under
`data/state/schema_migrations/dynamic_domain_normalization/`. Schema DDL is
additive; observation updates run transactionally and roll back if exact-row
verification fails. The tool hashes the ordered worklist, locks and reloads the
target rows, and refuses to continue if the database changed after preflight.
It also stops on partial columns, a missing expected index, or disagreement
between the migration registry and physical schema. The tool never deletes
observations or evidence files.

## Cohort static session audit

After a profile/cohort static run, verify canonical row counts and Web/read views for one `session_stamp`:

```bash
PYTHONPATH=. python scripts/db/audit_static_session.py --session 20260502-rda-canonical-only
```

### Static pipeline grain / integrity (read-only)

Explains **package-level DB vs per-artifact JSON** and optional **artifact-stage pipeline_summary**
sums from archive JSON (not deduped). Complements ``audit_static_session.py`` (counts only).

**JSON path semantics:** persistence summaries count **paths recorded on outcomes**, usually under
``data/static_analysis/reports/latest/<sha>.json`` (hash-deduped). This script's ``--count-archive-json``
counts ``*.json`` under ``data/static_analysis/reports/archive/<session_stamp>/`` (session tree when
archive/both mode writes there). Those totals are **not** expected to match.

Optional ``--with-display-labels`` adds a human-facing column: CSV override (default reference file)
then ``apps.display_name`` (does not load static report JSON).

```bash
PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py --session-stamp 20260510-all-full
PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py --session-stamp 20260510-all-full \
  --count-archive-json --aggregate-json-summaries --json
PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py --session-stamp 20260510-all-full \
  --count-archive-json --with-display-labels
```

## Static session header refresh (aggregates + disposition)

After bulk repairs or if you need to recompute ``static_analysis_sessions`` counters from
child tables (without touching ``web_visibility_default`` / ``cleanup_status`` /
``superseded_by_session_id``):

```bash
PYTHONPATH=. python scripts/db/refresh_static_analysis_sessions.py --all
PYTHONPATH=. python scripts/db/refresh_static_analysis_sessions.py \
  --session-stamp '20260510-all-full-145' --scope-label ''
```

Normal static runs also trigger a **best-effort** refresh at run finalization and after
successful ``static_session_run_links`` writes (see ``static_session_summary.py``).

Canonical writers only (empty historical legacy-table rows are **not** treated as failure):

```bash
PYTHONPATH=. python scripts/db/audit_static_session.py --session 20260502-rda-canonical-only
```

## Evidence hash posture

Finding evidence externalization uses a compact query row plus a SHA-256 keyed
payload table:

- `static_analysis_findings.evidence_hash`
- `static_finding_evidence_payloads.evidence_hash`

New canonical DDL defines both as:

```sql
CHAR(64) CHARACTER SET ascii COLLATE ascii_bin
```

Existing development databases may still have older collations such as
`utf8mb4_general_ci` or `latin1_swedish_ci`. Check before disabling inline
finding evidence:

```bash
PYTHONPATH=. python scripts/db/check_evidence_storage_posture.py
PYTHONPATH=. python scripts/db/check_evidence_latest_write_posture.py --since-hours 168
```

If `evidence_hash_collation_ok=0`, use a reviewed safe-alter path during a
maintenance window. Back up first, verify no hash values exceed 64 hex
characters, then alter only the two hash columns:

```bash
PYTHONPATH=. python scripts/db/normalize_evidence_hash_collation.py
PYTHONPATH=. python scripts/db/normalize_evidence_hash_collation.py --apply
```

The helper is dry-run by default, validates existing hashes as 64-character hex
strings, and uses the direct narrow `MODIFY` path. On MariaDB/InnoDB this works
with the existing payload primary key and findings secondary index; the table is
rebuilt as needed by the server. The equivalent reviewed SQL is:

```sql
ALTER TABLE static_finding_evidence_payloads
  MODIFY evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;

ALTER TABLE static_analysis_findings
  MODIFY evidence_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL;
```

Then rerun storage posture, latest-write posture, and hash parity before
changing `SCYTALEDROID_FINDINGS_EVIDENCE_INLINE` or stripping inline evidence.

Manual indexes added during live diagnosis must be represented in canonical
schema/bootstrap before they are treated as durable. The dynamic/static exact
hash path currently expects `ix_dynamic_sessions_base_apk_sha256` and the
`static_analysis_runs` composite contract index
`ix_static_runs_base_hash_contract (base_apk_sha256, status, run_class,
identity_valid)`. A separate single-column `static_analysis_runs(base_apk_sha256)`
index is intentionally omitted because the composite index has `base_apk_sha256`
as its leftmost column and covers exact-hash probes.

Do not strip inline finding evidence until all of the following are true:

- a fresh static run succeeds on the current writer path;
- latest-write posture is clean;
- evidence hash collation is fixed;
- `v_web_app_findings` resolves payload fallback.

## Files

| File | Role |
| --- | --- |
| `check_schema_posture.sql` | Read-only SQL checks (portable to any SQL client). |
| `recreate_web_consumer_views.py` | Posture / semantic smoke / counts; guarded **`recreate`** (`--layer` full, manifest, or web). |
| `view_repair_support.py` | Helpers; ordered DDL for full vs manifest vs web-only sequences (scripts package). |
| `check_permission_intel.py` | Env/connectivity + governance row counts for **`SCYTALEDROID_PERMISSION_INTEL_DB_*`**. |
| `normalize_evidence_hash_collation.py` | Dry-run default migration helper for the two finding evidence hash columns (`--apply` writes). |
| `audit_permission_intel_queue_compatibility.py` | Read-only PI queue report (`aosp` vs legacy `aosp_promote`, Scytale rows, apply-outcome dry check). |
| `audit_static_permission_observation_linkage.py` | Read-only core DB: matrix → run SHA-256 / versions / `apk_id`. |
| `run_permission_intel_scytale_s2_readiness_audit.sh` | Bundles intel check + audits + targeted pytest (best-effort if DB unset). |
| `audit_static_session.py` | Cohort audit: canonical tables + `v_web_*` + handoff + legacy-table counts (informational); prints copyable SQL. |
| `report_static_session_grain_integrity.py` | Read-only grain map: SAR counts + optional archive JSON pipeline rollups vs DB findings (split-heavy triage). |
| `report_apk_lineage_availability.py` | Read-only package/version/hash/install-set lineage, byte availability, static coverage, dynamic coverage, and design checks. |
| `report_package_lineage_workbench.py` | Read-only package-first operator workbench for identity, bytes, static/dynamic coverage, gaps, and recommended actions. |
| `report_static_analysis_targets.py` | Read-only queue-like static target model derived from package/hash lineage, including block reasons. |
| `report_dynamic_static_alignment.py` | Read-only exact dynamic/static hash alignment and worklist; optional exact-target readiness output. |
| `report_dynamic_static_recovery_plan.py` | Read-only exact-gap artifact recovery planner; default old-root posture is historical identity only; `--write-report` emits CSV/JSON worklists, and `--write-receipt` writes a non-destructive JSON recovery receipt. |
| `report_dynamic_static_pairing_eligibility.py` | Read-only dynamic-session dataset eligibility report for strict paired analysis, historical identity only, reharvest, and current-byte states; `--write-report` emits CSV/JSON session and package worklists. |
| `report_dynamic_domain_context.py` | Filesystem-first, DB-optional dynamic domain-context report. Retains legacy `root_domain`, adds a pinned-PSL candidate and drift counts, and never rewrites historical evidence. |
| `repair_dynamic_dataset_validity_from_db_issues.py` | Dry-run default DB-only repair for legacy dynamic rows whose latest `dynamic_session_issues.dataset_validity` payload already proves `valid_dataset_run=true`; `--apply` fills bounded `dynamic_sessions` columns by run ID only. |
| `report_current_corpus_preflight.py` | Read-only current-corpus preflight after fresh inventory/harvest: repository rows, canonical store files, apk_sets, split metadata, and static target states. |
| `refresh_external_sdk_tracker_intel.py` | Dry-run default refresh of repo-owned external tracker/SDK reference intel from the Exodus public API; receipt bundles include source/normalized hashes and ODbL/DbCL attribution. `--input-receipt` replays a hash-verified frozen snapshot without network access; `--apply` upserts additive rows. |
| `report_external_tracker_context.py` | Read-only overlap audit between external tracker intel and selected static endpoint root domains; separates specific overlaps from generic-root/infrastructure-root overlap. |
| `backfill_apk_sets_from_receipts.py` | Dry-run default install-set spine backfill from receipt-backed harvest artifacts; `--apply` writes additive rows. |
| `backfill_apk_set_links.py` | Dry-run default `apk_set_id` link backfill for static/dynamic rows with unique artifact-set matches; `--apply` writes nullable links only and a timestamped receipt by default (`--receipt-dir` for explicit dry-run/apply receipts). |
| `smoke_web_db.sh` | Wraps **`ScytaleDroid-Web/scripts/sd_web_db_smoke.php`** (PDO read smoke). |

## Naming contract

**Do not create physical tables whose names start with `v_` or `vw_`** in the operational analytics DB. Those prefixes are reserved for **SQL VIEW** definitions that layer over canonical tables (`static_analysis_*`, `apps`, `dynamic_*`, etc.), including non-Web reporting views (`v_run_overview`, `v_static_handoff_v1`, artifact registry views, cohort views, etc.).
