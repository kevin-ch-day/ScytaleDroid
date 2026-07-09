# `scripts/db/*.py` inventory and integration map

See also **[`scripts_integration_strategy.md`](scripts_integration_strategy.md)** for the broader `scripts/` tree (subtrees, removal candidates, suggested integration order).

Operational scripts under `scripts/db/` are **implementation helpers**. This document classifies each script, states read/write posture, and records the **intended workflow owner** so menus and static pre/post-flight can call or reference them without ad-hoc memory.

Legend:

| Class | Meaning |
| --- | --- |
| **A** | Active operator command (CLI or menu should surface) |
| **S** | Static workflow helper (session/schema/static cohort) |
| **G** | Governance / readiness / Permission Intel |
| **M** | One-time migration / backfill (run deliberately; not routine) |
| **L** | Legacy / superseded by menu modules (keep until callers migrated) |
| **C** | CI / test-only or library (not a standalone operator entry) |

## Refinement status fields

When touching a `scripts/db` helper, keep the row below current and preserve these
working decisions:

| Status | Meaning |
| --- | --- |
| `keep` | Stable path; do not rename or remove. |
| `combine_later` | Keep path, but move reusable logic into an app module or future grouped command. |
| `move_later` | Candidate for package/module relocation after caller parity. |
| `archive_later` | One-time or historical helper; only move after docs/tests/external-use check. |
| `delete_later` | Superseded and safe to remove only after a dedicated removal review. |

The current cleanup rule is **inventory first, no deletes or renames yet**.
Operators still use the existing script paths. Generated caches such as
`__pycache__/` are safe to remove; tracked script movement needs a replacement
path and reference update.

| Script | Class | Purpose (short) | Read-only? | DB? | `--help` | Auto-call? | Menu / owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `check_permission_intel.py` | G | Validate Intel env, connectivity, governance snapshot rows | yes | Intel DSN | yes | optional CI | `run.sh` / gates; DB Tools → 2 (readiness is item 2) |
| `permission_intel_readiness.py` | G | Thin CLI wrapper around `permission_intel_readiness` module | yes | Intel | yes | optional | DB Tools → 2 (item 2) |
| `recreate_web_consumer_views.py` | A / G | Recreate Web consumer **views** (DDL on views) | **writes** DDL | core | yes | posture/semantic workflows | DB maintenance; AGENTS smoke |
| `view_repair_support.py` | C | Shared helpers for view repair scripts (imported) | n/a | n/a | n/a | no | `recreate_web_consumer_views` |
| `static_schema_audit.py` | S | Read-only static-related schema inventory | yes | core | yes | CI / doctor | DB Tools / gates |
| `session_static_health.py` | S | Read-only static session health probe | yes | core | yes | post-run diagnostics menu | **DB Tools → 9 (item 6)**; static post-run → 11 |
| `audit_static_session.py` | S | Cohort/session audit: counts + Web views + legacy | yes | core (+views) | yes | propose post-run | Static audit; `audit_static_session` |
| `refresh_static_analysis_sessions.py` | S | Recompute `static_analysis_sessions` rollups | **writes** | core | yes | propose post-run job | DB maintenance |
| `report_static_session_grain_integrity.py` | S | Grain / `static_session_id` integrity report | yes | core | yes | optional | **DB Tools → 9 (item 7)** |
| `verify_static_session_id_rollout.py` | S | Scalar counts for session-id rollout | yes | core | yes (`--explain` = stderr legend) | optional | **DB Tools → 9 (item 5)**; post-run → 11 |
| `check_evidence_storage_posture.py` | G | Snapshot metadata vs pointers; findings hash↔payload | yes | core | yes | optional CI / doctor | scripts/db; DB maintenance |
| `check_evidence_latest_write_posture.py` | G | Recent-window findings: hash↔payload, inline vs env, web-shaped evidence | yes | core | yes | after fresh static run | operator / DB maintenance |
| `report_dynamic_static_alignment.py` | G | Dynamic sessions vs canonical static hash alignment + static worklist | yes | core | yes | no | operator triage; dynamic↔static research |
| `report_apk_lineage_availability.py` | A / G | Package/version/hash/install-set lineage coverage and byte availability | yes | core | yes | no | APK lineage / package coverage |
| `report_package_lineage_workbench.py` | A | Package-first operator workbench: identity, bytes, static/dynamic coverage, actions | yes | core | yes | no | APK Library → Package Lineage Workbench |
| `report_static_analysis_targets.py` | A / G | Queue-like read model for hash-driven static targets and block reasons | yes | core | yes | no | APK Library / Static target planning |
| `report_dynamic_static_recovery_plan.py` | A / G | Exact dynamic/static gap artifact recovery planner; optional JSON receipt | default read; writes receipt with `--write-receipt` | core | yes | no | APK Library / artifact lifecycle planning |
| `report_dynamic_static_pairing_eligibility.py` | A / G | Read-only dynamic-session eligibility for strict paired analysis vs dynamic-only/reharvest/external-artifact states | yes | core | yes | no | Dataset analysis planning |
| `report_current_corpus_preflight.py` | A / G | Read-only current-corpus preflight after fresh inventory/harvest: repository rows, canonical store files, apk_sets, split metadata, and static target states | yes | core | yes | no | Current corpus rebuild / harvest preflight |
| `report_dynamic_paper_freeze_readiness.py` | A | Read-only dynamic cutoff evidence tier and paper-readiness report | yes | core/evidence | yes | no | Paper 3 cutoff evidence source |
| `report_paper3_writing_package.py` | A | Generate Paper 3 writing bridge/workspace from cutoff evidence | yes | file outputs only | yes | no | Paper 3 writing workspace |
| `report_dynamic_live_operational_state.py` | G | Read-only live queue/current-build operational state snapshot | yes | core/evidence | yes | no | Dynamic operational vs paper-readiness split |
| `report_dynamic_retained_evidence_reuse.py` | G | Read-only retained/prior-build evidence reuse report | yes | evidence | yes | no | Paper cutoff caveats / retained evidence |
| `report_evidence_storage_posture.py` | G | Read-only sizes / dedupe signals (flags, findings, audit) | yes | core | yes | no | operator triage |
| `probe_finding_evidence_hash_parity.py` | G | Sample SQL vs Python ``evidence_hash`` / mismatch hints | yes | core | yes | no | operator triage before strip-inline |
| `backfill_static_finding_evidence_payloads.py` | M | Backfill ``evidence_hash`` + payload table; optional strip inline | default read; **writes** with ``--apply`` | core | yes | no | operator / maintenance |
| `normalize_evidence_hash_collation.py` | M | Narrow safe ALTER helper for finding evidence hash ``ascii_bin`` collation | default read; **writes** with ``--apply`` | core | yes | no | evidence migration maintenance |
| `backfill_apk_sets_from_receipts.py` | M | Additive install-set spine backfill from receipt-backed harvest artifacts | default read; **writes** with `--apply` | core | yes | no | APK lineage migration helper |
| `backfill_apk_set_links.py` | M | Backfill nullable `apk_set_id` links where artifact-set hash is unique | default read; **writes** with `--apply` | core | yes | no | APK lineage migration helper |
| `check_static_run_governance_posture.py` | G | Static run canonical / handoff invariant counts | yes | core | yes | optional CI / doctor | **DB Tools → 9 (item 2)**; shared module `static_run_governance_checks`; gates |
| `report_artifact_registry_integrity.py` | S | Artifact registry integrity (dangling refs) | yes | core | yes | propose post-run | **DB Tools → 9 (item 3)** |
| `report_artifact_registry_cleanup_candidates.py` | S | Read-only cleanup policy buckets for `artifact_registry` | yes | core | yes | no | **DB Tools → 9 (item 4)**; post-run → 11 |
| `prune_artifact_registry_dangling.py` | A | Age-gated dangling registry prune (receipt JSON v1 envelope + CSV/SQL; receipt + `--apply`; DB only) | default dry-run; **writes** with `--apply` | core | yes | never auto | operator / maintenance |
| `verify_evidence_manifest.py` | S | Filesystem + optional DB evidence manifest parity | mixed | optional | yes | deploy | evidence checks |
| `validate_canonical_masvs_session.py` | S | MASVS views vs session stamp | yes | core | yes | CI / research | static gates |
| `audit_static_permission_observation_linkage.py` | S | Matrix → run → SHA linkage audit | yes | core | yes | CI | persistence QA |
| `audit_permission_intel_queue_compatibility.py` | G | Intel queue compatibility (Scytale vs Erebus) | yes | Intel + core | yes | occasional | governance |
| `audit_permission_name_casing.py` | G | Permission string casing audit | yes | core + Intel | yes | occasional | governance |
| `report_app_label_hygiene.py` | A | Catalog: inventory vs `apps.display_name` / focus bucket | yes | core | yes | **preflight summary (counts only)** | **DB Tools → Catalog hygiene → 1** |
| `apply_app_display_name_overrides.py` | A | Curated CSV → `apps.display_name` (dry-run default) | default read; `--apply` writes | core | yes | never auto | **Catalog hygiene → 2–3** |
> Note: `scripts/db/__init__.py` is package metadata only (class **C**).

## Consolidation candidates

These are planning notes only; keep old paths stable until wrappers, docs, and
menus have parity.

| Family | Current scripts | Future grouped surface | Recommended status | Notes |
| --- | --- | --- | --- | --- |
| evidence-storage | `check_evidence_storage_posture.py`, `check_evidence_latest_write_posture.py`, `report_evidence_storage_posture.py`, `probe_finding_evidence_hash_parity.py`, `backfill_static_finding_evidence_payloads.py`, `normalize_evidence_hash_collation.py` | `evidence_storage.py check/latest/report/probe/backfill/normalize-collation` or app module wrappers | combine_later | Keep inline evidence enabled until fresh-write proof and `evidence_hash` collation posture are clean. |
| package-lineage / exact recovery | `report_apk_lineage_availability.py`, `report_package_lineage_workbench.py`, `report_static_analysis_targets.py`, `report_dynamic_static_alignment.py`, `report_dynamic_static_recovery_plan.py`, `report_dynamic_static_pairing_eligibility.py` | `scytaledroid/Database/db_scripts/package_lineage_read_model.py` plus optional grouped CLI `package_lineage.py coverage/workbench/targets/alignment/recovery-plan/pairing-eligibility` | combine_later | Highest-overlap family. Keep existing script names stable while shared SQL, availability, coverage, and action classification move into one module. |
| dynamic-static | `report_dynamic_static_alignment.py` | package-lineage grouped surface or Dynamic/DB menu in-process report | keep/combine_later | Report is read-only and correctly avoids package-name repair; exact-target readiness should reuse the lineage availability classifier. |
| static-session | `audit_static_session.py`, `session_static_health.py`, `report_static_session_grain_integrity.py`, `refresh_static_analysis_sessions.py`, `verify_static_session_id_rollout.py`, `check_static_run_governance_posture.py` | `static_sessions.py health/grain/refresh/verify/governance` | combine_later | Preserve write boundaries: refresh remains explicit. |
| artifact-registry | `report_artifact_registry_integrity.py`, `report_artifact_registry_cleanup_candidates.py`, `prune_artifact_registry_dangling.py` | `artifact_registry.py integrity/cleanup-candidates/prune` | combine_later | Prune remains dry-run by default with receipt + `--apply`. |
| permission-intel | `check_permission_intel.py`, `permission_intel_readiness.py`, `audit_permission_intel_queue_compatibility.py`, `audit_permission_name_casing.py`, `run_permission_intel_scytale_s2_readiness_audit.sh` | `permission_intel.py readiness/queue/casing` | keep/combine_later | Separate Intel DB target; do not mix with core static results. |
| schema-view-maintenance | `recreate_web_consumer_views.py`, `view_repair_support.py`, `check_schema_posture.sql`, `smoke_web_db.sh` | keep explicit scripts | keep | DDL and Web smoke should stay deliberate operator actions. |
| catalog-hygiene | `report_app_label_hygiene.py`, `apply_app_display_name_overrides.py` | catalog menu + package module | keep/combine_later | Never auto-apply display name overrides during static scan. |
| apk-set migration | `backfill_apk_sets_from_receipts.py`, `backfill_apk_set_links.py` | archive folder after install-set spine is populated and new writers are stable | archive_later | Keep dry-run default and `--apply` explicit. Do not infer exact split membership from package-level `apk_split_groups`. |
| Paper 3 cutoff/writing | `report_dynamic_paper_freeze_readiness.py`, `report_dynamic_live_operational_state.py`, `report_dynamic_retained_evidence_reuse.py`, `report_paper3_writing_package.py` | keep explicit scripts until rough-draft process is complete | keep | These scripts encode the current-build churn vs cutoff-evidence policy. Do not archive during Paper 3 drafting. |

## Package lineage / recovery overlap

The current package lineage work is intentionally additive, but the scripts now
share enough concepts that the next code cleanup should target a shared
read-model module before adding more reports.

| Script | Current role | Consolidation note |
| --- | --- | --- |
| `report_apk_lineage_availability.py` | Broad package/version/hash/install-set coverage and design checks. | Best current source for package-level aggregate semantics. |
| `report_package_lineage_workbench.py` | Operator drilldown for one package, including action and availability summaries. | Should reuse the same row builder and action classifier as coverage/targets. |
| `report_static_analysis_targets.py` | Queue-like read model derived from lineage rows. | Should become a view over shared lineage rows plus target priority/status rules. |
| `report_dynamic_static_alignment.py` | Exact dynamic/static gap source and exact-target readiness. | Should source byte/split readiness from shared lineage availability helpers. |
| `report_dynamic_static_recovery_plan.py` | Artifact lifecycle plan for exact dynamic/static gaps, with optional non-destructive receipt. | Should reuse shared path/root/canonical-store classifiers; keep receipt writing explicit. |
| `report_dynamic_static_pairing_eligibility.py` | Dataset eligibility view for dynamic sessions: strict paired, link-preview candidate, reharvest, external-artifact required, or dynamic-only. | Should remain read-only; never update `dynamic_sessions.static_run_id`. |

Current shared module seed: `scytaledroid/Database/db_scripts/package_lineage_read_model.py`.
Continue moving script-private helpers into it when touching this family.

Recommended shared module boundary:

- Fetch package/version/hash/install-set identity rows.
- Compute byte availability from recorded path and canonical SHA store.
- Compute static coverage by exact base hash and, when present, `apk_set_id`.
- Compute dynamic coverage and exact-pairing gaps.
- Classify action states: `already_covered`, `analyze_exact_static`,
  `restore_artifacts`, `reharvest_required`, `dynamic_link_preview_available`,
  `dynamic_identity_mismatch_review`, and unrecoverable/archive-required states.
- Render-independent data objects for scripts and menus.

Do **not** delete or rename current script paths in the extraction pass. First
make wrappers call shared code, then update menus/tests/docs, then archive only
after path references are gone.

## Integration roadmap (not all implemented in the first wiring PR)

### Static run preflight (implemented incrementally)

| Topic | Status | Notes |
| --- | --- | --- |
| Permission Intel readiness | already in `static_run_preflight` via `intel_gate` | keep |
| Session / schema readiness | partial (`schema_gate`, persistence lines) | extend as needed |
| Output path readiness | already in preflight | keep |
| Harvest / inventory alignment | not in static preflight yet | Device / harvest menus own truth; future link to snapshot freshness |
| **App display-name hygiene (selected packages)** | **first wiring: one-line summary** | uses `apps` only; **no** CSV apply; **no** `device_inventory` copy |
| Session stale lock | partial elsewhere (`_emit_db_preflight_lock_warning`) | consolidate later |
| APK artifact / report output readiness | partial in scan launch | deepen later |

### Static post-run audit (proposal)

Single “audit card” or optional prompt should summarize (read-only where possible):

- `refresh_static_analysis_sessions` (currently a **write** — should remain operator-triggered or explicit post-run flag)
- session health (`session_static_health` via **static post-run diagnostics → 11** and **DB Tools → 9 item 6**)
- run completion matrix (completed / failed / interrupted)
- APK reports saved vs expected (from run outcome / rollups)
- persistence failures (existing persistence diagnostics)
- `static_session_id` verification (`report_static_session_grain_integrity` / `verify_static_session_id_rollout`)
- static run governance invariants (`check_static_run_governance_posture.py`)
- dynamic orphan check (existing dynamic DB utilities — route separately)
- artifact registry dangling (`report_artifact_registry_integrity`)
- artifact registry cleanup candidates / policy buckets (`report_artifact_registry_cleanup_candidates`)
- **app display-name unresolved count** (same counter as preflight delta)

### Database Tools menu (implemented baseline)

See `database_menu.py`: **option 8 — Catalog hygiene**; **option 9 — Static & registry diagnostics** (ledger: run-class / handoff invariants, governance subprocess, artifact registry integrity, cleanup candidates, `verify_static_session_id_rollout`; session: `session_static_health`, grain integrity, canonical audit). **option 1 — Database health & integrity** rolls up DB-wide summary, latest-session depth checks, and evidence linkage. **option 2 — Permission Intel & snapshot governance** covers Intel DSN snapshot status and readiness.

### Deploy / readiness

Continue to use `AGENTS.md` smoke paths (`check_permission_intel`, `recreate_web_consumer_views`, `smoke_web_db.sh`). This inventory links scripts to those workflows.

## Reducing Sprawl

Candidates to **archive** after menu/CLI parity (do not move yet):

- Duplicate Intel checks if fully subsumed by `permission_intel_readiness` module + menu.
- One-time `backfill_*`, `normalize_*`, `phase_b1_*`, and `schema_version_width_hotfix.py` helpers after DB/schema rollout receipts are no longer needed for active repair.

Removed from the active `scripts/db` tree:

- `backfill_static_session_id_on_runs.py`
- `scripts/db/sql/backfill_static_analysis_runs_static_session_id.sql`
- `report_dynamic_draft_package.py`
- `tests/database/test_report_dynamic_draft_package.py`

The static-session rollout helpers were replaced by the maintained
`refresh_static_analysis_sessions.py` and `verify_static_session_id_rollout.py`
paths. The older dynamic draft exporter was replaced by
`report_dynamic_paper_freeze_readiness.py` plus `report_paper3_writing_package.py`.

Candidates to **keep as scripts** even when menu-wrapped:

- Long-running or DDL scripts (`recreate_web_consumer_views.py`) where operators want log files and explicit argv.

## Policy reminders

- **Never** auto-apply `apply_app_display_name_overrides.py` during static scan.
- **Never** bulk-copy `device_inventory.app_label` into `apps.display_name` as a silent catalog fix (per product decision).
