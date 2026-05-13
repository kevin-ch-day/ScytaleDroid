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
| `report_evidence_storage_posture.py` | G | Read-only sizes / dedupe signals (flags, findings, audit) | yes | core | yes | no | operator triage |
| `probe_finding_evidence_hash_parity.py` | G | Sample SQL vs Python ``evidence_hash`` / mismatch hints | yes | core | yes | no | operator triage before strip-inline |
| `backfill_static_finding_evidence_payloads.py` | M | Backfill ``evidence_hash`` + payload table; optional strip inline | default read; **writes** with ``--apply`` | core | yes | no | operator / maintenance |
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
| `backfill_static_session_id_on_runs.py` | M | Backfill `static_session_id` on runs | **writes** | core | yes | no | one-time / maintenance |

> Note: `scripts/db/__init__.py` is package metadata only (class **C**).

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

## Reducing sprawl (later; no deletions in this pass)

Candidates to **archive** after menu/CLI parity (do not move yet):

- One-off backfills once production has caught up (`backfill_static_session_id_on_runs.py`).
- Duplicate Intel checks if fully subsumed by `permission_intel_readiness` module + menu.

Candidates to **keep as scripts** even when menu-wrapped:

- Long-running or DDL scripts (`recreate_web_consumer_views.py`) where operators want log files and explicit argv.

## Policy reminders

- **Never** auto-apply `apply_app_display_name_overrides.py` during static scan.
- **Never** bulk-copy `device_inventory.app_label` into `apps.display_name` as a silent catalog fix (per product decision).
