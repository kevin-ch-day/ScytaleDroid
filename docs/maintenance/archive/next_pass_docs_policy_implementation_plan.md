# Next pass — docs / policy implementation plan (controlled slice)

**Archived:** moved from `docs/maintenance/next_pass_docs_policy_implementation_plan.md` (documentation Wave W1).  
**Date:** 2026-05-09  
**Scope:** documentation and policy alignment only — **no** application logic, schema, Web repo, `metrics` migration, `risk_actions`, `views_bridge`, or reset changes in this slice.

---

## Deliverables completed in this slice

| # | Deliverable | Artifact |
| --- | --- | --- |
| 1 | Session identity contract | `docs/maintenance/session_identity_contract.md` |
| 2 | Risk scoring policy wording | Updates to `docs/database/static_schema_table_inventory.md`, `docs/persistence.md`, `docs/maintenance/permission_intelligence_pipeline.md`, `docs/maintenance/operator_acceptance_matrix.md` |
| 3 | `session_static_health.py` hygiene **plan** (no script logic) | `docs/maintenance/session_static_health_hygiene_plan.md` |
| 4 | Evidence manifest **design** (no writer) | `docs/maintenance/evidence_run_manifest_spec.md` |
| 5 | PI / Erebus boundary memo | `docs/maintenance/pi_erebus_operational_boundary.md` |

---

## Proposed files created or changed

| Path | Action | Docs-only vs behavior |
| --- | --- | --- |
| `docs/maintenance/session_identity_contract.md` | **Create** | Docs-only |
| `docs/maintenance/session_static_health_hygiene_plan.md` | **Create** | Docs-only |
| `docs/maintenance/evidence_run_manifest_spec.md` | **Create** | Docs-only |
| `docs/maintenance/pi_erebus_operational_boundary.md` | **Create** | Docs-only |
| `docs/maintenance/archive/next_pass_docs_policy_implementation_plan.md` | **Archive** (this file) | Docs-only |
| `docs/maintenance/documentation_authority_index.md` | **Update** (index entries) | Docs-only |
| `docs/database/static_schema_table_inventory.md` | **Update** (risk surfaces) | Docs-only |
| `docs/persistence.md` | **Update** (risk rollup paragraph) | Docs-only |
| `docs/maintenance/permission_intelligence_pipeline.md` | **Update** (`risk_scores` vs gate) | Docs-only |
| `docs/maintenance/operator_acceptance_matrix.md` | **Update** (clarify `risk_scores` vs `static_schema_gate`) | Docs-only |
| `docs/database/permission_intel_schema_drift_erebus_vs_scytaledroid.md` | **Update** (pointer to boundary memo §0) | Docs-only |

**No** `scytaledroid/**/*.py` edits in this slice (including `session_static_health.py` — hygiene is **planned** only).

---

## Test / verification commands

Docs-only slice — no pytest delta required. Optional hygiene:

```bash
python -m py_compile scripts/db/session_static_health.py scripts/db/audit_static_session.py  # sanity if touched later
```

Manual: open new docs from repo root and verify internal links resolve.

---

## Where prior docs disagreed with this policy (resolved in prose)

| Topic | Prior drift | Resolution in this slice |
| --- | --- | --- |
| **`risk_scores` vs gate** | Operator matrix listed `risk_scores` beside canonical ledger tables without stating it is **not** in `schema_gate.static_schema_gate()`. | Clarified: rollup / deployment completeness signal; **not** the same contract as static schema gate. |
| **Child-table session filters** | Historical bug pattern (`WHERE session_label` on `static_analysis_findings`). | **Forbidden** pattern spelled in `session_identity_contract.md`. |
| **PI vs Erebus** | Drift doc focuses on DDL; ownership of **obs_sample / apply** scattered. | **`pi_erebus_operational_boundary.md`** states ownership and blockers. |
| **`session_static_health` legacy errors** | Exception text prints as `ERROR:` while exit 0. | Hygiene plan: SKIP/INFO + optional gating like `audit_static_session`. |

**Note:** `scytaledroid/Database/db_utils/action_groups/status_actions.py` still lists `risk_scores` in `DB_SNAPSHOT_REQUIRED_STATIC_TABLES` for **DB schema snapshot** completeness — that is **intentional** and **not** the same as `static_schema_gate()`; see comments in code (authoritative) and inventory doc (operator).

---

## Follow-up implementation queue (not this slice)

1. Implement `session_static_health.py` gating + wording per hygiene plan + tests.
2. Implement `evidence_manifest.json` writer + consumer hooks (separate design review).
3. Optional `--session-label` for `session_static_health.py` if operators request dual probe.
