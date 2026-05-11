# Evidence run manifest (design spec)

**Status:** **Phase 1 (session) writer implemented** — `scytaledroid/StaticAnalysis/cli/persistence/evidence_manifest_writer.py` emits `data/sessions/<session_stamp>/evidence_manifest.json` after successful `run_map.json` finalization (best-effort; **never** fails the static run; disable with `SCYTALEDROID_EVIDENCE_MANIFEST=0`). Field evolution remains governed by this spec.  
**Purpose:** minimum **machine-readable** bundle so a static run can be **defended, replayed, or audited** without grep-driven reconstruction across `output/`, `data/`, and the DB.

---

## 1. Placement

- **Implemented (Phase 1):** session-level **`evidence_manifest.json`** next to **`run_map.json`** under `data/sessions/<session_stamp>/` (same tree as `static_run_map` / session linkage).
- **Future (optional):** per-run-root manifest under `evidence/static_runs/<id>/`, **or** `output/audit/evidence/<session_stamp>/manifest.json` for aggregation-only layouts — pick one product-wide if extended; v1 should not mix both without a `manifest_location` / scope field consumers understand.
- **Version field:** `manifest_schema_version` (semver or integer) for forward evolution.

---

## 2. Required fields (minimum contract)

| Field | Type | Notes |
| --- | --- | --- |
| `manifest_schema_version` | string or int | Consumer selects parser. |
| `static_run_id` | int | `static_analysis_runs.id` for the defended run (or array if session-level manifest lists many runs). |
| `session_stamp` | string | As persisted on SAR. |
| `session_label` | string | As persisted on SAR (may equal `session_stamp`). |
| `db_catalog` | string | Analyst database name (not secrets). |
| `schema_version` | string or object | From `schema_version` table or diagnostic snapshot at run time. |
| `git_commit` / `build_id` | string | `git_commit` from `get_git_commit()`. Optional `build_id` from `SCYTALEDROID_BUILD_ID`, `GITHUB_SHA`, or `CI_COMMIT_SHA` (first non-empty wins; truncated for safety). |
| `environment_fingerprint` | object | **No secrets:** Python version, OS, relevant env **flags** only (e.g. paper-grade on/off), not `SCYTALEDROID_DB_PASSWD`. |
| `canonical_artifacts` | array | Ordered list of `{ "path": "…", "sha256": "…", "role": "detector_report" \| "handoff_json" \| "run_map" \| … }`. |
| `handoff` | object | `{ "json_path": "…", "sha256": "…" }` mirroring SAR `static_handoff_json_path` / `static_handoff_hash` when present. |
| `detector_report` | object | Primary persisted JSON report path + sha256 (archive and/or latest if both material). |

**Canonical join rule reminder:** artifact paths are filesystem truth; **`static_run_id`** + hashes must match SAR columns for DB-backed replay.

---

## 3. Supporting vs optional

| Tier | Contents |
| --- | --- |
| **Supporting logs** | Transaction / persistence logs, `static_persistence_failures` references, lock health snapshots — **not** sufficient alone for scientific replay without DB + reports. |
| **Optional diagnostics** | DB verification footer text, legacy mirror counts, reconcile JSON — operator value only. |

---

## 4. Non-goals (this spec)

- **No** schema/DDL changes.
- **No** mandatory Web repo fields.
- **No** deletion of existing artifacts; manifest **adds** discoverability.

---

## 5. Consumer / verification

- **Operator CLI:** ``PYTHONPATH=. python scripts/db/verify_evidence_manifest.py --session <session_stamp>`` — validates JSON shape, on-disk paths, and sha256 fields in ``canonical_artifacts`` / nested handoff + detector rows. Add ``--db`` to compare handoff JSON file hashes to ``static_analysis_runs.static_handoff_hash`` (requires analyst DSN).
- **Programmatic:** ``scytaledroid.StaticAnalysis.cli.persistence.evidence_manifest_verify`` exposes ``verify_evidence_manifest_payload`` and ``verify_manifest_handoff_hash_vs_database`` for tests and automation.
- Dynamic plan loader / paper eligibility: **optional** cross-check manifest sha256 vs SAR (extend verify module when contracts tighten).
- Publication / cohort tooling: cite manifest as evidence index in human-readable reports.

---

## 6. Phase 1 failure modes (policy)

These answers gate **Phase 1** (“best-effort manifest writer, does not fail the run”) vs later paper-grade enforcement.

| Question | Phase 1 policy |
| --- | --- |
| **When should manifest generation run?** | **After** static persistence commits successfully for the run (or at end of `session_finalizer` / `persist_run_summary` success path), **asynchronously or last-step** so it never blocks the transaction. Never before SAR row exists. |
| **What if an artifact is missing?** | Record the field with `status: "missing"` or omit the path entry and add a `warnings[]` string. **Do not** fail the static run. Phase 1 is **documentation of reality**, not a completeness gate. |
| **What if hashing fails?** | Record `sha256: null` + `hash_error` message in manifest; **WARN** in logs. **Do not** fail the run. |
| **Does missing manifest fail normal runs?** | **No** in Phase 1. Absence of `evidence_manifest.json` is normal until the feature ships and backfills are optional. |
| **Does paper-grade mode eventually fail closed?** | **Out of scope for Phase 1.** A later phase may add `SCYTALEDROID_MANIFEST_REQUIRED=1` (or paper-grade hook) that **fails closed** only after the writer is stable and operators accept the UX. Document that transition explicitly before flipping. |
| **Where should the manifest live?** | Default: **session directory** next to `run_map.json` (same `session_stamp` tree) **or** `output/audit/evidence/<session_stamp>/manifest.json` — pick one product-wide; v1 should not mix both without `manifest_location` field. |
| **What fields are required in v1?** | Minimum: `manifest_schema_version`, `static_run_id`, `session_stamp`, `session_label`, `generated_at_utc`, `canonical_artifacts` (possibly empty with warnings), `git_commit` or `build_id`, `schema_version`, `environment_fingerprint` (no secrets). `handoff` / `detector_report` may be **partial** with `missing`/`hash_error` as above. |

**SKIP / ERROR semantics for the writer itself:** writer subprocess or helper should use **SKIP** when manifest path is not writable (log only); **ERROR** log lines are OK but must not change SAR `status` or exit code of the main CLI in Phase 1.

---

## 7. Related

- `docs/maintenance/session_identity_contract.md`
- `docs/design/v1_evidence_catalog_verification.md` (ACK-gated; do not conflate without review)
- `AGENTS.md` — evidence directories are not architecture truth; this manifest would **anchor** one run’s pointers.
