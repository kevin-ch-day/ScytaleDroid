# Fast implementation backlog — three lanes

**Purpose:** ship small batches quickly without Lane‑3 risk. Each task row is a PR-sized unit.

## Lanes

| Lane | Scope | Gate |
| --- | --- | --- |
| **1 — Fast safe fixes** | Docs, labels, operator wording, SKIP/INFO/WARN/ERROR cleanup, metadata, narrow tests | None beyond normal review |
| **2 — Bounded code cleanup** | Helper extraction, duplicated diagnostic SQL, script hygiene, obvious read-path consolidation; **preserve behavior** | No schema; grep proof for legacy INSERTs unchanged |
| **3 — Design-gated** | `metrics` migration, `risk_actions` behavior, `views_bridge` / `v_run_overview`, MASVS fallback removal, reset paths, PI `obs_sample` writes, schema/DDL, evidence manifest when it can affect run success | Written design + tests + explicit approval |

## Task row template

| ID | Lane | Task | Files (expected) | Behavior change | Risk | Tests | Rollback | Now vs gated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

## Completed / in-flight (this repo batch)

| ID | Lane | Task | Files | Behavior change | Risk | Tests | Rollback | Now vs gated |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B‑script‑1 | 1+2 | Session static health canonical/legacy policy | `scripts/db/session_static_health.py`, tests | Stricter exit 1 on canonical errors; legacy SKIP/INFO | Low | `tests/scripts/test_cli_script_smoke.py` (legacy display section) | Revert script | **Done** |
| A‑risk‑1 | 1 | Risk scoring operator wording | `health_checks_permission.py`, `query_runner.py`, docs already aligned | Labels/hints only | Very low | Manual / existing suites | Revert strings | **This batch** |
| C‑audit‑1 | 1 | Audit script section vocabulary | `audit_static_session.py` | stdout titles only | Very low | `py_compile`, smoke | Revert strings | **This batch** |
| B‑helper‑1 | 2 | Legacy mirror diagnostic helpers | `legacy_static_mirror_diagnostics.py`, `audit_static_session.py`, `session_static_health.py` | Same SQL, centralized | Low | New unit tests | Revert import + inline | **Done** |
| A‑script‑vocab‑1 | 1 | Operator stdout vocabulary | `static_schema_audit.py`, `check_permission_intel.py` | stdout labels only | Very low | importlib tests + existing | Revert prints | **This batch** |
| B‑helper‑runs‑1 | 2 | `legacy_runs_count_by_session_stamp` + wiring notes | `legacy_static_mirror_diagnostics.py`, `audit_static_session.py`, `legacy_static_reader_dependency_map.md` §2.1.1 | `runs` count SQL deduped | Low | DB unit tests | Revert helper call | **This batch** |
| Doc‑manifest‑fm‑1 | 1 | Evidence manifest Phase 1 failure modes | `evidence_run_manifest_spec.md` | Policy prose only | None | n/a | Revert section | **This batch** |
| Ev‑manifest‑p1 | 2 | Session `evidence_manifest.json` writer + verify CLI | `evidence_manifest_writer.py`, `evidence_manifest_verify.py`, `scripts/db/verify_evidence_manifest.py`, `postprocessing.py`, tests, spec, `.env.example` | Best-effort manifest; `canonical_artifacts` includes `detector_report` / `handoff_json`; optional `build_id`; verify exit 1 on drift | Low | persistence + scripts smoke tests | Revert hook + modules + script | **Done** |

## Lane 3 backlog (do not start here without design doc)

- `metrics.run_id` semantic migration
- `risk_actions` join behavior changes
- `views_bridge` / `CREATE_V_RUN_OVERVIEW` rewrite
- `reset_static` / `reset_full` table lists
- MASVS legacy fallback removal
- PI `android_permission_obs_sample` writers
- Evidence manifest **required** on run success (Phase 2+)

## Standard verification (after each batch)

```bash
python -m py_compile <changed python files>
pytest tests/persistence -q
pytest tests/db_utils -q
pytest tests/scripts -q
pytest tests/static_analysis/test_diagnostic_output_helpers.py -q
pytest tests/database/test_legacy_static_mirror_diagnostics.py -q
rg 'INSERT INTO (runs|findings|metrics|buckets|contributors)\b' scytaledroid --glob '*.py'
```

## Related policy docs

- `docs/maintenance/session_identity_contract.md`
- `docs/maintenance/session_static_health_hygiene_plan.md`
- `docs/maintenance/evidence_run_manifest_spec.md`
- `docs/maintenance/pi_erebus_operational_boundary.md`
