# Legacy static tables — consumer index (read-only)

**Purpose:** single entry page for the **legacy five** (`runs`, legacy base **`findings`**, `metrics`, `buckets`, `contributors`). Per-file reader matrices and §8 edge cases were consolidated into **`legacy_static_reader_dependency_map.md`** to avoid maintaining two inventories.

**Constraints:** no DDL, migrations, or drops implied here. Pair with **`scripts/db/static_schema_audit.py`** and **`static_database_schema_audit_plan.md`**.

---

## Baseline facts (unchanged)

**Tables in scope:** `runs`, `findings` (legacy mirror — not `static_analysis_findings`), `metrics`, `buckets`, `contributors`.

**Python writer scan:** no `INSERT INTO` the legacy five in `scytaledroid/**/*.py`:

```bash
rg 'INSERT INTO (runs|findings|metrics|buckets|contributors)\b' scytaledroid --glob '*.py'
```

**Registry:** `scytaledroid/Database/db_utils/bridge_posture.py` — `current_writers=()` for each legacy-five row; **`current_readers`** is illustrative (see map + docstring there).

**Classification legend** (for interpreting older PRs and `static_schema_audit.py` output): `1` active reader · `2` writer · `3` tests · `4` docs · `5` reset/cleanup · `6` compatibility/registry · `7` unknown.

---

## Where to read next

| Need | Document |
| --- | --- |
| **File/function call sites**, false positives, `metrics.run_id` split, §8 gaps | [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) |
| **Phased retirement**, gates, what not to do | [legacy_static_deprecation_playbook.md](legacy_static_deprecation_playbook.md) |
| **Web repo** SQL, `diag.php`, alias `findings`, single legacy `runs` diagnostic | [legacy_static_tables_web_deep_dive.md](legacy_static_tables_web_deep_dive.md) |
| **Relabel / UX sequencing** (no schema) | [legacy_static_deprecation_playbook.md — Appendix A](legacy_static_deprecation_playbook.md#legacy-static-table-compatibility-appendix) |
| **Phase 2A completion** (snapshot, CSV, bridge metadata) | [legacy_static_phase2a_policy_alignment_plan.md](legacy_static_phase2a_policy_alignment_plan.md) |

---

## Related single sources of truth

- `AGENTS.md` — canonical static persistence; legacy mirror not written by new static pipelines.
- `docs/maintenance/static_database_schema_audit_plan.md` — read-only inventory semantics.
