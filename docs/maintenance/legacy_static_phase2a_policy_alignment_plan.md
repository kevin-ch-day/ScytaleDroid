# Phase 2A — Legacy static policy alignment (completed)

**Status:** **Implemented.** This file is a **short completion record** only. Detailed call sites, edge cases, and retirement ordering live in **`legacy_static_reader_dependency_map.md`**; phased strategy in **`legacy_static_deprecation_playbook.md`**.

**What shipped**

- **`status_actions`:** legacy `findings` removed from **`required_tables["static"]`**; separate **`legacy_mirror_table_presence`** / meta for the legacy five (missing tables are normal when only canonical writers run). See dependency map **§8.5**.
- **`ownership_matrix_v1_3.csv`:** legacy-five (and related) **write_owner** / **notes** aligned with “no `INSERT INTO` legacy five in current Python” (grep baseline below).
- **`bridge_posture.py`:** bounded **`current_readers`** refresh + docstring disclaimer (not exhaustive vs dependency map).
- **Reconcile audit JSON:** per-table **`legacy_*_mirror_packages`** in bridge summary (post–Phase 2A code path). See dependency map **§8.6** and **`tests/persistence/test_run_persistence_reconcile_bridge_json.py`**.

**Still intentionally out of scope** (defer to playbook Phase 2–3 / other tracks): `risk_actions`, metrics-query migration, `views_bridge`, `reset_static` / `reset_full`, MASVS env-gated fallback, schema/DDL, Web repo code changes.

---

## Verification commands (keep green on legacy-touching PRs)

```bash
# Legacy-five INSERT baseline — must stay zero hits in scytaledroid/
rg 'INSERT INTO (runs|findings|metrics|buckets|contributors)\b' scytaledroid --glob '*.py'

pytest tests/database/test_db_utils_status_actions_snapshot_and_digest_contracts.py tests/database/test_schema_gate_static.py tests/database/test_bridge_posture.py -q

python -m py_compile scytaledroid/Database/db_utils/action_groups/status_actions.py scytaledroid/Database/db_utils/bridge_posture.py
```

**Full design narrative** (JSON shape sketches, CSV column intent, rollback notes) lived in git history of this file before consolidation; do not revive long prose here without a new RFC.

---

## Related

- [legacy_static_reader_dependency_map.md](legacy_static_reader_dependency_map.md) — authoritative reader map and **§8** follow-ups.
- [legacy_static_deprecation_playbook.md](legacy_static_deprecation_playbook.md) — phased exit; **DDL last**.
- [legacy_static_tables_consumer_audit.md](legacy_static_tables_consumer_audit.md) — one-page index (tables in scope + pointers).
