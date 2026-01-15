# Web Write Contract (design)

Scope: operator-facing web writes. Ground-truth tables remain immutable (raw observations, static findings, permission snapshots).

## Matrix (design only)

| Area/Table        | Web Write? | Mode           | Required audit fields                             | Notes                                    |
|-------------------|------------|----------------|---------------------------------------------------|------------------------------------------|
| web_annotations   | Yes        | Insert/Update  | created_at/by, updated_at/by, op_source, reason/notes | Attach notes to entity_type+entity_id    |
| web_user_prefs    | Yes        | Upsert         | created_at/by, updated_at/by, op_source           | Per-user prefs (filters, columns)        |
| audit_event_log   | Append-only| Insert only    | event_at, actor, source_app, entity_type/id, action, reason, before/after | Provenance for operator edits            |
| Triage queue (future) | Yes    | Insert/Update  | created/updated, op_source, reason/notes          | For “apply later” workflows              |
| Dictionary curation (future, optional) | Maybe | Insert/Update | created/updated, op_source, reason/notes, before/after | Only if approved; otherwise RO           |

Immutable / RO from web (must not mutate):
- Raw observations: inventories, static findings, permission snapshots, string findings, runs metadata.
- Any “ground truth” tables populated by CLI scanners.

Status: design only. No schema changes shipped until PM green-light after Fedora validation.
