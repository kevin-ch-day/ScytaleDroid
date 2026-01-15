# Audit Event Log (design)

Purpose: append-only provenance for operator-initiated writes (triage, notes, queues, dictionary changes). Supports PhD/research integrity.

## Table sketch (design only)
- `event_id` BIGINT AUTO_INCREMENT PRIMARY KEY
- `event_at_utc` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
- `actor` VARCHAR(128) NOT NULL (user/uid)
- `source_app` VARCHAR(32) NOT NULL (e.g., web, cli)
- `entity_type` VARCHAR(64) NOT NULL (e.g., apk, permission, device, queue_item, dict_entry)
- `entity_id` VARCHAR(191) NOT NULL (FK/ID/hash)
- `action` VARCHAR(64) NOT NULL (triage_update, note_add, queue_create, dict_change, pref_update)
- `reason_code` VARCHAR(64) NULL
- `notes` TEXT NULL
- `before_json` JSON NULL
- `after_json` JSON NULL
- Indexes: `(entity_type, entity_id, event_at_utc)`, `(actor, event_at_utc)`, `(source_app, event_at_utc)`

Guidance:
- Keep before/after concise: only the fields touched by the action; no binary blobs.
- Emit on operator actions: triage status change, note add/edit, queue create/update, dictionary curation, user preference change (if relevant).
- Retention: keep all in DEV; prune/archival can be revisited later.

Status: design only. No schema changes until PM green-lights.
