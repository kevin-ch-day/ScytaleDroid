# LAMP Integration Notes (Draft)

This folder captures early guidance for wiring ScytaleDroid’s database into a Linux/Apache/MySQL/PHP stack.

## Overview

ScytaleDroid’s CLI populates MySQL tables (see `docs/database/queries/`) that a PHP front‑end can consume. No schema migrations are required yet—focus on read-only dashboards over the existing tables.

## Suggested workflow

1. **Provision MySQL credentials** for the PHP app with read-only access to the ScytaleDroid schema.
2. **Reuse the query specs** in `../database/queries/` to build DAO classes or prepared statements inside the PHP layer.
3. **Expose artifacts via HTTP downloads** from `data/apks/device_apks/` (ensure Apache has read permission or proxy through PHP with access controls).
4. **Cache inventory snapshots** in MySQL (import `data/state/<serial>/inventory/latest.json`) before driving device dashboards.
5. **Add environment toggles** so LAMP can detect whether quick harvests skipped DB writes (inspect `HARVEST_WRITE_DB` flag if you expose it via config).

## TODO

- Document Apache virtual host permissions for the artifact repository.
- Provide PHP examples (PDO prepared statements) mirroring the pseudo-SQL in the query docs.
- Add authentication/authorization strategy (JWT, Basic Auth, etc.) for analysts accessing the dashboards.
- Evaluate whether to mirror run manifests into SQL for easier consumption.

Keep this doc updated as the LAMP integration progresses.
