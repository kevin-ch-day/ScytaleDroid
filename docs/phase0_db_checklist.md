# Database Unification (MariaDB) Checklist

Goal: single canonical MariaDB backend for CLI workflows, no silent SQLite fallback.

## Prereqs
- MariaDB running on Fedora and reachable.
- `.env` (gitignored) with `SCYTALEDROID_DB_URL=mysql://user:pass@host:3306/dbname`
  - Optional: set `SCYTALEDROID_ENV_FILE` to point to another env file.

## Commands
1) Bootstrap schema (MariaDB)
   ```bash
   python -m scytaledroid.Database.tools.db_init
   ```
2) Status check
   ```bash
   python -m scytaledroid.Database.tools.db_status
   ```
3) Run CLI against MariaDB
   ```bash
   ./run_mariadb.sh    # loads .env and enforces MariaDB
   ```
4) Database Utilities → “Check connection & show config”
   - Backend shows `mysql`
   - Host/Port/DB/User match MariaDB
   - Schema ver populated

## Acceptance
- If `SCYTALEDROID_DB_URL` is set and connection/schema fails, CLI exits non-zero (no fallback).
- Fresh MariaDB can be bootstrapped deterministically via `db_init`.
- Schema version is stored and reported in db_status and the CLI menu.

## Troubleshooting
- Connection fails: verify credentials/host in `SCYTALEDROID_DB_URL`.
- Schema missing: rerun `python -m scytaledroid.Database.tools.db_init`.
- Want SQLite dev mode: unset `SCYTALEDROID_DB_URL` (explicit choice).

## URL schemes and examples
- Supported: `mysql://` or `mariadb://` (PyMySQL driver), `mysql+pymysql://` also works.
- TCP example (`.env`):
  ```
  SCYTALEDROID_DB_URL=mysql://user:pass@localhost:3306/scytaledroid
  ```
- Socket auth: not covered in this checklist; if needed, add `?unix_socket=/path/to/socket` to the URL and ensure the MariaDB user permits socket auth on that host.
