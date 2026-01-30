# scripts/ layout

This directory contains helper tools and utilities. The only supported entrypoints
for operators are:

- `./setup.sh`
- `./run.sh`
- `./run_mariadb.sh`

Everything under `scripts/` is categorized as:

- `scripts/lib/` — shell libraries sourced by `setup.sh` or other helpers.
- `scripts/operator/` — operator diagnostics and maintenance helpers.
- `scripts/dev/` — developer-only utilities.
- `scripts/archive/` — deprecated or pending deletion.

Nothing in `scripts/` is executed by the main CLI automatically.
