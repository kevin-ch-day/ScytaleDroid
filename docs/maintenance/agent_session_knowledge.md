# Shared session practices

Read AGENTS.md and the maintenance ownership, workflow-entrypoint and documentation
maps before cross-cutting work. Keep environment-specific context in ignored local
guidance; this file contains portable practices only.

## Evidence and operations

- Preserve dirty worktrees, retained packs and immutable checksum manifests.
- Treat the database as a derived runtime index; validate primary evidence independently.
- Bind exact build and run identities. Display names and compatibility projections
  are not evidence keys. Keep original permission spelling.
- Distinguish technical validity, QA, paper eligibility, quota completion and readiness.
- Keep experiments and frozen cohorts separate; later checkpoints do not replace
  original inputs or outputs. Current intelligence is not historical frozen authority.
- Producer/source labels need code and provenance checks. Encounter counters are not
  unique samples or observations, and authority provenance does not identify a writer.
- Missing privileges, artifacts or attribution are UNAVAILABLE, not zero.
- Isolate tests with disposable storage, dotenv disabled, network off and no live
  database socket. Integration tests need explicit disposable database authorization.
- Passing tests does not authorize release, production recovery, migrations or scans.
- Report exact SQL and query time for counts; never substitute metadata estimates.

## Local values and permissions

Resolve these variables from the environment or the ignored local guidance:
SCYTALEDROID_AUDIT_DB_USER, SCYTALEDROID_AUDIT_CORE_SCHEMA,
SCYTALEDROID_AUDIT_PI_SCHEMA, SCYTALEDROID_REPORT_DIR and SCYTALEDROID_PAPER_BUNDLE.
If a required value is absent or contradictory, stop that operation and ask.
Validate schema identifiers before SQL interpolation; never interpolate arbitrary text.
Use the configured audit account explicitly, verify CURRENT_USER() and grants,
and reject administrative accounts. Do not print credentials or authentication hashes.

Shared settings prompt for database-client commands rather than embedding local
accounts or broad SQL allow rules. Permission strings do not expand environment
variables; resolve values in the command, then review the requested operation.
Bash rules are prompt controls, not an OS security boundary. Check effective settings
with /status and /permissions. Use /memory and /context to inspect local imports.
