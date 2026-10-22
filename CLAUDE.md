# Claude Code sessions

@AGENTS.md
@docs/maintenance/agent_session_knowledge.md
@CLAUDE.local.md

## Defaults and evidence

- Read-only unless the user asks for changes. Missing access/data is UNAVAILABLE, not zero.
- Core results and shared permission intelligence use separate DSNs. Resolve the
  approved read-only account from local configuration and verify CURRENT_USER().
  Never use an administrative account or silently switch users.
- Integration tests truncate tables: use only explicitly disposable databases,
  never operational, development or shared intelligence catalogs.
- Runtime evidence packs and PCAPs are primary; the database is their derived index.
  Frozen bundles are immutable. Write new outputs into separately named folders.
- Bind package + version + base hash + split set + static run ID + runtime UUID.
  Never join on display names. Permission names are case-sensitive; casefold and
  lowercase paths are compatibility projections, not evidence identity.
- Shared intelligence writes require explicit approval. Do not target a live shared
  catalog with copy tools as part of ordinary analysis or diagnostics.
- Capture and harvest need the phone; retained-evidence analysis does not.
- Use tmux remotely. Long jobs record command, exit status and input hashes in
  named output folders outside frozen evidence.

## Commands and local configuration

- Start Claude at the checkout root: claude.
- Operator CLI: ./run.sh, only for an explicitly requested workflow.
- Fast lane: scripts/dev/test_fast_isolated.sh
- Targeted offline lanes (also run the default fast lane):
  scripts/dev/test_fast_isolated.sh tests/unit tests/static_analysis tests/persistence
  scripts/dev/test_fast_isolated.sh tests/gates tests/dynamic
- The wrapper needs bwrap and an installed venv; see its prerequisite errors.
  Extra pytest args pass through; do not override the offline marker selection.
- Resolve report destinations, audit accounts, schemas and retained-bundle locations
  from environment variables or the ignored local guidance. Stop if unavailable.
- Slash commands: /fast-tests, /git-state, /db-check, /cars2026-verify, /pi-writes.
- Keep study identities, cohort counts, access observations and recovery status in
  local notes. Verify dated facts before using them; do not publish them by default.
