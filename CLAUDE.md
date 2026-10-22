# Claude Code sessions

@AGENTS.md
@docs/maintenance/agent_session_knowledge.md

## Defaults and evidence

- Read-only unless the user asks for changes. Missing access/data is UNAVAILABLE, not zero.
- Core and Permission Intel use separate DSNs. Audit as claude_ro; verify CURRENT_USER().
  Never connect as systemadmin. Integration tests truncate tables: never target prod,
  dev or PI; only an explicitly disposable test database is permitted.
- Runtime evidence packs and PCAPs are primary; MariaDB is their derived index.
  Frozen output/paper/android_empirical_alignment_final/ and other freezes are immutable.
  Write new outputs in separately named folders.
- Bind package + version + base hash + split set + static run ID + runtime UUID.
  Never join on display names.
- Android permission strings are case-sensitive. Casefold/lowercase paths are
  compatibility projections, not evidence identity. Preserve exact strings.
- Shared PI writes require explicit approval: unknown dictionary/queue, OEM seen
  metadata, signal catalog, governance import and phase-1 copy.
  The phase-1 copy utility must never target live android_permission_intel.
- Capture and harvest need the phone; offline retained-evidence analysis does not.
- Use tmux remotely. Long jobs need named output folders with the command,
  exit status and input hashes; never write into frozen directories.

## Commands

- Start Claude at the checkout root: claude; remote shell: tmux new -s scytale.
- Operator CLI: ./run.sh (only for an explicitly requested workflow).
- Fast lane: scripts/dev/test_fast_isolated.sh
- Targeted offline lanes (also run the default fast lane):
  scripts/dev/test_fast_isolated.sh tests/unit tests/static_analysis tests/persistence
  scripts/dev/test_fast_isolated.sh tests/gates tests/dynamic
- Wrapper prerequisites: bwrap and .venv. Linked worktrees reuse the main checkout's
  installed .venv read-only; SCYTALEDROID_TEST_VENV can select another installed venv.
  Extra pytest args pass through; do not override the offline marker selection.
- Reports: ~/Documents/SQL_Results/reports/ with dated names, SQL, query time,
  source identities and explicit unavailable fields.
- Slash commands: /fast-tests, /git-state, /db-check, /cars2026-verify, /pi-writes.

## Study boundaries

- CARS 2026: 15 apps / 123 runs = 44 strict idle, 23 QFG, 56 interactive.
  QFG is not strict idle; static exposure and runtime metrics are separate measures.
- ICECCO's original 12-app study differs from the newer 15-app/114-run checkpoint.
- Consult dated knowledge and current audit navigation before trusting old counts,
  grants, release readiness or run-recovery status.
