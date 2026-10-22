# ScytaleDroid session knowledge
- Repo: /home/systemadmin/GitHub/ScytaleDroid; read AGENTS.md first.
- Read docs/maintenance/{repo_ownership_map,workflow_entrypoint_map,documentation_authority_index}.md.
- Core results and shared Permission Intel use separate DSNs.
- For audits use claude_ro, verify CURRENT_USER and grants; never silently switch accounts.
- Missing privileges/data are UNAVAILABLE, not zero.
- Preserve dirty worktrees, retained packs and immutable checksum manifests.
- CLI entry: ./run.sh; do not launch an operator workflow just to inspect state.
- Canonical static truth: static_analysis_sessions and static_analysis_runs plus child tables.
- Runtime evidence packs are primary; MariaDB is a derived index.
- Bind package + version + base hash + split identity + static ID + runtime UUID.
- Do not collapse raw permission case variants into exact evidence.
- Current PI interpretation is not the historical paper's frozen authority snapshot.
- PI static intake writes require explicit mutation opt-in; maintenance tools can also write PI.
- Distinguish technical validity, QA, paper eligibility, quota completion and readiness.
- CARS 2026 frozen alignment: output/paper/android_empirical_alignment_final.
- Its cohort is 15 apps / 123 runs: 44 strict idle, 23 QFG, 56 interactive.
- QFG is not strict idle; static exposure and runtime metrics are not a composite score.
- ICECCO original 12-app study differs from the newer 15-app/114-run checkpoint.
- Never regenerate into a frozen directory; create a separately authorized candidate output.
- Fast lane: tests/api, tests/database/test_web_db_scripts.py, tests/dynamic/test_pcap_features_transport.py.
- Tests create disposable files/SQLite; isolate storage, disable dotenv and network for read-only audits.
- Integration tests require an explicit disposable/test MariaDB URL and truncate that schema.
- Physical device is required for capture/harvest; retained-evidence analysis can run offline.
- Consult Documents/ScytaleDroid_Audits current navigation for dated release/recovery gates.
- Passing a local test lane does not authorize release, production recovery or scanning.

## Phase-2 corrections (October 21–22, 2026 snapshot)

Sources: ~/Documents/SQL_Results/reports/scytaledroid_orientation_20261022.md and
scytaledroid_deep_audit_20261022.md in that directory; linked CSVs carry SQL/times.
Reverify these observations; they are not permanent facts.

- claude_ro SELECT/SHOW VIEW on core prod/dev was verified: phase 1's access gap is closed.
- Selected CARS identities, finding counts and PCAP hashes match the DB; literal paths
  differ by relocation. Full QA equality remains unproven: the cohort-QA index is empty.
- Direct run-to-set membership verifies split counts in the audit CSV; the frozen
  manifest's blank selected_split_count is not rewritten.
- Seven applied migration checksums disagree with source; dev trails prod.
- Run 8676 remains STARTED with empty checked children and a stale lock.
  Release, recovery, lock removal and resumption need separate authorization.
- PI queue labels identify 304 static-analysis rows, consistent with this producer.
  Unknown/OEM counters lack writer-event provenance; encounters are not unique samples.
- The 23 high-count unknown rows total 21,814 sightings without matching observations.
  Static evidence supports intake opportunity, not authorship of every increment.
- Live permission_signal_catalog lacks default_band/stage expected by current code.
- Phase-1 copy defaults to live PI and lacks a live-target guard. Never target live PI.
  Its last actual execution is UNAVAILABLE; source commit dates are not execution dates.
- Case collisions affect permission/risk rows, including Venmo. Changed finding IDs
  were not proven. Compatibility matches are not exact identity.
- Offline tests do not close schema, scientific-equivalence, persistent-memory,
  deployment or device gates.
- Recovered later ICECCO tables/model outputs do not match original paper values.
  Original ICECCO inputs and CARS 2025 six-app data remain unlocated.

## Claude settings

Start at the checkout root. Inspect /status and /permissions after workspace trust.
Shared Bash rules are prompt controls, not an OS security boundary. Alternate wrappers
and other settings need review. Deny precedes ask/allow. The SELECT allowlist uses
exact client commands, not arbitrary SQL. Verify CURRENT_USER() is claude_ro;
never connect as systemadmin. Redact authentication hashes/credentials from grants.

Settings checked against installed Claude Code 2.1.304 and its published JSON schema:
https://code.claude.com/docs/en/settings
https://code.claude.com/docs/en/permissions

The published schema rejects parentheses inside Bash rule specifiers. Exact COUNT
queries therefore use normal approval; identity, grants and bounded SELECT row reads
are preapproved without weakening the allowlist to arbitrary SQL.
