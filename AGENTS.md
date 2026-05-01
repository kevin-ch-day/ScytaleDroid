# AGENTS.md

## Project summary
ScytaleDroid is an Android security research framework (not a single-purpose scanner) spanning device/APK collection, static analysis, dynamic/runtime measurement, database-backed evidence, and reporting/publication workflows.

## Core rule
Make small, bounded, behavior-preserving changes. Do not refactor unrelated areas.

## Domain routing (start here)
- Device/APK work: `scytaledroid/DeviceAnalysis/`
- Static analysis work: `scytaledroid/StaticAnalysis/`
- Dynamic analysis work: `scytaledroid/DynamicAnalysis/`
- DB/schema/read-model work: `scytaledroid/Database/`
- Reporting/export work: `scytaledroid/Reporting/`, `scytaledroid/Publication/`
- Web analyst surface issues: start in the separate Web repo, not Python analysis modules.
- Scripts are wrappers; business logic belongs in `scytaledroid/` modules.

## High-risk seams (extra caution)
- Static CLI dispatch/persistence/results paths (`StaticAnalysis/cli/flows|persistence|execution`).
- DB read-model/view facade surfaces (`Database/db_queries/views*.py`, `schema_manifest.py`).
- DB utility menu/controller paths (`Database/db_utils/menu_actions.py`, `db_utils/menus/`).

## Source-of-truth and compatibility rules
- Runtime code is authoritative when docs and code differ.
- Use maintenance maps for routing:
  - `docs/maintenance/repo_ownership_map.md`
  - `docs/maintenance/workflow_entrypoint_map.md`
  - `docs/maintenance/documentation_authority_index.md`
- Do not treat generated/local state (`output/`, `evidence/`, `logs/`, `data/`, local DB snapshots) as architecture truth.
- Do not expand legacy/bridge paths; keep thin compatibility wrappers when tests/callers still patch/import them.

## Refactor guardrails
- Preserve public imports/facades unless explicitly asked.
- Prefer extraction over rewrite.
- Keep wrappers thin (forwarding only); move real logic to nearby helpers.
- Do not change schema, SQL/view semantics, generated artifact layout, or unrelated domains unless explicitly requested.
- Do not change CLI output wording/section ordering in cleanup tasks unless explicitly requested.
- If scope expands across domains, stop and state why before proceeding.

## Validation (targeted first)
- Static: `pytest tests/static_analysis -q` and `pytest tests/persistence -q`
- Database: `pytest tests/database tests/db tests/db_utils -q`
- Dynamic: `pytest tests/dynamic -q`
- Gates/scripts/docs: `pytest tests/gates -q`
- Compile changed Python files: `python -m py_compile <changed_python_files>`

Run full-suite checks only after targeted tests pass (or when shared contracts change).

## Final response checklist
- Report: files changed, behavior preserved/changed, tests run, known risks/follow-ups.
- Flag pre-existing failures clearly and avoid mixing unrelated fixes into one commit.
